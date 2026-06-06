use crate::nar::NarGitStream;
use crate::nar::decode::NarGitDecoder;
use anyhow::{Context, Result, anyhow, bail};
use git2::Cred;
use git2::Direction;
use git2::FetchOptions;
use git2::RemoteCallbacks;
use git2::Signature;
use git2::Time;
use git2::{ErrorCode, FileMode, Oid, Repository};
use std::env;
use std::fs;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use tracing::{Level, info, instrument, span, trace};

/// A handle to the on-disk Git store.
///
/// Holds only the repository path; every operation opens its OWN single-owner
/// `git2::Repository`. A libgit2 `Repository` is not safe to share across threads
/// (its ODB has internal mutable caches), so the previous `Arc<RwLock<Repository>>`
/// + `unsafe impl Sync` was unsound under concurrent serving. `PathBuf` is `Send + Sync`,
/// so `GitRepo` is auto `Send + Sync` with no unsafe — which the NAR-decode closure in
/// `daemon::fetch` (bounded `Send + Sync + 'static`) requires.
#[derive(Clone)]
pub struct GitRepo {
    path: PathBuf,
}

impl GitRepo {
    pub fn new(path_to_repo: &Path) -> Result<Self, git2::Error> {
        let repo = if path_to_repo.exists() {
            info!(
                "Using an existing Git repository at {}",
                path_to_repo.display()
            );
            Repository::open(path_to_repo)?
        } else {
            info!(
                "Initializing a new Git repository at {}",
                path_to_repo.display()
            );
            Repository::init(path_to_repo)?
        };
        let mut config = repo.config()?;
        config.set_str("protocol.version", "2")?;
        // Store the canonical gitdir so future opens are stable (bare: the repo dir).
        Ok(Self {
            path: repo.path().to_path_buf(),
        })
    }

    /// Open a fresh, single-owner libgit2 handle against the on-disk repo.
    /// Cheap for local repositories; gives each caller/stream an isolated handle.
    fn open(&self) -> Result<Repository> {
        Ok(Repository::open(&self.path)?)
    }

    pub fn add_single_entry_tree(&self, entry_oid: Oid, name: &str, filemode: i32) -> Result<Oid> {
        let repo = self.open()?;
        let mut builder = repo.treebuilder(None)?;
        builder.insert(&name, entry_oid, filemode)?;
        Ok(builder.write()?)
    }

    #[allow(dead_code)]
    pub fn add_dir<T: AsRef<Path>>(&self, path: &T) -> Result<Oid> {
        let path = path.as_ref();
        if !path.is_dir() {
            return Err(anyhow!("No such directory: {}", path.to_str().unwrap()));
        }
        let tree_oid = self.create_tree_from_dir(&path)?;
        Ok(tree_oid)
    }

    pub fn add_nar(&self, content: impl Read) -> Result<(Oid, i32)> {
        let repo = self.open()?;
        let decoder = NarGitDecoder::new(&repo);
        let (oid, filemode) = decoder
            .parse(content)
            .with_context(|| "Error decoding NAR file")?;
        Ok((oid, filemode))
    }

    /// Raw commit message bytes — the stored narinfo, byte-for-byte.
    /// MUST use `message_raw_bytes()`; `message()`/`message_bytes()` trim leading
    /// whitespace/newlines and would corrupt the narinfo round-trip.
    pub fn get_commit_message_raw(&self, oid: Oid) -> Result<Vec<u8>> {
        let repo = self.open()?;
        Ok(repo.find_commit(oid)?.message_raw_bytes().to_vec())
    }

    /// All commit OIDs reachable from `tip` — the whole package closure, since a
    /// package commit's parents are its dependency commits.
    pub fn walk_commits(&self, tip: Oid) -> Result<Vec<Oid>> {
        let repo = self.open()?;
        let mut walk = repo.revwalk()?;
        walk.push(tip)?;
        let mut out = Vec::new();
        for oid in walk {
            out.push(oid?);
        }
        Ok(out)
    }

    /// Create/update a reference to `oid`. Force-updates: package commit OIDs are
    /// deterministic (fixed signature/time), so a re-publish writes the identical OID
    /// (no-op clobber); closure materialization and CI re-push need idempotency.
    pub fn add_ref(&self, ref_name: &str, oid: Oid) -> Result<()> {
        let repo = self.open()?;
        repo.reference(ref_name, oid, /* force = */ true, "")?;
        Ok(())
    }

    pub fn get_entry_as_nar(&self, oid: Oid) -> Result<Option<NarGitStream>> {
        let repo = self.open()?;
        let filemode = {
            let object = repo.find_object(oid, None)?;
            let kind = object
                .kind()
                .ok_or_else(|| anyhow!("Object with oid {} does not have a type", oid))?;
            match kind {
                git2::ObjectType::Blob => FileMode::Blob.into(),
                git2::ObjectType::Tree => FileMode::Tree.into(),
                _ => bail!("Object must either be a tree or a blob"),
            }
        }; // `object` borrow of `repo` ends here, before `repo` is moved into the stream

        let stream = NarGitStream::new(repo, oid, filemode);
        Ok(Some(stream))
    }

    pub fn get_oid_from_reference(&self, reference: &str) -> Option<Oid> {
        let repo = self.open().ok()?;
        repo.find_reference(reference).ok().and_then(|r| r.target())
    }

    fn create_tree_from_dir(&self, path: &Path) -> Result<Oid> {
        let repo = self.open()?;
        let mut builder = repo.treebuilder(None)?;
        for entry in path.read_dir()? {
            let entry_path = entry?.path();
            let entry_file_name = entry_path
                .file_name()
                .expect("Failed to get filename")
                .to_str()
                .unwrap();

            if entry_path.is_symlink() {
                let target = fs::read_link(&entry_path)?;
                let blob_oid = repo.blob(target.as_os_str().as_bytes())?;
                builder.insert(entry_file_name, blob_oid, FileMode::Link.into())?;
            } else if entry_path.is_file() {
                let permissions = entry_path.metadata()?.permissions();
                let is_executable = permissions.mode() & 0o111 != 0;
                let filemode = if is_executable {
                    FileMode::BlobExecutable
                } else {
                    FileMode::Blob
                };
                let blob_oid = repo.blob_path(&entry_path)?;
                builder.insert(entry_file_name, blob_oid, filemode.into())?;
            } else if entry_path.is_dir() {
                let subtree_oid = self.create_tree_from_dir(&entry_path)?;
                builder.insert(entry_file_name, subtree_oid, FileMode::Tree.into())?;
            }
        }
        Ok(builder.write()?)
    }

    pub fn commit(&self, tree_oid: Oid, parent_oids: &[Oid], comment: Option<&str>) -> Result<Oid> {
        let span = span!(Level::TRACE, "Commiting", comment);
        let _guard = span.enter();

        let repo = self.open()?;
        let sig = Signature::new("gachix", "gachix@gachix.com", &Time::new(0, 0))?;

        trace!("Retrieving main tree object {}", tree_oid);
        let commit_tree = repo.find_tree(tree_oid)?;

        trace!("Collecting commit oids for {} parents", parent_oids.len());
        let mut parents: Vec<git2::Commit<'_>> = Vec::new();
        for oid in parent_oids.iter() {
            trace!("Retrieving parent commit {}", oid);
            let commit = repo.find_commit(*oid)?;
            parents.push(commit);
        }
        let parents: Vec<&git2::Commit<'_>> = parents.iter().collect();

        let commit_oid = repo.commit(
            None,
            &sig,
            &sig,
            comment.unwrap_or(""),
            &commit_tree,
            parents.as_slice(),
        )?;
        trace!("Commit successful");
        Ok(commit_oid)
    }

    pub fn reference_exists(&self, name: &str) -> Result<bool> {
        let repo = self.open()?;
        match repo.find_reference(name) {
            Ok(_) => Ok(true),
            Err(e) => {
                if e.code() == ErrorCode::NotFound {
                    Ok(false)
                } else {
                    bail!(e)
                }
            }
        }
    }

    pub fn list_references(&self, ref_name: &str) -> Result<Vec<String>> {
        let repo = self.open()?;
        let refs = repo.references_glob(ref_name)?;
        let mut refs_names = Vec::new();
        for reference in refs {
            let reference = reference?;
            refs_names.push(
                reference
                    .name()
                    .ok_or_else(|| anyhow!("Could not get name from reference"))?
                    .to_string(),
            );
        }
        Ok(refs_names)
    }

    pub fn match_sole_entry_id(&self, tree_oid: Oid, name: &str) -> Result<Option<Oid>> {
        let repo = self.open()?;
        let tree = repo.find_tree(tree_oid)?;
        if tree.len() != 1 {
            return Ok(None);
        }
        let entry = tree
            .iter()
            .next()
            .ok_or_else(|| anyhow!("Expected at least one entry in tree"))?;
        let entry_oid = entry.name().and_then(|n| {
            if n == name {
                return Some(entry.id());
            }
            None
        });
        Ok(entry_oid)
    }

    pub fn check_remote_health(&self, url: &str) -> Result<()> {
        let repo = self.open()?;
        let mut remote = repo.remote_anonymous(url)?;
        let mut callbacks = RemoteCallbacks::new();
        callbacks.credentials(|_url, _user_from_url, _allowed_types| {
            let user = env::var("USER").unwrap();
            if _allowed_types.contains(git2::CredentialType::USERNAME) {
                return git2::Cred::username(&user);
            }
            Cred::ssh_key(
                &env::var("USER").unwrap(),
                None,
                std::path::Path::new(&format!("{}/.ssh/id_ed25519", env::var("HOME").unwrap())),
                None,
            )
        });
        match remote.connect_auth(Direction::Fetch, Some(callbacks), None) {
            Ok(connection) => {
                connection.list()?;
                Ok(())
            }
            Err(e) => {
                bail!("Connection failed: {}", e);
            }
        }
    }

    /// Fetch `remote_ref` from `url` into a scratch ref and return its resolved commit OID,
    /// or `Ok(None)` if the remote does not advertise the ref.
    ///
    /// Fetches into a scratch namespace (NOT the canonical package ref) so the caller can
    /// create canonical refs only after the whole closure is validated — replication stays
    /// transactional even if the closure is corrupt or the process dies mid-way.
    #[instrument(skip(self))]
    pub fn fetch_ref(&self, url: &str, remote_ref: &str) -> Result<Option<Oid>> {
        let repo = self.open()?;
        // Anonymous remote: a per-open handle must not reuse a stale persisted remote.
        let mut remote = repo.remote_anonymous(url)?;
        let scratch = "refs/gachix-fetch/scratch";
        let refspec = format!("+{}:{}", remote_ref, scratch);

        trace!("Fetching {} from remote into scratch", remote_ref);
        let mut fetch_options = FetchOptions::new();
        let mut callbacks = RemoteCallbacks::new();
        callbacks.credentials(|_url, _user_from_url, _allowed_types| {
            let user = env::var("USER").unwrap();
            if _allowed_types.contains(git2::CredentialType::USERNAME) {
                return git2::Cred::username(&user);
            }
            Cred::ssh_key(
                &env::var("USER").unwrap(),
                None,
                std::path::Path::new(&format!("{}/.ssh/id_ed25519", env::var("HOME").unwrap())),
                None,
            )
        });
        fetch_options.remote_callbacks(callbacks);
        fetch_options.download_tags(git2::AutotagOption::None);
        fetch_options.update_fetchhead(false);

        // Fetching a specific ref the remote does not advertise makes libgit2 fail with
        // "couldn't find remote ref ...". libgit2 exposes no typed error for this, so we
        // match narrowly (NotFound code, or the specific phrase) and treat it as "remote
        // does not have the package" (Ok(None)); any other error is propagated (fail-fast).
        if let Err(e) = remote.fetch(&[refspec], Some(&mut fetch_options), None) {
            let msg = e.message().to_lowercase();
            if e.code() == ErrorCode::NotFound || msg.contains("couldn't find remote ref") {
                trace!("Remote does not have {} ({})", remote_ref, e.message());
                return Ok(None);
            }
            return Err(e.into());
        }

        // Success is decided by whether the scratch ref now resolves — NOT by
        // received_objects(), which is 0 when the closure's objects are already present
        // locally (e.g. shared with a previously-fetched sibling closure).
        let oid = repo.find_reference(scratch).ok().and_then(|r| r.target());
        // Drop the scratch ref; the fetched objects stay in the ODB and are made reachable
        // by the canonical refs the caller creates immediately after (no GC runs between).
        if let Ok(mut r) = repo.find_reference(scratch) {
            let _ = r.delete();
        }
        Ok(oid)
    }
}

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use anyhow::Result;
//     use rand::distributions::{Alphanumeric, DistString};
//     use rand::{self};
//     use std::fs;
//     use std::path::PathBuf;
//     use tempfile::TempDir;
//
//     fn create_random_package(dir: &PathBuf) -> Result<PathBuf> {
//         let mut rng = rand::thread_rng();
//         let random_string = Alphanumeric.sample_string(&mut rng, 5);
//         let package_path = dir.join(&random_string);
//         fs::create_dir(&package_path)?;
//         fs::write(package_path.join("some_file"), random_string)?;
//         Ok(package_path.to_path_buf())
//     }
// }
