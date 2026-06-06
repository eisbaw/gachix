use super::PACKAGE_REF_PREFIX;
use super::SINGLE_FILE_PACKAGE_MARKER;
use std::fs;
use std::str::FromStr;

use crate::git_store::GitRepo;
use crate::nar::NarGitStream;
use crate::nix_interface::daemon::DynNixDaemon;
use crate::nix_interface::daemon::NixDaemon;
use crate::nix_interface::nar_info::NarInfo;
use crate::nix_interface::path::NixPath;
use crate::nix_interface::signature::PrivateKey;
use crate::nix_interface::signature::fingerprint_store_object;
use crate::settings;
use anyhow::{anyhow, bail};
use async_recursion::async_recursion;
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use git2::FileMode;
use git2::Oid;
use tracing::{debug, info, warn};

use anyhow::Result;

/// A valid 32-char Nix base32 store hash (alphabet `[0-9a-z]`).
///
/// HTTP handlers pass the raw URL component straight to the readers below; this is the
/// trust-boundary check that prevents a crafted hash (e.g. containing `/` or `..`) from
/// being interpolated into a ref path. `NixPath::new` enforces length but not charset.
fn valid_hash(h: &str) -> bool {
    h.len() == 32 && h.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

/// Shard = first 2 chars of the 32-char base32 hash (1024 buckets). base32 is single-byte
/// ASCII, so `[..2]` never splits a char.
fn shard(hash: &str) -> &str {
    debug_assert_eq!(hash.len(), 32);
    &hash[..2]
}

/// The package branch ref: `refs/heads/gachix/<shard>/<hash>`. One ref per package; the
/// commit it points at carries the contents (tree), the dependency closure (parents), and
/// the signed narinfo (commit message).
fn get_package_ref(hash: &str) -> String {
    format!("{PACKAGE_REF_PREFIX}/{}/{}", shard(hash), hash)
}

#[derive(Clone)]
pub struct Store {
    settings: settings::Store,
    repo: GitRepo,
    private_key: Option<PrivateKey>,
}

impl Store {
    pub fn new(settings: settings::Store) -> Result<Self> {
        let repo = GitRepo::new(&settings.path)?;

        let private_key = if let Some(key_path) = &settings.sign_private_key_path {
            let key = PrivateKey::from_str(&fs::read_to_string(key_path)?)?;
            info!(
                "Using private key located at: {:?}",
                fs::canonicalize(key_path)?
            );
            Some(key)
        } else {
            None
        };

        let store = Self {
            settings,
            repo,
            private_key,
        };
        info!(
            "Repository contains {} packages",
            store.num_available_packages()?
        );
        Ok(store)
    }

    pub fn available_daemons(&self) -> Result<Vec<DynNixDaemon>> {
        let mut daemons = Vec::new();
        if self.settings.use_local_nix_daemon {
            daemons.push(DynNixDaemon::Local(NixDaemon::local()));
        }
        if self.settings.builders.is_empty() {
            return Ok(daemons);
        }
        let key_file = self.settings.ssh_private_key_path.as_ref().ok_or_else(|| {
            anyhow!("Path to private ssh key must be specified when using remote Nix daemons")
        })?;

        for url in &self.settings.builders {
            daemons.push(DynNixDaemon::Remote(NixDaemon::remote(
                &url.host_str().unwrap(),
                key_file.clone(),
            )));
        }
        Ok(daemons)
    }

    pub async fn peer_health_check(&self) -> bool {
        let mut success = true;

        for mut daemon in self.available_daemons().unwrap() {
            match daemon.connect().await {
                Ok(_) => info!(
                    "Succesfully connected to Nix daemon at {}",
                    daemon.get_address()
                ),
                Err(e) => {
                    success = false;
                    warn!(
                        "Failed to connect to remote Nix daemon at {} : {}",
                        daemon.get_address(),
                        e
                    )
                }
            };
            daemon.disconnect();
        }

        for url in &self.settings.remotes {
            let url_str = url.as_str();
            // host() is None for hostless peers (e.g. file:// local peers); fall back to
            // the full URL for logging rather than panicking.
            let host = url.host_str().unwrap_or(url_str);
            match self.repo.check_remote_health(&url_str) {
                Ok(_) => info!("Succesfully connected to Git repository at {}", host),
                Err(e) => {
                    success = false;
                    warn!("Failed to connect to Git repository {}: {}", host, e)
                }
            }
        }

        success
    }

    /// Add a single package without materializing its dependency closure. Produces a
    /// parentless commit (tree = contents, message = signed narinfo) under one branch ref —
    /// self-consistent and servable; its references are intentionally not fetched/committed.
    pub async fn add_single(&self, package_path: &NixPath) -> Result<()> {
        info!("Adding single package {}", package_path.get_name());
        let package_id = package_path.get_base_32_hash();

        if self.repo.reference_exists(&get_package_ref(package_id))? {
            debug!("Package already exists");
            return Ok(());
        }

        let Ok(Some((narinfo, package_oid))) =
            self.get_package_from_nix_daemons(package_path).await
        else {
            bail!(
                "There doesn't exist a Nix daemon which has {}",
                package_path
            );
        };

        let message = narinfo.to_string();
        let commit_oid = self.repo.commit(package_oid, &[], Some(&message))?;
        self.repo.add_ref(&get_package_ref(package_id), commit_oid)?;
        Ok(())
    }

    pub async fn add_closure(&self, package_path: &NixPath) -> Result<()> {
        info!("Adding closure for {}", package_path.get_name());
        let entries_before = self.num_available_packages()?;
        match self._add_closure(package_path).await? {
            Some(_) => {
                let entries_after = self.num_available_packages()?;
                let num_packages_added = entries_after - entries_before;
                info!("Added {num_packages_added} packages")
            }
            None => bail!(
                "Could not add closure of package {}",
                package_path.get_name()
            ),
        }
        Ok(())
    }

    #[async_recursion]
    pub async fn _add_closure(&self, package_path: &NixPath) -> Result<Option<Oid>> {
        let package_id = package_path.get_base_32_hash();

        // Check if the package commit already exists locally
        if let Some(commit_oid) = self.get_commit(package_id) {
            debug!("Package already exists: {}", package_path.get_name());
            return Ok(Some(commit_oid));
        }

        // Ask Git peers if they have replicated the package (and its closure)
        if let Some(commit_oid) = self.get_package_commit_from_git_remotes(package_path)? {
            return Ok(Some(commit_oid));
        }

        // Ask known Nix daemons if they can provide the package
        let Ok(Some((narinfo, package_oid))) =
            self.get_package_from_nix_daemons(package_path).await
        else {
            return Ok(None);
        };

        // Recurse into package dependencies and collect their commit oids
        let deps = narinfo.get_dependencies();
        let mut parent_commits = Vec::new();
        for dependency in &deps {
            let Some(dep_coid) = self._add_closure(dependency).await? else {
                return Ok(None);
            };
            parent_commits.push(dep_coid);
        }

        // ONE commit per package: tree = contents, parents = dependency commits,
        // message = the signed narinfo. ONE ref => atomic publish.
        let message = narinfo.to_string();
        let commit_oid = self
            .repo
            .commit(package_oid, &parent_commits, Some(&message))?;
        self.repo.add_ref(&get_package_ref(package_id), commit_oid)?;
        Ok(Some(commit_oid))
    }

    pub async fn get_package_from_nix_daemons(
        &self,
        package_path: &NixPath,
    ) -> Result<Option<(NarInfo, Oid)>> {
        for mut daemon in self.available_daemons()? {
            daemon.connect().await?;
            // Ask if daemon has the package
            // TODO: ask it to build the package if it does not have it
            if !daemon.path_exists(package_path).await? {
                continue;
            };
            // Add the package contents to the Git database
            let clone = self.repo.clone();
            let (mut package_oid, filemode) = daemon
                .fetch(package_path, move |r| Ok(clone.add_nar(r)?))
                .await?;

            // Handle single file packages
            // Commits can only point to trees therefore we need to wrap the blob in a special tree
            if filemode != i32::from(FileMode::Tree) {
                package_oid = self.repo.add_single_entry_tree(
                    package_oid,
                    SINGLE_FILE_PACKAGE_MARKER,
                    filemode,
                )?;
            }

            // Build narinfo metadata (signed). It is stored in the commit message, not as a
            // separate blob, so there is nothing extra to write to the object database here.
            let narinfo = self
                .build_narinfo(&mut daemon, package_oid.to_string().as_str(), package_path)
                .await?;

            match &daemon {
                DynNixDaemon::Local(_) => {
                    debug!("Using local daemon, fetched {} ", package_path.get_name())
                }
                DynNixDaemon::Remote(daemon) => debug!(
                    "Using daemon at {}, fetched package {}",
                    daemon.get_address(),
                    package_path.get_name()
                ),
            }
            daemon.disconnect();
            return Ok(Some((narinfo, package_oid)));
        }
        Ok(None)
    }

    /// Replicate a package and its whole closure from a Git peer.
    ///
    /// Fetching the single top branch transfers every reachable object (all dependency
    /// commits, trees, blobs) via the commit DAG. We then materialize a local branch ref
    /// for each closure member so every package is independently servable by hash.
    fn get_package_commit_from_git_remotes(&self, store_path: &NixPath) -> Result<Option<Oid>> {
        let package_id = store_path.get_base_32_hash();
        let top_ref = get_package_ref(package_id);

        for remote_url in &self.settings.remotes {
            // fetch_ref pulls the whole closure into the ODB via a scratch ref and returns
            // the tip OID (or None if this remote does not have the package). It does NOT
            // create the canonical package ref — materialize_closure_refs does, only after
            // the whole closure validates, so a partial/corrupt fetch never short-circuits
            // a later re-fetch (transactional replication).
            let Some(top_oid) = self.repo.fetch_ref(remote_url.as_str(), &top_ref)? else {
                continue;
            };
            debug!(
                "Using git peer at {}, fetched closure of {}",
                remote_url,
                store_path.get_name()
            );
            self.materialize_closure_refs(top_oid)?;
            return Ok(Some(top_oid));
        }
        Ok(None)
    }

    /// Create `refs/heads/gachix/<shard>/<hash>` for every package in the closure reachable
    /// from `tip`, recovering each hash from the commit's narinfo (`StorePath:`). Objects are
    /// already present from the single closure fetch.
    ///
    /// Transactional in two phases: (1) parse EVERY commit's narinfo first — any failure
    /// (corruption / mixed-layout) aborts before a single canonical ref is written, so no
    /// half-closure is left behind; (2) write the refs deps-first, the TOP ref LAST, so even
    /// a ref-write failure cannot leave the top ref present (which would make a later
    /// `_add_closure` short-circuit and never retry).
    fn materialize_closure_refs(&self, tip: Oid) -> Result<()> {
        // walk_commits yields the tip first, then its ancestors.
        let mut to_create = Vec::new();
        for commit_oid in self.repo.walk_commits(tip)? {
            let msg = self.repo.get_commit_message_raw(commit_oid)?;
            let narinfo = NarInfo::parse(&String::from_utf8_lossy(&msg))?;
            let hash = narinfo.store_path.get_base_32_hash().to_string();
            to_create.push((hash, commit_oid));
        }
        // Reverse so dependencies are written before the top package commit.
        for (hash, commit_oid) in to_create.into_iter().rev() {
            let r = get_package_ref(&hash);
            if !self.repo.reference_exists(&r)? {
                self.repo.add_ref(&r, commit_oid)?;
            }
        }
        Ok(())
    }

    async fn build_narinfo(
        &self,
        nix_daemon: &mut DynNixDaemon,
        key: &str,
        store_path: &NixPath,
    ) -> Result<NarInfo> {
        let Some(path_info) = nix_daemon.get_pathinfo(&store_path).await? else {
            return Err(anyhow!(
                "Could not find narinfo for {}",
                store_path.get_path()
            ));
        };
        let references: Vec<NixPath> = path_info
            .references
            .iter()
            .map(|p| NixPath::new(p))
            .collect::<Result<Vec<_>, _>>()?;

        let nar_size = path_info.nar_size;
        let nar_hash = hex::decode(path_info.nar_hash)?;

        // TODO: compute hash instead of copying it and verify it against the received hash
        let mut nar_hash_32_base = nix_base32::to_nix_base32(&nar_hash);
        // TODO: formatting should be handled by the NarInfo struct
        nar_hash_32_base = format!("sha256:{}", nar_hash_32_base);

        let signature = self.private_key.as_ref().map(|private_key| {
            let fingerprint =
                fingerprint_store_object(store_path, &nar_hash_32_base, nar_size, &references);
            let signature_bytes = private_key.sign(fingerprint.as_bytes());
            format!(
                "{}:{}",
                private_key.name,
                BASE64_STANDARD.encode(signature_bytes)
            )
        });

        let deriver = path_info.deriver.map(|d| NixPath::new(&d)).transpose()?;
        let narinfo = NarInfo::new(
            store_path.clone(),
            key.to_string(),
            nar_hash_32_base.clone(),
            path_info.nar_size,
            None,
            nar_hash_32_base,
            path_info.nar_size,
            deriver,
            references,
            signature,
        );
        Ok(narinfo)
    }

    pub fn get_narinfo(&self, base32_hash: &str) -> Result<Option<Vec<u8>>> {
        if !valid_hash(base32_hash) {
            return Ok(None);
        }
        match self.repo.get_oid_from_reference(&get_package_ref(base32_hash)) {
            Some(commit_oid) => Ok(Some(self.repo.get_commit_message_raw(commit_oid)?)),
            None => Ok(None),
        }
    }

    pub fn entry_exists(&self, base32_hash: &str) -> Result<bool> {
        if !valid_hash(base32_hash) {
            return Ok(false);
        }
        self.repo.reference_exists(&get_package_ref(base32_hash))
    }

    pub fn get_as_nar_stream(&self, key: &str) -> Result<Option<NarGitStream>> {
        // `key` is a git tree/blob OID hex (from the narinfo URL), validated by Oid::from_str
        // below — NOT a store hash, so valid_hash() does not apply here.
        let tree_oid = Oid::from_str(key)?;
        // get the blob oid if the package consists of a single file
        // else use the package tree oid
        let oid = self
            .repo
            .match_sole_entry_id(tree_oid, SINGLE_FILE_PACKAGE_MARKER)?
            .unwrap_or(tree_oid);
        self.repo.get_entry_as_nar(oid)
    }

    pub fn list_entries(&self) -> Result<Vec<String>> {
        self.repo.list_references("refs/heads/gachix/*/*")
    }

    fn num_available_packages(&self) -> Result<usize> {
        Ok(self.repo.list_references("refs/heads/gachix/*/*")?.len())
    }

    pub fn get_commit(&self, hash: &str) -> Option<Oid> {
        if !valid_hash(hash) {
            return None;
        }
        self.repo.get_oid_from_reference(&get_package_ref(hash))
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        git_store::store::Store,
        nix_interface::{
            daemon::{DynNixDaemon, NixDaemon},
            path::NixPath,
        },
        settings,
    };
    use anyhow::Result;
    use std::path::PathBuf;
    use std::process::Command;
    use tempfile::TempDir;

    fn build_nix_package(package_name: &str) -> Result<NixPath> {
        let output = Command::new("nix")
            .arg("build")
            .arg(format!("nixpkgs#{}", package_name))
            .arg("--print-out-paths")
            .output()?;

        let path = NixPath::new(&String::from_utf8_lossy(&output.stdout).to_string())?;
        Ok(path)
    }

    pub fn set_repo_path(path: &PathBuf) -> settings::Store {
        settings::Store {
            path: path.clone(),
            builders: vec![],
            remotes: vec![],
            use_local_nix_daemon: true,
            sign_private_key_path: None,
            ssh_private_key_path: None,
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_add_package() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let repo_path = temp_dir.path().join("gachix");
        let store = Store::new(set_repo_path(&repo_path))?;

        let path = build_nix_package("hello")?;
        store.get_package_from_nix_daemons(&path).await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_add_closure() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let repo_path = temp_dir.path().join("gachix");
        let store = Store::new(set_repo_path(&repo_path))?;

        let path = build_nix_package("sl")?;
        store.add_closure(&path).await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_add_narinfo() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let repo_path = temp_dir.path().join("gachix");
        let store = Store::new(set_repo_path(&repo_path))?;

        let path = build_nix_package("kitty")?;
        let mut nix = DynNixDaemon::Local(NixDaemon::local());
        nix.connect().await?;
        store.build_narinfo(&mut nix, "somekey", &path).await?;
        Ok(())
    }
}
