pub mod common;
use std::collections::HashMap;
use std::process::Command;

use anyhow::Result;
use tempfile::TempDir;

#[test]
fn test_no_peers_leads_to_error() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let temp_dir_path = temp_dir.path();

    let repo = temp_dir_path.join("cache");
    let package_path = common::build_nix_package("hello")?;
    let config = HashMap::from([("GACHIX__STORE__USE_LOCAL_NIX_DAEMON", "0")]);

    let result = common::add_to_cache(&package_path, &repo, Some(config));
    assert!(result.is_err());

    Ok(())
}

// Replication: a requester with NO Nix daemon must reconstruct an ENTIRE closure from a
// Git peer — one branch fetch transfers all closure objects, then every closure member is
// materialized as its own servable refs/heads/gachix/<shard>/<hash>. Regression test for
// the transactional / success-detection replication fixes.
#[test]
fn test_fetch_entire_closure_from_git_remote() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let temp_dir_path = temp_dir.path();

    let holder_path = temp_dir_path.join("holder");
    let requester_path = temp_dir_path.join("requester");

    let package_path = common::build_nix_package("hello")?;
    let hash = common::get_hash(&package_path)?;

    // Holder ingests the full closure via the local Nix daemon.
    common::add_to_cache(&package_path, &holder_path, None)?;

    // Requester has no daemon and no builders: it can only replicate from the holder.
    // remotes is Vec<Url>, so the local peer must be a file:// URL, not a bare path.
    let remote = format!("file://{}", holder_path.display());
    let user = std::env::var("USER").unwrap_or_default();
    let home = std::env::var("HOME").unwrap_or_default();
    let config = HashMap::from([
        ("GACHIX__STORE__REMOTES", remote.as_str()),
        ("GACHIX__STORE__USE_LOCAL_NIX_DAEMON", "0"),
        ("USER", user.as_str()),
        ("HOME", home.as_str()),
    ]);
    common::add_to_cache(&package_path, &requester_path, Some(config))?;

    // Every closure member must have a servable branch ref — not just the top package.
    let out = Command::new("git")
        .arg("-C")
        .arg(&requester_path)
        .arg("for-each-ref")
        .arg("--format=%(refname)")
        .arg("refs/heads/gachix/")
        .output()?;
    let refs = String::from_utf8_lossy(&out.stdout);
    let count = refs.lines().count();
    assert!(
        refs.contains(&format!("/{hash}")),
        "top package ref for {hash} missing after replication:\n{refs}"
    );
    assert!(
        count >= 2,
        "expected the whole closure (>=2 refs incl. dependencies), got {count}:\n{refs}"
    );

    Ok(())
}
//
// // This test only really tests partial fetches if we assume that it always tries to fetch from git
// // remotes first
// #[test]
// fn test_partial_fetch_from_git_remotes() -> Result<()> {
//     let temp_dir = TempDir::new()?;
//     let temp_dir_path = temp_dir.path();
//
//     let holder_path = temp_dir_path.join("holder");
//     let requester_path = temp_dir_path.join("requester");
//
//     let glibc_path = common::build_nix_package("glibc")?;
//     let hello_path = common::build_nix_package("hello")?;
//
//     let config = HashMap::from([
//         ("GACHIX__STORE__REMOTES", holder_path.to_str().unwrap()),
//         ("GACHIX__STORE__USE_LOCAL_NIX_DAEMON", "1"),
//     ]);
//
//     common::add_to_cache(&glibc_path, &holder_path, None)?;
//     common::add_to_cache(&hello_path, &requester_path, Some(config))?;
//
//     Ok(())
// }
