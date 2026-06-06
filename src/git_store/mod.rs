pub mod repository;
pub use repository::GitRepo;
pub mod store;

const SINGLE_FILE_PACKAGE_MARKER: &str = "gachix-single-file";

/// Branch namespace for package commits: refs/heads/gachix/<shard>/<hash>
pub const PACKAGE_REF_PREFIX: &str = "refs/heads/gachix";
