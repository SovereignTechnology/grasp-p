//! Crash-safe replacement of small state snapshots.

use std::fs::File;
use std::io::{self, Write};
use std::path::Path;

/// Replace `path` only after the complete new contents are durable.
pub(crate) fn write(path: &Path, contents: &[u8]) -> io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "snapshot path has no parent")
    })?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(contents)?;
    temporary.as_file_mut().sync_all()?;
    temporary.persist(path).map_err(|error| error.error)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomically_replaces_an_existing_snapshot() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.json");
        std::fs::write(&path, b"old").unwrap();

        write(&path, b"complete new snapshot").unwrap();

        assert_eq!(std::fs::read(path).unwrap(), b"complete new snapshot");
    }
}
