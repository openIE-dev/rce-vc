//! A Git repository on disk: loose objects and refs.
//!
//! Objects this crate writes are loose and byte-for-byte what Git expects,
//! so `git fsck --strict` accepts them. Reading supports loose objects and
//! loose refs (what `git commit` and `git branch` produce); packfiles and
//! packed refs are left to `gix` in a networked build.

use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::codec::{sha1, zlib_inflate, zlib_store};

/// A Git object id (SHA-1).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Oid(pub [u8; 20]);

impl Oid {
    /// Lowercase hex.
    pub fn hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }
    /// Parse 40 hex characters.
    pub fn from_hex(s: &str) -> Option<Oid> {
        let s = s.trim().as_bytes();
        if s.len() != 40 {
            return None;
        }
        let mut out = [0u8; 20];
        for (i, p) in s.chunks_exact(2).enumerate() {
            out[i] = ((p[0] as char).to_digit(16)? * 16 + (p[1] as char).to_digit(16)?) as u8;
        }
        Some(Oid(out))
    }
}

impl fmt::Debug for Oid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", &self.hex()[..10])
    }
}

impl fmt::Display for Oid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.hex())
    }
}

/// Errors from the projection.
#[derive(Debug)]
pub enum ProjError {
    /// Filesystem error.
    Io(io::Error),
    /// Malformed object or ref.
    Corrupt(String),
    /// A Git feature this version does not handle.
    Unsupported(String),
    /// A slot that cannot be a path, or a file/directory clash.
    Path(String),
    /// A file that is not UTF-8.
    NonUtf8(String),
    /// The commit does not descend from an admitted state.
    NoBase(String),
    /// The state is not well formed.
    Wf(rcevc_core::WfError),
}

impl From<io::Error> for ProjError {
    fn from(e: io::Error) -> Self {
        ProjError::Io(e)
    }
}

impl fmt::Display for ProjError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for ProjError {}

/// A repository: `<work>/.git`.
pub struct GitDir {
    git: PathBuf,
}

impl GitDir {
    /// Open or create a repository whose work tree is `work`.
    pub fn init(work: &Path) -> io::Result<GitDir> {
        let git = work.join(".git");
        fs::create_dir_all(git.join("objects"))?;
        fs::create_dir_all(git.join("refs/heads"))?;
        fs::create_dir_all(git.join("refs/tags"))?;
        if !git.join("HEAD").exists() {
            fs::write(git.join("HEAD"), "ref: refs/heads/main\n")?;
        }
        if !git.join("config").exists() {
            fs::write(
                git.join("config"),
                "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n",
            )?;
        }
        Ok(GitDir { git })
    }

    /// Path of the `.git` directory.
    pub fn path(&self) -> &Path {
        &self.git
    }

    fn obj_path(&self, oid: &Oid) -> PathBuf {
        let h = oid.hex();
        self.git.join("objects").join(&h[..2]).join(&h[2..])
    }

    /// Hash an object without writing it.
    pub fn hash(kind: &str, data: &[u8]) -> Oid {
        let mut full = format!("{kind} {}\0", data.len()).into_bytes();
        full.extend_from_slice(data);
        Oid(sha1(&full))
    }

    /// Write an object (idempotent).
    pub fn write(&self, kind: &str, data: &[u8]) -> io::Result<Oid> {
        let mut full = format!("{kind} {}\0", data.len()).into_bytes();
        full.extend_from_slice(data);
        let oid = Oid(sha1(&full));
        let p = self.obj_path(&oid);
        if !p.exists() {
            let dir = p.parent().expect("object path has a parent");
            fs::create_dir_all(dir)?;
            let tmp = dir.join(format!("tmp-{}", oid.hex()));
            fs::write(&tmp, zlib_store(&full))?;
            fs::rename(tmp, &p)?;
        }
        Ok(oid)
    }

    /// Read and verify an object: (kind, payload).
    pub fn read(&self, oid: &Oid) -> Result<(String, Vec<u8>), ProjError> {
        let p = self.obj_path(oid);
        let raw = match fs::read(&p) {
            Ok(r) => r,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Err(ProjError::Unsupported(format!("object {oid:?} not loose (packfiles need gix)")));
            }
            Err(e) => return Err(e.into()),
        };
        let full = zlib_inflate(&raw).map_err(ProjError::Corrupt)?;
        if sha1(&full) != oid.0 {
            return Err(ProjError::Corrupt(format!("object {oid:?} hash mismatch")));
        }
        let nul = full.iter().position(|&b| b == 0).ok_or_else(|| ProjError::Corrupt("no header".into()))?;
        let header = std::str::from_utf8(&full[..nul]).map_err(|_| ProjError::Corrupt("header".into()))?;
        let (kind, len) = header.split_once(' ').ok_or_else(|| ProjError::Corrupt("header".into()))?;
        let body = full[nul + 1..].to_vec();
        if len.parse::<usize>().ok() != Some(body.len()) {
            return Err(ProjError::Corrupt("length mismatch".into()));
        }
        Ok((kind.to_string(), body))
    }

    /// Point `name` (for example `refs/heads/main`) at `oid`.
    pub fn set_ref(&self, name: &str, oid: &Oid) -> io::Result<()> {
        let p = self.git.join(name);
        if let Some(d) = p.parent() {
            fs::create_dir_all(d)?;
        }
        fs::write(p, format!("{}\n", oid.hex()))
    }

    /// Read a loose ref.
    pub fn read_ref(&self, name: &str) -> Option<Oid> {
        Oid::from_hex(&fs::read_to_string(self.git.join(name)).ok()?)
    }
}
