//! A Git repository on disk: loose objects and refs.
//!
//! Objects this crate writes are loose and byte-for-byte what Git expects,
//! so `git fsck --strict` accepts them. Reading supports loose objects and
//! loose refs (what `git commit` and `git branch` produce); packfiles and
//! packed refs are left to `gix` in a networked build.

use std::fmt::{self, Write};
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
        let mut out = String::with_capacity(self.0.len() * 2);
        for byte in &self.0 {
            let _ = write!(out, "{byte:02x}");
        }
        out
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
    ///
    /// Takes the same lock file as [`GitDir::compare_and_swap_ref`]. A held
    /// lock fails instead of writing over a compare-and-swap. This is a
    /// local `create_new` file, not a distributed lock.
    pub fn set_ref(&self, name: &str, oid: &Oid) -> io::Result<()> {
        let p = self.git.join(name);
        if let Some(d) = p.parent() {
            fs::create_dir_all(d)?;
        }
        let _lock = acquire_lock(&lock_path(&p)).map_err(lock_io)?;
        let tmp = sibling(&p, ".cas-tmp");
        fs::write(&tmp, format!("{}\n", oid.hex()))?;
        fs::rename(tmp, p)?;
        Ok(())
    }

    /// Read a loose ref.
    pub fn read_ref(&self, name: &str) -> Option<Oid> {
        Oid::from_hex(&fs::read_to_string(self.git.join(name)).ok()?)
    }

    /// Compare-and-swap a loose ref.
    ///
    /// `op_id` is the RCE-VC identity of this update attempt. It is not a Git
    /// object id. The ref target is a Git object id. A matching object id
    /// written by another attempt is not success for this `op_id`.
    ///
    /// The lock file is `{name}.lock`. The temporary file is `{name}.cas-tmp`
    /// (the whole file name, so a dotted ref such as `refs/tags/v1.2.3` is
    /// the file that moves). The op log is `.git/rcevc-cas/ops/{name}/{op_id}`
    /// and is executor-local state, not a Git object and not an admission
    /// receipt. A held lock returns [`RefUpdateError::Busy`] instead of
    /// waiting. The same op id with a different object id is
    /// [`RefUpdateError::OpRetarget`]. This is a local filesystem lock, not
    /// a distributed one, and it does not claim crash durability beyond the
    /// rename of the loose ref.
    pub fn compare_and_swap_ref(
        &self,
        name: &str,
        op_id: rcevc_core::Digest,
        expected: Option<Oid>,
        new_oid: Oid,
    ) -> Result<RefCas, RefUpdateError> {
        let path = checked_ref_path(&self.git, name)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let lock_path = lock_path(&path);
        let _lock = acquire_lock(&lock_path)?;
        if let Some(wrote) = read_op(&self.op_path(name, &op_id))? {
            if wrote != new_oid {
                return Err(RefUpdateError::OpRetarget {
                    wrote,
                    requested: new_oid,
                });
            }
            let still_tip = self.read_ref(name) == Some(wrote);
            return Ok(RefCas::Replay { wrote, still_tip });
        }
        let current = self.read_ref(name);
        if current != expected {
            if current == Some(new_oid) {
                return Err(RefUpdateError::Unrelated { current: new_oid });
            }
            return Err(RefUpdateError::Stale { expected, current });
        }
        let tmp = sibling(&path, ".cas-tmp");
        fs::write(&tmp, format!("{}\n", new_oid.hex()))?;
        fs::rename(&tmp, &path)?;
        let op = self.op_path(name, &op_id);
        if let Some(parent) = op.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(op, format!("{}\n", new_oid.hex()))?;
        Ok(RefCas::Applied { oid: new_oid })
    }

    fn op_path(&self, name: &str, op_id: &rcevc_core::Digest) -> PathBuf {
        self.git
            .join("rcevc-cas")
            .join("ops")
            .join(name)
            .join(op_id.hex())
    }
}

/// Result of [`GitDir::compare_and_swap_ref`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefCas {
    /// This op id moved the ref to `oid`.
    Applied {
        /// New tip.
        oid: Oid,
    },
    /// This op id was already applied. The ref was not written again.
    Replay {
        /// Object id the op log recorded.
        wrote: Oid,
        /// Whether the loose ref is still `wrote`.
        still_tip: bool,
    },
}

/// Why a ref compare-and-swap did not apply.
#[derive(Debug)]
pub enum RefUpdateError {
    /// Filesystem error.
    Io(io::Error),
    /// The lock file already exists.
    Busy,
    /// The ref name is not a loose ref under `refs/`.
    RefusedName,
    /// The op log or ref bytes are not an object id.
    Corrupt(String),
    /// The tip is not the expected object id.
    Stale {
        /// Object id the caller required, or absent.
        expected: Option<Oid>,
        /// Object id now stored, or absent.
        current: Option<Oid>,
    },
    /// The tip is already `current`, and this op id did not write it.
    Unrelated {
        /// Current tip.
        current: Oid,
    },
    /// This op id already wrote `wrote`, and the retry asked for `requested`.
    OpRetarget {
        /// Object id in the op log.
        wrote: Oid,
        /// Object id the retry asked to write.
        requested: Oid,
    },
}

impl From<io::Error> for RefUpdateError {
    fn from(e: io::Error) -> Self {
        RefUpdateError::Io(e)
    }
}

impl fmt::Display for RefUpdateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for RefUpdateError {}

fn checked_ref_path(git: &Path, name: &str) -> Result<PathBuf, RefUpdateError> {
    if !name.starts_with("refs/")
        || name.contains("..")
        || name.contains('\\')
        || name.contains("//")
        || name.ends_with('/')
    {
        return Err(RefUpdateError::RefusedName);
    }
    if name
        .split('/')
        .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(RefUpdateError::RefusedName);
    }
    Ok(git.join(name))
}

fn lock_path(ref_path: &Path) -> PathBuf {
    sibling(ref_path, ".lock")
}

fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut os = path.as_os_str().to_os_string();
    os.push(suffix);
    PathBuf::from(os)
}

fn lock_io(err: RefUpdateError) -> io::Error {
    io::Error::new(io::ErrorKind::Other, err.to_string())
}

struct LockGuard {
    path: PathBuf,
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn acquire_lock(path: &Path) -> Result<LockGuard, RefUpdateError> {
    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
    {
        Ok(_) => Ok(LockGuard {
            path: path.to_path_buf(),
        }),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Err(RefUpdateError::Busy),
        Err(e) => Err(RefUpdateError::Io(e)),
    }
}

fn read_op(path: &Path) -> Result<Option<Oid>, RefUpdateError> {
    match fs::read_to_string(path) {
        Ok(text) => match Oid::from_hex(text.trim()) {
            Some(oid) => Ok(Some(oid)),
            None => Err(RefUpdateError::Corrupt("op log".into())),
        },
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(RefUpdateError::Io(e)),
    }
}
