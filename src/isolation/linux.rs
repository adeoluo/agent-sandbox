//! Landlock ruleset construction (Linux 5.13+), using raw syscalls.
//!
//! The ruleset is built in the parent: every allowed root is opened with `O_PATH` and added
//! as a `PATH_BENEATH` rule. The forked child then only calls `prctl(PR_SET_NO_NEW_PRIVS)`
//! and `landlock_restrict_self`, both async-signal-safe.

use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use crate::policy::{CompiledPolicy, NetworkMode};

const CREATE_RULESET_VERSION: libc::c_uint = 1 << 0;
const RULE_PATH_BENEATH: libc::c_int = 1;

const EXECUTE: u64 = 1 << 0;
const WRITE_FILE: u64 = 1 << 1;
const READ_FILE: u64 = 1 << 2;
const READ_DIR: u64 = 1 << 3;
const REFER: u64 = 1 << 13;
const TRUNCATE: u64 = 1 << 14;
const ABI1_ALL: u64 = (1 << 13) - 1;

const NET_BIND_TCP: u64 = 1 << 0;
const NET_CONNECT_TCP: u64 = 1 << 1;

#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
    handled_access_net: u64,
}

#[repr(C, packed)]
struct PathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

/// The kernel's Landlock ABI version, or an error if Landlock is unsupported or disabled.
pub fn abi() -> io::Result<i32> {
    // SAFETY: a NULL attribute with size 0 and the VERSION flag only queries the ABI.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<RulesetAttr>(),
            0usize,
            CREATE_RULESET_VERSION,
        )
    };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(rc as i32)
    }
}

/// A ready-to-apply ruleset.
#[derive(Debug)]
pub struct Ruleset {
    fd: OwnedFd,
    pub abi: i32,
    /// TCP bind/connect is restricted (ABI 4+ and network mode `deny`).
    pub network: bool,
}

impl Ruleset {
    pub fn build(policy: &CompiledPolicy, program: &Path) -> io::Result<Self> {
        let abi =
            abi().map_err(|e| io::Error::new(e.kind(), format!("Landlock unavailable: {e}")))?;
        let mut handled = ABI1_ALL;
        if abi >= 2 {
            handled |= REFER;
        }
        if abi >= 3 {
            handled |= TRUNCATE;
        }
        let network = abi >= 4 && policy.policy.network.mode == NetworkMode::Deny;
        let attr = RulesetAttr {
            handled_access_fs: handled,
            handled_access_net: if network {
                NET_BIND_TCP | NET_CONNECT_TCP
            } else {
                0
            },
        };
        // SAFETY: attr is a valid, initialized struct of the given size.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                &attr as *const RulesetAttr,
                std::mem::size_of::<RulesetAttr>(),
                0u32,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the syscall returned a new, owned file descriptor.
        let fd = unsafe { OwnedFd::from_raw_fd(fd as RawFd) };
        let ruleset = Self { fd, abi, network };

        let read = EXECUTE | READ_FILE | READ_DIR;
        for root in &policy.read_roots {
            ruleset.add(root, read, handled)?;
        }
        for root in &policy.writable_roots {
            ruleset.add(root, handled, handled)?;
        }
        for dev in ["/dev/null", "/dev/zero"] {
            ruleset.add(Path::new(dev), READ_FILE | WRITE_FILE | TRUNCATE, handled)?;
        }
        for dev in ["/dev/urandom", "/dev/random"] {
            ruleset.add(Path::new(dev), READ_FILE, handled)?;
        }
        ruleset.add(program, EXECUTE | READ_FILE, handled)?;
        Ok(ruleset)
    }

    fn add(&self, path: &Path, access: u64, handled: u64) -> io::Result<()> {
        let Ok(meta) = std::fs::metadata(path) else {
            return Ok(());
        };
        let mut access = access & handled;
        if !meta.is_dir() {
            access &= EXECUTE | WRITE_FILE | READ_FILE | TRUNCATE;
        }
        let c_path = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| io::Error::other("path contains NUL"))?;
        // SAFETY: c_path is a valid NUL-terminated string.
        let raw = unsafe { libc::open(c_path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: open returned a new, owned file descriptor.
        let parent = unsafe { OwnedFd::from_raw_fd(raw) };
        let attr = PathBeneathAttr {
            allowed_access: access,
            parent_fd: parent.as_raw_fd(),
        };
        // SAFETY: attr is a valid packed struct as the kernel expects.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_landlock_add_rule,
                self.fd.as_raw_fd(),
                RULE_PATH_BENEATH,
                &attr as *const PathBeneathAttr,
                0u32,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub fn raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

/// Applies a ruleset to the calling process. Runs in the forked child.
pub fn restrict_self(fd: RawFd) -> io::Result<()> {
    // SAFETY: prctl and syscall are async-signal-safe; arguments are plain integers.
    unsafe {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return Err(io::Error::last_os_error());
        }
        if libc::syscall(libc::SYS_landlock_restrict_self, fd, 0u32) != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}
