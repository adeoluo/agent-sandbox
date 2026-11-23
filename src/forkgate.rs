//! Kernel-mediated process cap for uid 0 on Linux when cgroup v2 `pids.max` is not writable.
//!
//! The kernel ignores `RLIMIT_NPROC` for root, and a parent that polls `/proc` can only react
//! after the fact. This module makes the cap deterministic instead: the child installs a
//! seccomp filter that routes every `clone`, `clone3`, `fork` and `vfork` made by the command
//! or any descendant to a supervisor thread through a seccomp user-notification listener. The
//! calling task stays blocked in the kernel while the supervisor counts the live tasks of the
//! process group, then either lets the call continue or fails it with `EAGAIN`.
//!
//! The count is taken over the process group, so the same filter refuses `setsid` and
//! `setpgid` with `EPERM`: a task cannot leave the group that is being counted.
//! Foreign-architecture system calls (and the x32 ABI on x86-64) are refused, because their
//! numbers differ and would bypass the gate.
//!
//! The mechanism needs Linux 5.5 or newer and a runtime that permits seccomp listeners. When
//! it is unavailable the sandbox refuses to run a policy that sets `max_processes` rather than
//! pretend the cap is enforced (see `limits::ProcessCap`).

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod imp {
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Arc, OnceLock};
    use std::thread::{self, JoinHandle};
    use std::time::{Duration, Instant};

    const BPF_LD_W_ABS: u16 = 0x20;
    const BPF_JEQ_K: u16 = 0x15;
    #[cfg(target_arch = "x86_64")]
    const BPF_JGE_K: u16 = 0x35;
    const BPF_RET_K: u16 = 0x06;

    const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
    const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
    const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc0_0000;

    const SECCOMP_SET_MODE_FILTER: libc::c_ulong = 1;
    const SECCOMP_FILTER_FLAG_NEW_LISTENER: libc::c_ulong = 1 << 3;
    const SECCOMP_USER_NOTIF_FLAG_CONTINUE: u32 = 1;

    // _IOWR('!', 0, struct seccomp_notif) and _IOWR('!', 1, struct seccomp_notif_resp).
    const SECCOMP_IOCTL_NOTIF_RECV: u64 = 0xC050_2100;
    const SECCOMP_IOCTL_NOTIF_SEND: u64 = 0xC018_2101;

    const OFFSET_NR: u32 = 0;
    const OFFSET_ARCH: u32 = 4;

    #[cfg(target_arch = "x86_64")]
    const AUDIT_ARCH_NATIVE: u32 = 0xC000_003E;
    #[cfg(target_arch = "aarch64")]
    const AUDIT_ARCH_NATIVE: u32 = 0xC000_00B7;

    /// How long the supervisor waits for an approved fork to become visible in `/proc` before
    /// it handles the next request, so concurrent forkers cannot each be counted against a
    /// stale total.
    const SETTLE: Duration = Duration::from_millis(5);

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct SeccompData {
        nr: libc::c_int,
        arch: u32,
        instruction_pointer: u64,
        args: [u64; 6],
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct SeccompNotif {
        id: u64,
        pid: u32,
        flags: u32,
        data: SeccompData,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct SeccompNotifResp {
        id: u64,
        val: i64,
        error: i32,
        flags: u32,
    }

    /// Control-message buffer aligned for `cmsghdr`.
    #[repr(C, align(8))]
    struct CmsgBuf([u8; 64]);

    const fn stmt(code: u16, k: u32) -> libc::sock_filter {
        libc::sock_filter {
            code,
            jt: 0,
            jf: 0,
            k,
        }
    }

    const fn jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
        libc::sock_filter { code, jt, jf, k }
    }

    /// System calls that create a task.
    fn gated() -> Vec<u32> {
        #[cfg(target_arch = "x86_64")]
        let legacy = [libc::SYS_fork as u32, libc::SYS_vfork as u32];
        #[cfg(not(target_arch = "x86_64"))]
        let legacy: [u32; 0] = [];
        [libc::SYS_clone as u32, libc::SYS_clone3 as u32]
            .into_iter()
            .chain(legacy)
            .collect()
    }

    /// System calls that would move a task out of the counted process group.
    fn refused() -> [u32; 2] {
        [libc::SYS_setsid as u32, libc::SYS_setpgid as u32]
    }

    /// The seccomp program. Built in the parent so the child only reads it.
    pub fn filter() -> Vec<libc::sock_filter> {
        let eperm = SECCOMP_RET_ERRNO | libc::EPERM as u32;
        let mut f = vec![
            stmt(BPF_LD_W_ABS, OFFSET_ARCH),
            jump(BPF_JEQ_K, AUDIT_ARCH_NATIVE, 1, 0),
            stmt(BPF_RET_K, eperm),
            stmt(BPF_LD_W_ABS, OFFSET_NR),
        ];
        #[cfg(target_arch = "x86_64")]
        {
            // The x32 ABI reuses this architecture value with bit 30 set in the number.
            f.push(jump(BPF_JGE_K, 0x4000_0000, 0, 1));
            f.push(stmt(BPF_RET_K, SECCOMP_RET_ERRNO | libc::ENOSYS as u32));
        }
        let gated = gated();
        let refused = refused();
        let comparisons = gated.len() + refused.len();
        // Layout after the comparisons: [allow] [notify] [eperm].
        for (i, nr) in gated.iter().enumerate() {
            let after = comparisons - i - 1;
            f.push(jump(BPF_JEQ_K, *nr, (after + 1) as u8, 0));
        }
        for (j, nr) in refused.iter().enumerate() {
            let after = refused.len() - j - 1;
            f.push(jump(BPF_JEQ_K, *nr, (after + 2) as u8, 0));
        }
        f.push(stmt(BPF_RET_K, SECCOMP_RET_ALLOW));
        f.push(stmt(BPF_RET_K, SECCOMP_RET_USER_NOTIF));
        f.push(stmt(BPF_RET_K, eperm));
        f
    }

    /// Installs the filter and returns the listener, or -1. Async-signal-safe.
    unsafe fn install(prog: &[libc::sock_filter]) -> libc::c_int {
        // SAFETY: plain integer arguments; the program outlives the call.
        unsafe {
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return -1;
            }
            let fprog = libc::sock_fprog {
                len: prog.len() as libc::c_ushort,
                filter: prog.as_ptr().cast_mut(),
            };
            libc::syscall(
                libc::SYS_seccomp,
                SECCOMP_SET_MODE_FILTER,
                SECCOMP_FILTER_FLAG_NEW_LISTENER,
                &fprog as *const libc::sock_fprog,
            ) as libc::c_int
        }
    }

    fn kernel_at_least(major: u32, minor: u32) -> bool {
        // SAFETY: utsname is plain data and uname fills it.
        let release = unsafe {
            let mut u: libc::utsname = std::mem::zeroed();
            if libc::uname(&mut u) != 0 {
                return false;
            }
            std::ffi::CStr::from_ptr(u.release.as_ptr())
                .to_string_lossy()
                .into_owned()
        };
        let mut parts = release
            .split(|c: char| !c.is_ascii_digit())
            .filter(|s| !s.is_empty())
            .map(|s| s.parse::<u32>().unwrap_or(0));
        let (maj, min) = (parts.next().unwrap_or(0), parts.next().unwrap_or(0));
        (maj, min) >= (major, minor)
    }

    fn probe() -> bool {
        if !kernel_at_least(5, 5) {
            return false;
        }
        let prog = filter();
        // SAFETY: the forked child only calls async-signal-safe functions and exits.
        unsafe {
            let pid = libc::fork();
            if pid < 0 {
                return false;
            }
            if pid == 0 {
                let fd = install(&prog);
                libc::_exit(if fd >= 0 { 0 } else { 1 });
            }
            let mut status = 0;
            loop {
                let rc = libc::waitpid(pid, &mut status, 0);
                if rc == pid {
                    break;
                }
                if rc < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                    return false;
                }
            }
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
        }
    }

    /// Whether this host accepts a seccomp user-notification listener (probed once).
    pub fn available() -> bool {
        static CACHE: OnceLock<bool> = OnceLock::new();
        *CACHE.get_or_init(probe)
    }

    /// The parent side of a gate that the forked child has not armed yet.
    pub struct Gate {
        parent: OwnedFd,
        child: OwnedFd,
        prog: Arc<Vec<libc::sock_filter>>,
    }

    /// What the child needs between `fork` and `exec`.
    #[derive(Clone)]
    pub struct ChildSide {
        sock: RawFd,
        prog: Arc<Vec<libc::sock_filter>>,
    }

    impl Gate {
        pub fn new() -> io::Result<Self> {
            let mut fds = [0 as libc::c_int; 2];
            // SAFETY: fds is a valid two-element array.
            let rc = unsafe {
                libc::socketpair(
                    libc::AF_UNIX,
                    libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
                    0,
                    fds.as_mut_ptr(),
                )
            };
            if rc != 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: socketpair returned two descriptors that nothing else owns.
            let (parent, child) =
                unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
            Ok(Self {
                parent,
                child,
                prog: Arc::new(filter()),
            })
        }

        pub fn child_side(&self) -> ChildSide {
            ChildSide {
                sock: self.child.as_raw_fd(),
                prog: self.prog.clone(),
            }
        }

        /// Receives the listener from the exec'd child and starts the supervisor.
        pub fn supervise(self, pgid: libc::pid_t, max_tasks: u64) -> io::Result<Supervisor> {
            let Gate { parent, child, .. } = self;
            // Close our copy of the child's end so a child that never sent reads as EOF.
            drop(child);
            let listener = receive_fd(parent.as_raw_fd())?;
            let stop = Arc::new(AtomicBool::new(false));
            let refusals = Arc::new(AtomicU64::new(0));
            let (stop2, refusals2) = (stop.clone(), refusals.clone());
            let handle = thread::Builder::new()
                .name("agent-sandbox-forkgate".into())
                .spawn(move || supervise(listener, pgid, max_tasks, &stop2, &refusals2))?;
            Ok(Supervisor {
                stop,
                refusals,
                handle: Some(handle),
            })
        }
    }

    impl ChildSide {
        /// Arms the gate and hands the listener to the parent. Runs in the forked child and
        /// only makes async-signal-safe system calls on data prepared in the parent.
        pub fn arm(&self) -> io::Result<()> {
            // SAFETY: see `install`; the descriptors are valid in the child.
            unsafe {
                let listener = install(&self.prog);
                if listener < 0 {
                    return Err(io::Error::last_os_error());
                }
                let rc = send_fd(self.sock, listener);
                let err = io::Error::last_os_error();
                libc::close(listener);
                if rc < 0 {
                    return Err(err);
                }
            }
            Ok(())
        }
    }

    unsafe fn send_fd(sock: RawFd, fd: RawFd) -> isize {
        // SAFETY: every pointer refers to a live stack object of the stated size.
        unsafe {
            let mut byte = [0u8; 1];
            let mut iov = libc::iovec {
                iov_base: byte.as_mut_ptr().cast(),
                iov_len: 1,
            };
            let mut buf = CmsgBuf([0; 64]);
            let mut msg: libc::msghdr = std::mem::zeroed();
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = buf.0.as_mut_ptr().cast();
            msg.msg_controllen = libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) as _;
            let cmsg = libc::CMSG_FIRSTHDR(&msg);
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as _;
            std::ptr::write_unaligned(libc::CMSG_DATA(cmsg).cast::<RawFd>(), fd);
            libc::sendmsg(sock, &msg, libc::MSG_NOSIGNAL)
        }
    }

    fn receive_fd(sock: RawFd) -> io::Result<OwnedFd> {
        // SAFETY: every pointer refers to a live stack object of the stated size.
        unsafe {
            let mut byte = [0u8; 1];
            let mut iov = libc::iovec {
                iov_base: byte.as_mut_ptr().cast(),
                iov_len: 1,
            };
            let mut buf = CmsgBuf([0; 64]);
            let mut msg: libc::msghdr = std::mem::zeroed();
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = buf.0.as_mut_ptr().cast();
            msg.msg_controllen = buf.0.len() as _;
            let n = loop {
                let n = libc::recvmsg(sock, &mut msg, libc::MSG_CMSG_CLOEXEC);
                if n < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                break n;
            };
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            let cmsg = libc::CMSG_FIRSTHDR(&msg);
            if n == 0
                || cmsg.is_null()
                || (*cmsg).cmsg_level != libc::SOL_SOCKET
                || (*cmsg).cmsg_type != libc::SCM_RIGHTS
            {
                return Err(io::Error::other(
                    "the child did not hand over a seccomp listener",
                ));
            }
            let fd = std::ptr::read_unaligned(libc::CMSG_DATA(cmsg).cast::<RawFd>());
            Ok(OwnedFd::from_raw_fd(fd))
        }
    }

    fn supervise(
        listener: OwnedFd,
        pgid: libc::pid_t,
        max_tasks: u64,
        stop: &AtomicBool,
        refusals: &AtomicU64,
    ) {
        let fd = listener.as_raw_fd();
        while !stop.load(Ordering::SeqCst) {
            let mut pfd = libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: pfd is a valid pollfd for the duration of the call.
            let rc = unsafe { libc::poll(&mut pfd, 1, 20) };
            if rc < 0 {
                if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                break;
            }
            if rc == 0 {
                continue;
            }
            if pfd.revents & libc::POLLIN == 0 {
                // POLLHUP: every task that carried the filter is gone.
                break;
            }
            // SAFETY: the kernel requires a zeroed request and fills it in.
            let mut req: SeccompNotif = unsafe { std::mem::zeroed() };
            // SAFETY: req is valid for the size encoded in the request number.
            if unsafe { libc::ioctl(fd, SECCOMP_IOCTL_NOTIF_RECV as _, &mut req) } != 0 {
                match io::Error::last_os_error().raw_os_error() {
                    // The caller died before we read its request.
                    Some(libc::ENOENT) | Some(libc::EINTR) => continue,
                    _ => break,
                }
            }
            let live = crate::limits::group_process_count(pgid);
            let mut resp = SeccompNotifResp {
                id: req.id,
                val: 0,
                error: 0,
                flags: SECCOMP_USER_NOTIF_FLAG_CONTINUE,
            };
            let mut allowed = live < max_tasks;
            if allowed {
                // SAFETY: resp is valid for the size encoded in the request number.
                let rc = unsafe { libc::ioctl(fd, SECCOMP_IOCTL_NOTIF_SEND as _, &resp) };
                if rc != 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL) {
                    // No CONTINUE support: refuse rather than let the call through unchecked.
                    allowed = false;
                }
            }
            if allowed {
                let deadline = Instant::now() + SETTLE;
                while crate::limits::group_process_count(pgid) <= live && Instant::now() < deadline
                {
                    thread::yield_now();
                }
            } else {
                refusals.fetch_add(1, Ordering::SeqCst);
                resp.error = -libc::EAGAIN;
                resp.flags = 0;
                // SAFETY: as above. ENOENT (caller already gone) is fine to ignore.
                unsafe { libc::ioctl(fd, SECCOMP_IOCTL_NOTIF_SEND as _, &resp) };
            }
        }
    }

    /// The running supervisor. Dropping it stops the thread and closes the listener, after
    /// which any task still carrying the filter can no longer create tasks at all.
    pub struct Supervisor {
        stop: Arc<AtomicBool>,
        refusals: Arc<AtomicU64>,
        handle: Option<JoinHandle<()>>,
    }

    impl Supervisor {
        /// How many task-creation calls were refused with `EAGAIN`.
        pub fn refusals(&self) -> u64 {
            self.refusals.load(Ordering::SeqCst)
        }
    }

    impl Drop for Supervisor {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            if let Some(handle) = self.handle.take() {
                let _ = handle.join();
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn filter_routes_task_creation_to_the_listener_and_refuses_group_changes() {
            let f = filter();
            let ret = |i: usize| f[i].k;
            let n = f.len();
            assert_eq!(ret(n - 3), SECCOMP_RET_ALLOW);
            assert_eq!(ret(n - 2), SECCOMP_RET_USER_NOTIF);
            assert_eq!(ret(n - 1), SECCOMP_RET_ERRNO | libc::EPERM as u32);
            // Follow each comparison's taken branch to the action it selects.
            let target = |nr: u32| {
                let i = f
                    .iter()
                    .position(|ins| ins.code == BPF_JEQ_K && ins.k == nr)
                    .unwrap();
                f[i + 1 + f[i].jt as usize].k
            };
            for nr in gated() {
                assert_eq!(target(nr), SECCOMP_RET_USER_NOTIF, "syscall {nr}");
            }
            for nr in refused() {
                assert_eq!(
                    target(nr),
                    SECCOMP_RET_ERRNO | libc::EPERM as u32,
                    "syscall {nr}"
                );
            }
            // A foreign architecture never reaches the allow action.
            assert_eq!(f[1].k, AUDIT_ARCH_NATIVE);
            assert_eq!(f[2].k, SECCOMP_RET_ERRNO | libc::EPERM as u32);
        }

        #[test]
        fn kernel_version_comparison() {
            assert!(kernel_at_least(2, 6));
            assert!(!kernel_at_least(999, 0));
        }
    }
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub use imp::{ChildSide, Gate, Supervisor, available};

/// Whether this host accepts a seccomp user-notification listener.
#[cfg(not(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
pub fn available() -> bool {
    false
}
