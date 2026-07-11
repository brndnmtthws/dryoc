//! # Memory protection utilities
//!
//! Provides access to the memory locking system calls, such as `mlock()` and
//! `mprotect()` on UNIX-like systems, `VirtualLock()` and `VirtualProtect()` on
//! Windows. Similar to libsodium's `sodium_mlock` and `sodium_mprotect_*`
//! functions.
//!
//! On Linux, sets `MADV_DONTDUMP` with `madvise()` on locked regions.
//!
//! The protected memory features are available on Unix and Windows targets with
//! the `protected` feature flag enabled. This feature is enabled by default.
//!
//! ## Bottom line
//!
//! - Use protected memory for long-lived secrets such as private keys,
//!   key-encryption keys, password-hash inputs, and session keys.
//! - Locked memory asks the OS to keep those pages resident in RAM, reducing
//!   the chance that secret bytes are written to swap.
//! - On Linux, locked memory is also marked with `MADV_DONTDUMP`, reducing the
//!   chance that secret bytes appear in ordinary core dumps.
//! - Protected allocations are surrounded by no-access guard pages, which can
//!   turn some out-of-bounds reads or writes into immediate process faults.
//! - Read-only and no-access modes change OS page permissions, so invalid reads
//!   or writes can fault instead of silently exposing or corrupting data.
//! - Explicit zeroization preserves the value's lock and page-protection state.
//! - Dropping a protected value zeroizes its allocation and, if it is locked,
//!   unlocks it exactly once before releasing it.
//! - If cleanup cannot make memory writable, restore its protection, or unlock
//!   it, the process aborts rather than continuing with uncertain secret-memory
//!   state.
//! - It does not make bytes invisible to the current process, privileged OS
//!   tooling, debuggers, other processes with permission to inspect this
//!   process's address space, or copies made before data enters protected
//!   memory.
//! - It is heavier than ordinary allocation: each protected allocation uses
//!   page-aligned storage with guard pages, and protection changes require
//!   fallible system calls.
//! - Platform behavior differs: Linux gets best-effort dump exclusion with
//!   `MADV_DONTDUMP`; macOS and other Unix-like targets use `mlock()` and
//!   `mprotect()` without that dump flag; Windows uses `VirtualLock()` and
//!   `VirtualProtect()`.
//!
//! ## When to use protected memory
//!
//! Protected memory is most useful for secrets that remain in memory after an
//! operation returns. It gives the operating system more information about how
//! those bytes should be handled and makes accidental misuse easier to catch.
//!
//! The tradeoff is cost and complexity: small values can consume multiple pages
//! of virtual memory, protection changes require system calls, and those system
//! calls can fail because of platform limits or permissions. For short-lived
//! buffers that are created, used, and dropped immediately, zeroizing ordinary
//! stack or heap storage may be simpler and faster.
//!
//! ## What protection means in practice
//!
//! These APIs reduce exposure, but they do not make secret bytes invisible to
//! the process that owns them. Code with a valid reference can still read
//! read-write memory, and copies made before a value enters protected memory
//! are outside this module's control. For example,
//! [`NewLockedFromSlice::from_slice_into_locked`] copies the source slice into
//! a protected allocation; callers remain responsible for the lifetime and
//! cleanup policy of the original slice.
//!
//! Protected memory also is not a cross-process isolation mechanism. Another
//! process's ability to inspect these bytes is determined by the operating
//! system's process-memory access controls, such as debugger permissions,
//! sandbox policy, user identity, and privileges.
//!
//! In practice, a protected value is an owned heap allocation whose state is
//! tracked in the type: locked or unlocked, and read-write, read-only, or
//! no-access. Accessor methods are only available for states where that access
//! is valid, and direct memory access that bypasses the type system can still
//! fault if it violates the active OS page protections.
//!
//! ## Platform notes
//!
//! On Linux, locking a region also makes a best-effort `madvise()` call with
//! `MADV_DONTDUMP`, and unlocking reverses that with `MADV_DODUMP`. This keeps
//! the locked pages out of ordinary core dumps when the kernel accepts the
//! advice, but it is not a general crash-reporting or privileged-debugger
//! boundary.
//!
//! On macOS and other Unix-like targets, this module uses `mlock()`,
//! `munlock()`, and `mprotect()`, but it does not set a dump-exclusion flag.
//! Locking is still subject to the process memory-locking limit, which can be
//! low by default. If that limit is exceeded, protected allocation or locking
//! returns an error.
//!
//! On Windows, this module uses `VirtualLock()`, `VirtualUnlock()`, and
//! `VirtualProtect()`. `VirtualLock()` pins pages in the process working set
//! and can fail when the process exceeds the working-set limits enforced by the
//! OS. There is no `MADV_DONTDUMP` equivalent in this module.
//!
//! If the `serde` feature is enabled, the `serde::Deserialize` and
//! `serde::Serialize` traits will be implemented for [`HeapBytes`] and
//! [`HeapByteArray`].
//!
//! ## Example
//!
//! ```
//! use dryoc::protected::*;
//!
//! // Create a read-only, locked region of memory
//! let readonly_locked = HeapBytes::from_slice_into_readonly_locked(b"some locked bytes")
//!     .expect("failed to get locked bytes");
//!
//! // ... now do stuff with `readonly_locked` ...
//! println!("{:?}", readonly_locked.as_slice());
//! ```
//!
//! ## Protection features
//!
//! The type safe API uses traits to guard against misuse of protected memory.
//! For example, memory that is set as read-only can be accessed with immutable
//! accessors (such as `.as_slice()` or `.as_array()`), but not with mutable
//! accessors like `.as_mut_slice()` or `.as_mut_array()`.
//!
//! ```compile_fail
//! use dryoc::protected::*;
//!
//! // Create a read-only, locked region of memory
//! let readonly_locked = HeapBytes::from_slice_into_readonly_locked(b"some locked bytes")
//!     .expect("failed to get locked bytes");
//!
//! // Try to access the memory mutably
//! println!("{:?}", readonly_locked.as_mut_slice()); // fails to compile, cannot access mutably
//! ```
//!
//! Memory that has been protected as read-only or no-access will cause the
//! process to crash if you attempt to access the memory improperly. To test
//! this, try the following code (which requires an `unsafe` block):
//!
//! ```should_panic
//! use dryoc::protected::*;
//!
//! // Create a read-only, locked region of memory
//! let readonly_locked = HeapBytes::from_slice_into_readonly_locked(b"some locked bytes")
//!     .expect("failed to get locked bytes");
//!
//! // Write to a protected region of memory, causing a crash.
//! unsafe {
//!     std::ptr::write(readonly_locked.as_slice().as_ptr() as *mut u8, 0) // <- crash happens here
//! };
//! ```
//!
//! Running the code above produces as `signal: 10, SIGBUS: access to undefined
//! memory` panic.
#[cfg(feature = "nightly")]
use std::alloc::{AllocError, Allocator};
use std::fmt;
use std::marker::PhantomData;
use std::ptr::{self, NonNull};
use std::sync::LazyLock;

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error;
use crate::rng::copy_randombytes;
pub use crate::types::*;

mod int {
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub(super) enum LockMode {
        Locked,
        Unlocked,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub(super) enum ProtectMode {
        ReadOnly,
        ReadWrite,
        NoAccess,
    }

    #[derive(Clone)]
    pub(super) struct InternalData<A> {
        pub(super) a: A,
        pub(super) lm: LockMode,
        pub(super) pm: ProtectMode,
    }
}

#[doc(hidden)] // Edit this PR to remove doc(hidden) or add a doc comment.
pub mod traits {
    pub trait ProtectMode {}
    pub struct ReadOnly {}
    pub struct ReadWrite {}
    pub struct NoAccess {}

    impl ProtectMode for ReadOnly {}
    impl ProtectMode for ReadWrite {}
    impl ProtectMode for NoAccess {}

    pub trait LockMode {}
    pub struct Locked {}
    pub struct Unlocked {}
    impl LockMode for Locked {}
    impl LockMode for Unlocked {}
}

/// A region of memory that can be locked, but is not yet protected. In order to
/// lock the memory, it may require making a copy.
pub trait Lockable<A: Zeroize + Bytes> {
    /// Consumes `self`, creates a new protected region of memory, and returns
    /// the result in a heap-allocated, page-aligned region of memory. The
    /// memory is locked with `mlock()` on UNIX, or `VirtualLock()` on
    /// Windows. By default, the protect mode is set to ReadWrite (i.e., no
    /// exec) using `mprotect()` on UNIX, or `VirtualProtect()` on Windows.
    /// On Linux, it will also set `MADV_DONTDUMP` using `madvise()`.
    ///
    /// # Errors
    ///
    /// Returns [`error::Error::Io`] if the pages cannot be locked. A common
    /// cause is exceeding the process's locked-memory limit.
    fn mlock(self) -> Result<Protected<A, traits::ReadWrite, traits::Locked>, error::Error>;
}

/// Protected region of memory that can be locked.
pub trait Lock<A: Zeroize + Bytes, PM: traits::ProtectMode> {
    /// Locks a region of memory, using `mlock()` on UNIX, or `VirtualLock()` on
    /// Windows. By default, the protect mode is set to ReadWrite (i.e., no
    /// exec) using `mprotect()` on UNIX, or `VirtualProtect()` on Windows.
    /// On Linux, it will also set `MADV_DONTDUMP` using `madvise()`.
    ///
    /// # Errors
    ///
    /// Returns [`error::Error::Io`] if the pages cannot be locked, for example
    /// because the process has reached its locked-memory limit.
    fn mlock(self) -> Result<Protected<A, PM, traits::Locked>, error::Error>;
}

/// Protected region of memory that is already locked and can be unlocked.
pub trait Unlock<A: Zeroize + Bytes, PM: traits::ProtectMode> {
    /// Unlocks a region of memory, using `munlock()` on UNIX, or
    /// `VirtualUnlock()` on Windows.
    ///
    /// # Errors
    ///
    /// Returns [`error::Error::Io`] if the pages cannot be unlocked.
    fn munlock(self) -> Result<Protected<A, PM, traits::Unlocked>, error::Error>;
}

/// Protected region of memory that can be set as read-only.
pub trait ProtectReadOnly<A: Zeroize + Bytes, PM: traits::ProtectMode, LM: traits::LockMode> {
    /// Protects a region of memory as read-only (and no exec), using
    /// `mprotect()` on UNIX, or `VirtualProtect()` on Windows.
    ///
    /// # Errors
    ///
    /// Returns [`error::Error::Io`] if the page permissions cannot be changed.
    fn mprotect_readonly(self) -> Result<Protected<A, traits::ReadOnly, LM>, error::Error>;
}

/// Protected region of memory that can be set as read-write.
pub trait ProtectReadWrite<A: Zeroize + Bytes, PM: traits::ProtectMode, LM: traits::LockMode> {
    /// Protects a region of memory as read-write (and no exec), using
    /// `mprotect()` on UNIX, or `VirtualProtect()` on Windows.
    ///
    /// # Errors
    ///
    /// Returns [`error::Error::Io`] if the page permissions cannot be changed.
    fn mprotect_readwrite(self) -> Result<Protected<A, traits::ReadWrite, LM>, error::Error>;
}

/// Protected region of memory that can be set as no-access. Must be unlocked.
pub trait ProtectNoAccess<A: Zeroize + Bytes, PM: traits::ProtectMode> {
    /// Protects an unlocked region of memory as no-access (and no exec), using
    /// `mprotect()` on UNIX, or `VirtualProtect()` on Windows.
    ///
    /// # Errors
    ///
    /// Returns [`error::Error::Io`] if the page permissions cannot be changed.
    fn mprotect_noaccess(
        self,
    ) -> Result<Protected<A, traits::NoAccess, traits::Unlocked>, error::Error>;
}

/// Bytes which can be allocated and protected.
pub trait NewLocked<A: Zeroize + NewBytes + Lockable<A>> {
    /// Returns a new locked byte array.
    ///
    /// # Errors
    ///
    /// Returns [`error::Error::Io`] if the allocation cannot be locked,
    /// commonly because the process has reached its locked-memory limit.
    fn new_locked() -> Result<Protected<A, traits::ReadWrite, traits::Locked>, error::Error>;
    /// Returns a new locked byte array.
    ///
    /// # Errors
    ///
    /// Returns [`error::Error::Io`] if the allocation cannot be locked or its
    /// page permissions cannot be changed to read-only.
    fn new_readonly_locked() -> Result<Protected<A, traits::ReadOnly, traits::Locked>, error::Error>;
    /// Returns a new locked byte array, filled with random data.
    ///
    /// # Errors
    ///
    /// Returns [`error::Error::Io`] if the allocation cannot be locked.
    fn generate_locked() -> Result<Protected<A, traits::ReadWrite, traits::Locked>, error::Error>;
    /// Returns a new read-only, locked byte array, filled with random data.
    ///
    /// # Errors
    ///
    /// Returns [`error::Error::Io`] if the allocation cannot be locked or its
    /// page permissions cannot be changed to read-only.
    fn generate_readonly_locked()
    -> Result<Protected<A, traits::ReadOnly, traits::Locked>, error::Error>;
    /// Returns a new locked byte array, filled with random data.
    ///
    /// Prefer [`generate_locked`](Self::generate_locked). This method is
    /// retained for compatibility.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`generate_locked`](Self::generate_locked).
    #[deprecated(note = "use generate_locked() instead")]
    fn gen_locked() -> Result<Protected<A, traits::ReadWrite, traits::Locked>, error::Error> {
        Self::generate_locked()
    }
    /// Returns a new read-only, locked byte array, filled with random data.
    ///
    /// Prefer [`generate_readonly_locked`](Self::generate_readonly_locked).
    /// This method is retained for compatibility.
    ///
    /// # Errors
    ///
    /// Returns the same errors as
    /// [`generate_readonly_locked`](Self::generate_readonly_locked).
    #[deprecated(note = "use generate_readonly_locked() instead")]
    fn gen_readonly_locked() -> Result<Protected<A, traits::ReadOnly, traits::Locked>, error::Error>
    {
        Self::generate_readonly_locked()
    }
}

/// Create a new region of protected memory from a slice.
pub trait NewLockedFromSlice<A: Zeroize + NewBytes + Lockable<A>> {
    /// Returns a new locked region of memory from `src`.
    ///
    /// # Errors
    ///
    /// Returns an error if `src` has the wrong length for a fixed-size output
    /// or the pages cannot be locked.
    ///
    /// # Panics
    ///
    /// May panic if allocating or resizing the protected storage fails,
    /// including when the requested size cannot be rounded to whole pages.
    fn from_slice_into_locked(
        src: &[u8],
    ) -> Result<Protected<A, traits::ReadWrite, traits::Locked>, crate::error::Error>;
    /// Returns a new read-only locked region of memory from `src`.
    ///
    /// # Errors
    ///
    /// Returns an error if `src` has the wrong length for a fixed-size output,
    /// its pages cannot be locked, or its page permissions cannot be changed
    /// to read-only.
    ///
    /// # Panics
    ///
    /// May panic if allocating or resizing the protected storage fails,
    /// including when the requested size cannot be rounded to whole pages.
    fn from_slice_into_readonly_locked(
        src: &[u8],
    ) -> Result<Protected<A, traits::ReadOnly, traits::Locked>, crate::error::Error>;
}

/// Holds a protected region of memory. Does not implement `Copy` or
/// [`Debug`](std::fmt::Debug). Accessible states implement [`Clone`] when the
/// backing storage supports it; each clone has a distinct allocation.
pub struct Protected<A: Zeroize + Bytes, PM: traits::ProtectMode, LM: traits::LockMode> {
    i: Option<int::InternalData<A>>,
    p: PhantomData<PM>,
    l: PhantomData<LM>,
}

/// Short-hand type aliases for protected types.
pub mod ptypes {
    /// Locked, read-write, page-aligned memory region type alias
    pub type Locked<T> = super::Protected<T, super::traits::ReadWrite, super::traits::Locked>;
    /// Locked, read-only, page-aligned memory region type alias
    pub type LockedRO<T> = super::Protected<T, super::traits::ReadOnly, super::traits::Locked>;
    /// Unlocked, no-access, page-aligned memory region type alias
    pub type NoAccess<T> = super::Protected<T, super::traits::NoAccess, super::traits::Unlocked>;
    /// Unlocked, read-write, page-aligned memory region type alias
    pub type Unlocked<T> = super::Protected<T, super::traits::ReadWrite, super::traits::Unlocked>;
    /// Unlocked, read-only, page-aligned memory region type alias
    pub type UnlockedRO<T> = super::Protected<T, super::traits::ReadOnly, super::traits::Unlocked>;
    /// Locked, read-write, page-aligned bytes type alias
    pub type LockedBytes = Locked<super::HeapBytes>;
}

impl<T: Zeroize + NewBytes + ResizableBytes + Lockable<T> + NewLocked<T>> Clone for Locked<T> {
    fn clone(&self) -> Self {
        let mut cloned = T::new_locked().expect("unable to create new locked instance");
        cloned.resize(self.len(), 0);
        cloned.as_mut_slice().copy_from_slice(self.as_slice());
        cloned
    }
}

impl<T: Zeroize + NewBytes + ResizableBytes + Lockable<T> + NewLocked<T>> Clone for LockedRO<T> {
    fn clone(&self) -> Self {
        let mut cloned = T::new_locked().expect("unable to create new locked instance");
        cloned.resize(self.len(), 0);
        cloned.as_mut_slice().copy_from_slice(self.as_slice());
        cloned
            .mprotect_readonly()
            .expect("unable to protect readonly")
    }
}

impl<T: Zeroize + Bytes + Clone> Clone for Unlocked<T> {
    fn clone(&self) -> Self {
        Self::new_with(self.i.as_ref().unwrap().a.clone())
    }
}

impl<T: Zeroize + NewBytes + Clone> Clone for UnlockedRO<T> {
    fn clone(&self) -> Self {
        Unlocked::<T>::new_with(self.i.as_ref().unwrap().a.clone())
            .mprotect_readonly()
            .expect("unable to create new readonly instance")
    }
}

pub use ptypes::*;

fn dryoc_mlock(data: &[u8]) -> Result<(), std::io::Error> {
    if data.is_empty() {
        // no-op
        return Ok(());
    }
    #[cfg(unix)]
    {
        #[cfg(target_os = "linux")]
        {
            // tell the kernel not to include this memory in a core dump
            use libc::{MADV_DONTDUMP, madvise};
            // SAFETY: `data` is a valid, non-empty byte slice. `madvise` may
            // accept any address range and reports errors through its return
            // value; this advisory call does not change Rust aliasing rules.
            unsafe {
                madvise(data.as_ptr() as *mut c_void, data.len(), MADV_DONTDUMP);
            }
        }

        use libc::{c_void, mlock as c_mlock};
        // SAFETY: `data` is a valid, non-empty byte slice. The OS only pins the
        // mapped pages for this address range and reports failure via `ret`.
        let ret = unsafe { c_mlock(data.as_ptr() as *const c_void, data.len()) };
        match ret {
            0 => Ok(()),
            _ => Err(std::io::Error::last_os_error()),
        }
    }
    #[cfg(windows)]
    {
        use winapi::shared::minwindef::LPVOID;
        use winapi::um::memoryapi::VirtualLock;

        // SAFETY: `data` is a valid, non-empty byte slice. `VirtualLock` pins
        // the corresponding pages and reports failure through its return value.
        let res = unsafe { VirtualLock(data.as_ptr() as LPVOID, data.len()) };
        if res != 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }
}

fn dryoc_munlock(data: &[u8]) -> Result<(), std::io::Error> {
    if data.is_empty() {
        // no-op
        return Ok(());
    }
    #[cfg(unix)]
    {
        #[cfg(target_os = "linux")]
        {
            // undo MADV_DONTDUMP
            use libc::{MADV_DODUMP, madvise};
            // SAFETY: `data` is a valid, non-empty byte slice. This reverses
            // the advisory dump flag for the same address range.
            unsafe {
                madvise(data.as_ptr() as *mut c_void, data.len(), MADV_DODUMP);
            }
        }

        use libc::{c_void, munlock as c_munlock};
        // SAFETY: `data` is a valid, non-empty byte slice. The OS unpins the
        // mapped pages for this address range and reports failure via `ret`.
        let ret = unsafe { c_munlock(data.as_ptr() as *const c_void, data.len()) };
        match ret {
            0 => Ok(()),
            _ => Err(std::io::Error::last_os_error()),
        }
    }
    #[cfg(windows)]
    {
        use winapi::shared::minwindef::LPVOID;
        use winapi::um::memoryapi::VirtualUnlock;

        // SAFETY: `data` is a valid, non-empty byte slice. `VirtualUnlock`
        // unpins the corresponding pages and reports failure via `res`.
        let res = unsafe { VirtualUnlock(data.as_ptr() as LPVOID, data.len()) };
        if res != 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }
}

fn dryoc_mprotect_readonly(data: &[u8]) -> Result<(), std::io::Error> {
    dryoc_mprotect_ptr(
        data.as_ptr() as *mut u8,
        data.len(),
        PageProtectMode::ReadOnly,
    )
}

fn dryoc_mprotect_readwrite(data: &[u8]) -> Result<(), std::io::Error> {
    dryoc_mprotect_ptr(
        data.as_ptr() as *mut u8,
        data.len(),
        PageProtectMode::ReadWrite,
    )
}

fn dryoc_mprotect_readwrite_ptr(data: *mut u8, len: usize) -> Result<(), std::io::Error> {
    dryoc_mprotect_ptr(data, len, PageProtectMode::ReadWrite)
}

fn dryoc_mprotect_noaccess(data: &[u8]) -> Result<(), std::io::Error> {
    dryoc_mprotect_ptr(
        data.as_ptr() as *mut u8,
        data.len(),
        PageProtectMode::NoAccess,
    )
}

fn dryoc_mprotect_mode(data: &[u8], mode: &int::ProtectMode) -> Result<(), std::io::Error> {
    match mode {
        int::ProtectMode::ReadOnly => dryoc_mprotect_readonly(data),
        int::ProtectMode::ReadWrite => dryoc_mprotect_readwrite(data),
        int::ProtectMode::NoAccess => dryoc_mprotect_noaccess(data),
    }
}

fn dryoc_mprotect_noaccess_ptr(data: *mut u8, len: usize) -> Result<(), std::io::Error> {
    dryoc_mprotect_ptr(data, len, PageProtectMode::NoAccess)
}

#[derive(Clone, Copy)]
enum PageProtectMode {
    ReadOnly,
    ReadWrite,
    NoAccess,
}

fn dryoc_mprotect_ptr(
    data: *mut u8,
    len: usize,
    mode: PageProtectMode,
) -> Result<(), std::io::Error> {
    if len == 0 {
        // no-op
        return Ok(());
    }
    #[cfg(unix)]
    {
        use libc::{PROT_NONE, PROT_READ, PROT_WRITE, c_void, mprotect as c_mprotect};
        let prot = match mode {
            PageProtectMode::ReadOnly => PROT_READ,
            PageProtectMode::ReadWrite => PROT_READ | PROT_WRITE,
            PageProtectMode::NoAccess => PROT_NONE,
        };
        // SAFETY: Callers pass page-aligned ranges from protected allocations.
        // `mprotect` changes page permissions and reports errors via `ret`.
        let ret = unsafe { c_mprotect(data as *mut c_void, len, prot) };
        match ret {
            0 => Ok(()),
            _ => Err(std::io::Error::last_os_error()),
        }
    }
    #[cfg(windows)]
    {
        use winapi::shared::minwindef::{DWORD, LPVOID};
        use winapi::um::memoryapi::VirtualProtect;
        use winapi::um::winnt::{PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE};

        let protect = match mode {
            PageProtectMode::ReadOnly => PAGE_READONLY,
            PageProtectMode::ReadWrite => PAGE_READWRITE,
            PageProtectMode::NoAccess => PAGE_NOACCESS,
        };
        let mut old: DWORD = 0;

        // SAFETY: Callers pass committed ranges from `VirtualAlloc`.
        // `VirtualProtect` changes page permissions and reports errors via
        // `res`.
        let res = unsafe { VirtualProtect(data as LPVOID, len, protect, &mut old) };
        if res != 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }
}

impl<A: Zeroize + Bytes, PM: traits::ProtectMode, LM: traits::LockMode> Protected<A, PM, LM> {
    fn new() -> Self {
        Self {
            i: None,
            p: PhantomData,
            l: PhantomData,
        }
    }

    fn new_with(a: A) -> Self {
        Self {
            i: Some(int::InternalData {
                a,
                lm: int::LockMode::Unlocked,
                pm: int::ProtectMode::ReadWrite,
            }),
            p: PhantomData,
            l: PhantomData,
        }
    }

    fn swap_some_or_err<F, OPM: traits::ProtectMode, OLM: traits::LockMode>(
        &mut self,
        f: F,
    ) -> Result<Protected<A, OPM, OLM>, error::Error>
    where
        F: Fn(&mut int::InternalData<A>) -> Result<Protected<A, OPM, OLM>, error::Error>,
    {
        match &mut self.i {
            Some(d) => {
                let mut new = f(d)?;
                // swap into new struct
                std::mem::swap(&mut new.i, &mut self.i);
                Ok(new)
            }
            _ => Err(error::Error::invalid_state(
                crate::ErrorContext::ProtectedMemory,
            )),
        }
    }
}

impl<A: Zeroize + Bytes, PM: traits::ProtectMode> Unlock<A, PM>
    for Protected<A, PM, traits::Locked>
{
    fn munlock(mut self) -> Result<Protected<A, PM, traits::Unlocked>, error::Error> {
        self.swap_some_or_err(|old| {
            dryoc_munlock(old.a.as_slice())?;
            // update internal state
            old.lm = int::LockMode::Unlocked;
            Ok(Protected::<A, PM, traits::Unlocked>::new())
        })
    }
}

impl<A: Zeroize + Bytes + Default, PM: traits::ProtectMode> Lock<A, PM>
    for Protected<A, PM, traits::Unlocked>
{
    fn mlock(mut self) -> Result<Protected<A, PM, traits::Locked>, error::Error> {
        self.swap_some_or_err(|old| {
            dryoc_mlock(old.a.as_slice())?;
            // update internal state
            old.lm = int::LockMode::Locked;
            Ok(Protected::<A, PM, traits::Locked>::new())
        })
    }
}

impl<A: Zeroize + Bytes, PM: traits::ProtectMode, LM: traits::LockMode> ProtectReadOnly<A, PM, LM>
    for Protected<A, PM, LM>
{
    fn mprotect_readonly(mut self) -> Result<Protected<A, traits::ReadOnly, LM>, error::Error> {
        self.swap_some_or_err(|old| {
            dryoc_mprotect_readonly(old.a.as_slice())?;
            // update internal state
            old.pm = int::ProtectMode::ReadOnly;
            Ok(Protected::<A, traits::ReadOnly, LM>::new())
        })
    }
}

impl<A: Zeroize + Bytes, PM: traits::ProtectMode, LM: traits::LockMode> ProtectReadWrite<A, PM, LM>
    for Protected<A, PM, LM>
{
    fn mprotect_readwrite(mut self) -> Result<Protected<A, traits::ReadWrite, LM>, error::Error> {
        self.swap_some_or_err(|old| {
            dryoc_mprotect_readwrite(old.a.as_slice())?;
            // update internal state
            old.pm = int::ProtectMode::ReadWrite;
            Ok(Protected::<A, traits::ReadWrite, LM>::new())
        })
    }
}

impl<A: Zeroize + Bytes, PM: traits::ProtectMode> ProtectNoAccess<A, PM>
    for Protected<A, PM, traits::Unlocked>
{
    fn mprotect_noaccess(
        mut self,
    ) -> Result<Protected<A, traits::NoAccess, traits::Unlocked>, error::Error> {
        self.swap_some_or_err(|old| {
            dryoc_mprotect_noaccess(old.a.as_slice())?;
            // update internal state
            old.pm = int::ProtectMode::NoAccess;
            Ok(Protected::<A, traits::NoAccess, traits::Unlocked>::new())
        })
    }
}

impl<A: Zeroize + Bytes + AsRef<[u8]>, LM: traits::LockMode> AsRef<[u8]>
    for Protected<A, traits::ReadOnly, LM>
{
    fn as_ref(&self) -> &[u8] {
        self.i.as_ref().unwrap().a.as_ref()
    }
}

impl<A: Zeroize + Bytes + AsRef<[u8]>, LM: traits::LockMode> AsRef<[u8]>
    for Protected<A, traits::ReadWrite, LM>
{
    fn as_ref(&self) -> &[u8] {
        self.i.as_ref().unwrap().a.as_ref()
    }
}

impl<A: Zeroize + MutBytes + AsMut<[u8]>, LM: traits::LockMode> AsMut<[u8]>
    for Protected<A, traits::ReadWrite, LM>
{
    fn as_mut(&mut self) -> &mut [u8] {
        self.i.as_mut().unwrap().a.as_mut()
    }
}

impl<A: Zeroize + Bytes, LM: traits::LockMode> Bytes for Protected<A, traits::ReadOnly, LM> {
    #[inline]
    fn as_slice(&self) -> &[u8] {
        self.i.as_ref().unwrap().a.as_slice()
    }

    #[inline]
    fn len(&self) -> usize {
        self.i.as_ref().unwrap().a.len()
    }

    #[inline]
    fn is_empty(&self) -> bool {
        self.i.as_ref().unwrap().a.is_empty()
    }
}

impl<A: Zeroize + Bytes, LM: traits::LockMode> Bytes for Protected<A, traits::ReadWrite, LM> {
    #[inline]
    fn as_slice(&self) -> &[u8] {
        self.i.as_ref().unwrap().a.as_slice()
    }

    #[inline]
    fn len(&self) -> usize {
        self.i.as_ref().unwrap().a.len()
    }

    #[inline]
    fn is_empty(&self) -> bool {
        self.i.as_ref().unwrap().a.is_empty()
    }
}

impl<const LENGTH: usize> From<StackByteArray<LENGTH>> for HeapByteArray<LENGTH> {
    fn from(other: StackByteArray<LENGTH>) -> Self {
        let mut r = HeapByteArray::<LENGTH>::new_byte_array();
        let mut s = other;
        r.copy_from_slice(s.as_slice());
        s.zeroize();
        r
    }
}

impl<const LENGTH: usize> StackByteArray<LENGTH> {
    /// Locks a [StackByteArray], consuming it, and returning a [Protected]
    /// wrapper.
    ///
    /// # Errors
    ///
    /// Returns [`error::Error::Io`] if the pages cannot be locked.
    ///
    /// # Panics
    ///
    /// Panics if the page-aligned allocation cannot be created or its size
    /// cannot be represented after page rounding and adding guard pages.
    pub fn mlock(
        self,
    ) -> Result<Protected<HeapByteArray<LENGTH>, traits::ReadWrite, traits::Locked>, error::Error>
    {
        Protected::<HeapByteArray<LENGTH>, traits::ReadWrite, traits::Unlocked>::new_with(
            self.into(),
        )
        .mlock()
    }
}

impl<const LENGTH: usize> StackByteArray<LENGTH> {
    /// Returns a readonly protected [StackByteArray].
    ///
    /// # Errors
    ///
    /// Returns [`error::Error::Io`] if the page permissions cannot be changed
    /// to read-only.
    ///
    /// # Panics
    ///
    /// Panics if the page-aligned allocation cannot be created or its size
    /// cannot be represented after page rounding and adding guard pages.
    pub fn mprotect_readonly(
        self,
    ) -> Result<Protected<HeapByteArray<LENGTH>, traits::ReadOnly, traits::Unlocked>, error::Error>
    {
        Protected::<HeapByteArray<LENGTH>, traits::ReadWrite, traits::Unlocked>::new_with(
            self.into(),
        )
        .mprotect_readonly()
    }
}

impl<const LENGTH: usize> Lockable<HeapByteArray<LENGTH>> for HeapByteArray<LENGTH> {
    /// Locks a [HeapByteArray], and returns a [Protected] wrapper.
    fn mlock(
        self,
    ) -> Result<Protected<HeapByteArray<LENGTH>, traits::ReadWrite, traits::Locked>, error::Error>
    {
        Protected::<HeapByteArray<LENGTH>, traits::ReadWrite, traits::Unlocked>::new_with(self)
            .mlock()
    }
}

impl Lockable<HeapBytes> for HeapBytes {
    /// Locks a [HeapBytes], and returns a [Protected] wrapper.
    fn mlock(
        self,
    ) -> Result<Protected<HeapBytes, traits::ReadWrite, traits::Locked>, error::Error> {
        Protected::<HeapBytes, traits::ReadWrite, traits::Unlocked>::new_with(self).mlock()
    }
}

#[derive(Clone)]
/// Custom page-aligned allocator implementation. Creates blocks of page-aligned
/// heap-allocated memory regions, with no-access pages before and after the
/// allocated region of memory. Allocations whose requested alignment does not
/// divide the host page size are rejected.
pub struct PageAlignedAllocator;

#[cfg(unix)]
const DEFAULT_PAGESIZE: usize = 4096;

#[cfg(unix)]
fn page_size_from_sysconf(page_size: libc::c_long) -> usize {
    if page_size > 0 {
        page_size as usize
    } else {
        DEFAULT_PAGESIZE
    }
}

static PAGESIZE: LazyLock<usize> = LazyLock::new(|| {
    #[cfg(unix)]
    {
        use libc::{_SC_PAGE_SIZE, sysconf};
        // SAFETY: `sysconf(_SC_PAGE_SIZE)` has no pointer arguments and returns
        // the host page size or an error sentinel.
        let page_size = unsafe { sysconf(_SC_PAGE_SIZE) };
        page_size_from_sysconf(page_size)
    }
    #[cfg(windows)]
    {
        use winapi::um::sysinfoapi::{GetSystemInfo, SYSTEM_INFO};
        let mut si = SYSTEM_INFO::default();
        // SAFETY: `si` is a valid writable `SYSTEM_INFO` out-parameter for the
        // duration of the call.
        unsafe { GetSystemInfo(&mut si) };
        si.dwPageSize as usize
    }
});

fn _page_round(size: usize, pagesize: usize) -> Option<usize> {
    let rem = size % pagesize;
    if rem == 0 {
        Some(size)
    } else {
        size.checked_add(pagesize - rem)
    }
}

fn protected_alloc_error() -> std::io::Error {
    std::io::Error::other("protected memory allocation failed")
}

#[derive(Clone, Copy)]
struct RawRegionLayout {
    rounded_size: usize,
    total_size: usize,
}

fn checked_raw_region_layout(
    user_size: usize,
    pagesize: usize,
) -> Result<RawRegionLayout, std::io::Error> {
    let rounded_size = _page_round(user_size, pagesize).ok_or_else(protected_alloc_error)?;
    let guard_size = pagesize.checked_mul(2).ok_or_else(protected_alloc_error)?;
    let total_size = rounded_size
        .checked_add(guard_size)
        .ok_or_else(protected_alloc_error)?;
    Ok(RawRegionLayout {
        rounded_size,
        total_size,
    })
}

#[derive(Clone, Copy)]
struct RawProtectedAllocation {
    base: NonNull<u8>,
    data: NonNull<u8>,
    rounded_size: usize,
    total_size: usize,
}

fn platform_alloc(total_size: usize, pagesize: usize) -> Result<NonNull<u8>, std::io::Error> {
    #[cfg(unix)]
    {
        use libc::posix_memalign;
        let mut out = ptr::null_mut();

        // SAFETY: `out` is a valid out-parameter. `pagesize` is the host page
        // size and therefore a power-of-two alignment; `total_size` was checked
        // by `checked_raw_region_layout`.
        let ret = unsafe { posix_memalign(&mut out, pagesize, total_size) };
        if ret != 0 {
            return Err(std::io::Error::from_raw_os_error(ret));
        }

        NonNull::new(out as *mut u8).ok_or_else(protected_alloc_error)
    }
    #[cfg(windows)]
    {
        let _ = pagesize;
        use winapi::um::memoryapi::VirtualAlloc;
        use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE};

        // SAFETY: `total_size` was checked by `checked_raw_region_layout`. Null
        // address lets the OS choose the base, and failure is handled by
        // checking for null.
        let out = unsafe {
            VirtualAlloc(
                ptr::null_mut(),
                total_size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        };

        NonNull::new(out as *mut u8).ok_or_else(std::io::Error::last_os_error)
    }
}

fn platform_free(base: NonNull<u8>, total_size: usize) {
    #[cfg(unix)]
    {
        let _ = total_size;
        // SAFETY: `base` is the original allocation base returned by
        // `posix_memalign`.
        unsafe { libc::free(base.as_ptr() as *mut libc::c_void) };
    }
    #[cfg(windows)]
    {
        let _ = total_size;
        use winapi::shared::minwindef::LPVOID;
        use winapi::um::memoryapi::VirtualFree;
        use winapi::um::winnt::MEM_RELEASE;
        // SAFETY: `base` is the original allocation base returned by
        // `VirtualAlloc`; size 0 with `MEM_RELEASE` releases the whole region.
        unsafe { VirtualFree(base.as_ptr() as LPVOID, 0, MEM_RELEASE) };
    }
}

fn allocate_raw_region(user_size: usize) -> Result<RawProtectedAllocation, std::io::Error> {
    let pagesize = *PAGESIZE;
    let layout = checked_raw_region_layout(user_size, pagesize)?;
    let base = platform_alloc(layout.total_size, pagesize)?;
    let base_ptr = base.as_ptr();

    if let Err(err) = dryoc_mprotect_noaccess_ptr(base_ptr, pagesize) {
        platform_free(base, layout.total_size);
        return Err(err);
    }

    let aft_guard_offset = pagesize
        .checked_add(layout.rounded_size)
        .ok_or_else(protected_alloc_error)?;
    // SAFETY: `aft_guard_offset` was bounds-checked as part of the raw region
    // layout and leaves one full guard page in the allocation.
    let aft_guard = unsafe { base_ptr.add(aft_guard_offset) };
    if let Err(err) = dryoc_mprotect_noaccess_ptr(aft_guard, pagesize) {
        let _ = dryoc_mprotect_readwrite_ptr(base_ptr, pagesize);
        platform_free(base, layout.total_size);
        return Err(err);
    }

    // SAFETY: `base` points to the full raw allocation and `pagesize` skips the
    // front guard page to the start of the user region.
    let data_ptr = unsafe { base_ptr.add(pagesize) };
    let data = NonNull::new(data_ptr).ok_or_else(protected_alloc_error)?;

    Ok(RawProtectedAllocation {
        base,
        data,
        rounded_size: layout.rounded_size,
        total_size: layout.total_size,
    })
}

fn deallocate_raw_region(raw: RawProtectedAllocation) {
    let pagesize = *PAGESIZE;
    let base_ptr = raw.base.as_ptr();
    let _ = dryoc_mprotect_readwrite_ptr(base_ptr, pagesize);

    if let Some(aft_guard_offset) = pagesize.checked_add(raw.rounded_size) {
        // SAFETY: `aft_guard_offset` mirrors `allocate_raw_region` and points
        // at the aft guard page inside this allocation.
        let aft_guard = unsafe { base_ptr.add(aft_guard_offset) };
        let _ = dryoc_mprotect_readwrite_ptr(aft_guard, pagesize);
    }

    platform_free(raw.base, raw.total_size);
}

struct ProtectedBuffer {
    base: Option<NonNull<u8>>,
    data: NonNull<u8>,
    len: usize,
    capacity: usize,
    rounded_size: usize,
    total_size: usize,
}

// SAFETY: `ProtectedBuffer` uniquely owns its allocation. Moving it to another
// thread does not invalidate the allocation, and access to mutable bytes still
// requires `&mut self`.
unsafe impl Send for ProtectedBuffer {}

// SAFETY: Shared references expose only immutable byte slices and metadata; the
// type has no interior mutability.
unsafe impl Sync for ProtectedBuffer {}

impl ProtectedBuffer {
    fn new_filled(len: usize, value: u8) -> Result<Self, std::io::Error> {
        if len == 0 {
            return Ok(Self::default());
        }

        let raw = allocate_raw_region(len)?;
        let mut buffer = Self {
            base: Some(raw.base),
            data: raw.data,
            len,
            capacity: len,
            rounded_size: raw.rounded_size,
            total_size: raw.total_size,
        };
        buffer.as_mut_slice().fill(value);
        Ok(buffer)
    }

    fn from_slice(src: &[u8]) -> Result<Self, std::io::Error> {
        let mut buffer = Self::new_filled(src.len(), 0)?;
        buffer.as_mut_slice().copy_from_slice(src);
        Ok(buffer)
    }

    fn as_ptr(&self) -> *const u8 {
        self.data.as_ptr()
    }

    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.data.as_ptr()
    }

    fn as_slice(&self) -> &[u8] {
        debug_assert!(self.len <= self.capacity);
        // SAFETY: `data` is either a valid allocation for `len` initialized
        // bytes or a dangling non-null pointer with `len == 0`.
        unsafe { std::slice::from_raw_parts(self.data.as_ptr(), self.len) }
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        debug_assert!(self.len <= self.capacity);
        // SAFETY: `data` is either a valid uniquely owned allocation for `len`
        // initialized bytes or a dangling non-null pointer with `len == 0`.
        unsafe { std::slice::from_raw_parts_mut(self.data.as_ptr(), self.len) }
    }

    fn len(&self) -> usize {
        self.len
    }

    fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn resize(&mut self, new_len: usize, value: u8) {
        if new_len == self.len {
            return;
        }

        let mut resized = Self::new_filled(new_len, value).expect("protected resize failed");
        let len_to_copy = std::cmp::min(self.len, new_len);
        resized.as_mut_slice()[..len_to_copy].copy_from_slice(&self.as_slice()[..len_to_copy]);
        std::mem::swap(self, &mut resized);
    }

    fn copy_from_slice(&mut self, other: &[u8]) {
        self.as_mut_slice().copy_from_slice(other);
    }
}

impl Default for ProtectedBuffer {
    fn default() -> Self {
        Self {
            base: None,
            data: NonNull::dangling(),
            len: 0,
            capacity: 0,
            rounded_size: 0,
            total_size: 0,
        }
    }
}

impl Clone for ProtectedBuffer {
    fn clone(&self) -> Self {
        Self::from_slice(self.as_slice()).expect("protected clone failed")
    }
}

impl fmt::Debug for ProtectedBuffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProtectedBuffer")
            .field("len", &self.len())
            .field("contents", &"[REDACTED]")
            .finish()
    }
}

impl PartialEq for ProtectedBuffer {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice().ct_eq(other.as_slice()).into()
    }
}

impl Eq for ProtectedBuffer {}

impl Zeroize for ProtectedBuffer {
    fn zeroize(&mut self) {
        self.as_mut_slice().zeroize();
    }
}

impl Drop for ProtectedBuffer {
    fn drop(&mut self) {
        if let Some(base) = self.base.take() {
            if self.rounded_size != 0 {
                let _ = dryoc_mprotect_readwrite_ptr(self.data.as_ptr(), self.rounded_size);
            }
            self.as_mut_slice().zeroize();
            deallocate_raw_region(RawProtectedAllocation {
                base,
                data: self.data,
                rounded_size: self.rounded_size,
                total_size: self.total_size,
            });
        }
    }
}

impl AsRef<[u8]> for ProtectedBuffer {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl AsMut<[u8]> for ProtectedBuffer {
    fn as_mut(&mut self) -> &mut [u8] {
        self.as_mut_slice()
    }
}

impl std::ops::Deref for ProtectedBuffer {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl std::ops::DerefMut for ProtectedBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_mut_slice()
    }
}

impl std::ops::Index<usize> for ProtectedBuffer {
    type Output = u8;

    #[inline]
    fn index(&self, index: usize) -> &Self::Output {
        &self.as_slice()[index]
    }
}

impl std::ops::IndexMut<usize> for ProtectedBuffer {
    #[inline]
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.as_mut_slice()[index]
    }
}

macro_rules! impl_index_protected_buffer {
    ($range:ty) => {
        impl std::ops::Index<$range> for ProtectedBuffer {
            type Output = [u8];

            #[inline]
            fn index(&self, index: $range) -> &Self::Output {
                &self.as_slice()[index]
            }
        }
        impl std::ops::IndexMut<$range> for ProtectedBuffer {
            #[inline]
            fn index_mut(&mut self, index: $range) -> &mut Self::Output {
                &mut self.as_mut_slice()[index]
            }
        }
    };
}

impl_index_protected_buffer!(std::ops::Range<usize>);
impl_index_protected_buffer!(std::ops::RangeFull);
impl_index_protected_buffer!(std::ops::RangeFrom<usize>);
impl_index_protected_buffer!(std::ops::RangeInclusive<usize>);
impl_index_protected_buffer!(std::ops::RangeTo<usize>);
impl_index_protected_buffer!(std::ops::RangeToInclusive<usize>);

#[cfg(feature = "nightly")]
// SAFETY: `allocate` returns the user slice inside an owned allocation preceded
// by one guard page. `deallocate` subtracts that same guard-page offset,
// restores guard-page permissions, and releases the original allocation with
// the matching platform allocator.
unsafe impl Allocator for PageAlignedAllocator {
    #[inline]
    fn allocate(&self, layout: std::alloc::Layout) -> Result<NonNull<[u8]>, AllocError> {
        let pagesize = *PAGESIZE;
        if !pagesize.is_multiple_of(layout.align()) {
            return Err(AllocError);
        }

        let raw = allocate_raw_region(layout.size()).map_err(|_| AllocError)?;
        // SAFETY: `raw.data` points to the unique user-visible allocation
        // region returned by `allocate_raw_region`.
        unsafe {
            Ok(NonNull::new_unchecked(ptr::slice_from_raw_parts_mut(
                raw.data.as_ptr(),
                layout.size(),
            )))
        }
    }

    /// # Safety
    ///
    /// `ptr` must be a user-region pointer previously returned by this
    /// allocator's `allocate` method with the same `layout`.
    #[inline]
    // SAFETY: The caller contract above is the `Allocator::deallocate` safety
    // contract for this implementation.
    unsafe fn deallocate(&self, ptr: NonNull<u8>, layout: std::alloc::Layout) {
        let pagesize = *PAGESIZE;

        // SAFETY: `ptr` points to the user region returned by `allocate`, which
        // starts exactly one guard page after the original allocation base.
        let base_ptr = unsafe { ptr.as_ptr().sub(pagesize) };
        let Some(base) = NonNull::new(base_ptr) else {
            return;
        };
        let Ok(raw_layout) = checked_raw_region_layout(layout.size(), pagesize) else {
            return;
        };
        deallocate_raw_region(RawProtectedAllocation {
            base,
            data: ptr,
            rounded_size: raw_layout.rounded_size,
            total_size: raw_layout.total_size,
        });
    }
}

/// Provides a heap-allocated, fixed-length, page-aligned memory region.
///
/// This struct provides a heap-allocated fixed-length byte array. Required for
/// working with protected memory regions.
#[derive(Zeroize, ZeroizeOnDrop, Debug, PartialEq, Eq, Clone)]
pub struct HeapByteArray<const LENGTH: usize>(ProtectedBuffer);

/// Provides a heap-allocated, resizable memory region.
///
/// This struct provides heap-allocated resizable byte array. Required for
/// working with protected memory regions.
#[derive(Zeroize, ZeroizeOnDrop, Debug, PartialEq, Eq, Clone, Default)]
pub struct HeapBytes(ProtectedBuffer);

impl<A: Zeroize + NewBytes + Lockable<A>> NewLocked<A> for A {
    fn new_locked() -> Result<Protected<Self, traits::ReadWrite, traits::Locked>, error::Error> {
        Self::new_bytes().mlock()
    }

    fn new_readonly_locked()
    -> Result<Protected<Self, traits::ReadOnly, traits::Locked>, error::Error> {
        Self::new_bytes()
            .mlock()
            .and_then(|p| p.mprotect_readonly())
    }

    fn generate_locked() -> Result<Protected<Self, traits::ReadWrite, traits::Locked>, error::Error>
    {
        let mut res = Self::new_bytes().mlock()?;
        copy_randombytes(res.as_mut_slice());
        Ok(res)
    }

    fn generate_readonly_locked()
    -> Result<Protected<Self, traits::ReadOnly, traits::Locked>, error::Error> {
        Self::generate_locked().and_then(|s| s.mprotect_readonly())
    }
}

impl<A: Zeroize + NewBytes + ResizableBytes + Lockable<A>> NewLockedFromSlice<A> for A {
    /// Copies `src` into a new locked byte buffer.
    fn from_slice_into_locked(
        src: &[u8],
    ) -> Result<Protected<Self, traits::ReadWrite, traits::Locked>, crate::error::Error> {
        let mut res = Self::new_bytes().mlock()?;
        res.resize(src.len(), 0);
        res.as_mut_slice().copy_from_slice(src);
        Ok(res)
    }

    /// Copies `src` into a new read-only, locked byte buffer.
    fn from_slice_into_readonly_locked(
        src: &[u8],
    ) -> Result<Protected<Self, traits::ReadOnly, traits::Locked>, crate::error::Error> {
        Self::from_slice_into_locked(src).and_then(|s| s.mprotect_readonly())
    }
}

impl<const LENGTH: usize> NewLockedFromSlice<HeapByteArray<LENGTH>> for HeapByteArray<LENGTH> {
    /// Copies `other` into a new fixed-size locked byte array.
    fn from_slice_into_locked(
        other: &[u8],
    ) -> Result<Protected<Self, traits::ReadWrite, traits::Locked>, crate::error::Error> {
        if other.len() != LENGTH {
            return Err(length_error!(crate::ErrorContext::Slice, other.len(), exact LENGTH));
        }
        let mut res = Self::new_bytes().mlock()?;
        res.as_mut_slice().copy_from_slice(other);
        Ok(res)
    }

    fn from_slice_into_readonly_locked(
        other: &[u8],
    ) -> Result<Protected<Self, traits::ReadOnly, traits::Locked>, crate::error::Error> {
        Self::from_slice_into_locked(other).and_then(|s| s.mprotect_readonly())
    }
}

impl<const LENGTH: usize> Bytes for HeapByteArray<LENGTH> {
    #[inline]
    fn as_slice(&self) -> &[u8] {
        &self.0
    }

    #[inline]
    fn len(&self) -> usize {
        self.0.len()
    }

    #[inline]
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Bytes for HeapBytes {
    #[inline]
    fn as_slice(&self) -> &[u8] {
        &self.0
    }

    #[inline]
    fn len(&self) -> usize {
        self.0.len()
    }

    #[inline]
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<const LENGTH: usize> MutBytes for HeapByteArray<LENGTH> {
    #[inline]
    fn as_mut_slice(&mut self) -> &mut [u8] {
        self.0.as_mut_slice()
    }

    fn copy_from_slice(&mut self, other: &[u8]) {
        self.0.copy_from_slice(other)
    }
}

impl NewBytes for HeapBytes {
    fn new_bytes() -> Self {
        Self::default()
    }
}

impl MutBytes for HeapBytes {
    #[inline]
    fn as_mut_slice(&mut self) -> &mut [u8] {
        self.0.as_mut_slice()
    }

    fn copy_from_slice(&mut self, other: &[u8]) {
        self.0.copy_from_slice(other)
    }
}

impl ResizableBytes for HeapBytes {
    fn resize(&mut self, new_len: usize, value: u8) {
        self.0.resize(new_len, value);
    }
}

impl<A: Zeroize + NewBytes + ResizableBytes + Lockable<A>> ResizableBytes
    for Protected<A, traits::ReadWrite, traits::Locked>
{
    fn resize(&mut self, new_len: usize, value: u8) {
        match &mut self.i {
            Some(d) => {
                // because it's locked, we'll do a swaparoo here instead of a plain resize
                let mut new = A::new_bytes();
                // resize the new array
                new.resize(new_len, value);
                // need to actually lock the memory now, because it was previously locked
                let mut locked = new.mlock().expect("unable to lock on resize");
                let len_to_copy = std::cmp::min(new_len, d.a.as_slice().len());
                locked.i.as_mut().unwrap().a.as_mut_slice()[..len_to_copy]
                    .copy_from_slice(&d.a.as_slice()[..len_to_copy]);
                std::mem::swap(&mut locked.i, &mut self.i);
                // when dropped, the old region will unlock automatically in
                // Drop
            }
            None => panic!("invalid array"),
        }
    }
}

impl<A: Zeroize + NewBytes + ResizableBytes + Lockable<A>> ResizableBytes
    for Protected<A, traits::ReadWrite, traits::Unlocked>
{
    fn resize(&mut self, new_len: usize, value: u8) {
        match &mut self.i {
            Some(d) => d.a.resize(new_len, value),
            None => panic!("invalid array"),
        }
    }
}

impl<A: Zeroize + MutBytes, LM: traits::LockMode> MutBytes for Protected<A, traits::ReadWrite, LM> {
    #[inline]
    fn as_mut_slice(&mut self) -> &mut [u8] {
        match &mut self.i {
            Some(d) => d.a.as_mut_slice(),
            None => panic!("invalid array"),
        }
    }

    fn copy_from_slice(&mut self, other: &[u8]) {
        match &mut self.i {
            Some(d) => d.a.copy_from_slice(other),
            None => panic!("invalid array"),
        }
    }
}

impl<const LENGTH: usize> std::convert::AsRef<[u8; LENGTH]> for HeapByteArray<LENGTH> {
    fn as_ref(&self) -> &[u8; LENGTH] {
        let arr = self.0.as_ptr() as *const [u8; LENGTH];
        // SAFETY: `HeapByteArray<LENGTH>` always allocates exactly `LENGTH`
        // initialized bytes, and `[u8; LENGTH]` has alignment 1.
        unsafe { &*arr }
    }
}

impl<const LENGTH: usize> std::convert::AsMut<[u8; LENGTH]> for HeapByteArray<LENGTH> {
    fn as_mut(&mut self) -> &mut [u8; LENGTH] {
        let arr = self.0.as_mut_ptr() as *mut [u8; LENGTH];
        // SAFETY: `HeapByteArray<LENGTH>` always allocates exactly `LENGTH`
        // initialized bytes. `&mut self` provides exclusive access to them.
        unsafe { &mut *arr }
    }
}

impl<const LENGTH: usize> std::convert::AsRef<[u8]> for HeapByteArray<LENGTH> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl std::convert::AsRef<[u8]> for HeapBytes {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<const LENGTH: usize> std::convert::AsMut<[u8]> for HeapByteArray<LENGTH> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

impl std::convert::AsMut<[u8]> for HeapBytes {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

impl<const LENGTH: usize> std::ops::Deref for HeapByteArray<LENGTH> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const LENGTH: usize> std::ops::DerefMut for HeapByteArray<LENGTH> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl std::ops::Deref for HeapBytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for HeapBytes {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<A: Bytes + Zeroize, LM: traits::LockMode> std::ops::Deref
    for Protected<A, traits::ReadOnly, LM>
{
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.i.as_ref().unwrap().a.as_slice()
    }
}

impl<A: Bytes + Zeroize, LM: traits::LockMode> std::ops::Deref
    for Protected<A, traits::ReadWrite, LM>
{
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.i.as_ref().unwrap().a.as_slice()
    }
}

impl<A: MutBytes + Zeroize, LM: traits::LockMode> std::ops::DerefMut
    for Protected<A, traits::ReadWrite, LM>
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.i.as_mut().unwrap().a.as_mut_slice()
    }
}

impl<const LENGTH: usize> std::ops::Index<usize> for HeapByteArray<LENGTH> {
    type Output = u8;

    #[inline]
    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}
impl<const LENGTH: usize> std::ops::IndexMut<usize> for HeapByteArray<LENGTH> {
    #[inline]
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index]
    }
}

macro_rules! impl_index_heapbytearray {
    ($range:ty) => {
        impl<const LENGTH: usize> std::ops::Index<$range> for HeapByteArray<LENGTH> {
            type Output = [u8];

            #[inline]
            fn index(&self, index: $range) -> &Self::Output {
                &self.0[index]
            }
        }
        impl<const LENGTH: usize> std::ops::IndexMut<$range> for HeapByteArray<LENGTH> {
            #[inline]
            fn index_mut(&mut self, index: $range) -> &mut Self::Output {
                &mut self.0[index]
            }
        }
    };
}

impl_index_heapbytearray!(std::ops::Range<usize>);
impl_index_heapbytearray!(std::ops::RangeFull);
impl_index_heapbytearray!(std::ops::RangeFrom<usize>);
impl_index_heapbytearray!(std::ops::RangeInclusive<usize>);
impl_index_heapbytearray!(std::ops::RangeTo<usize>);
impl_index_heapbytearray!(std::ops::RangeToInclusive<usize>);

impl<const LENGTH: usize> Default for HeapByteArray<LENGTH> {
    fn default() -> Self {
        Self(ProtectedBuffer::new_filled(LENGTH, 0).expect("protected allocation failed"))
    }
}

impl<A: Zeroize + NewBytes + Lockable<A> + NewLocked<A>> Default
    for Protected<A, traits::ReadWrite, traits::Locked>
{
    fn default() -> Self {
        A::new_locked().expect("mlock failed")
    }
}

impl std::ops::Index<usize> for HeapBytes {
    type Output = u8;

    #[inline]
    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}
impl std::ops::IndexMut<usize> for HeapBytes {
    #[inline]
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index]
    }
}

macro_rules! impl_index_heapbytes {
    ($range:ty) => {
        impl std::ops::Index<$range> for HeapBytes {
            type Output = [u8];

            #[inline]
            fn index(&self, index: $range) -> &Self::Output {
                &self.0[index]
            }
        }
        impl std::ops::IndexMut<$range> for HeapBytes {
            #[inline]
            fn index_mut(&mut self, index: $range) -> &mut Self::Output {
                &mut self.0[index]
            }
        }
    };
}

impl_index_heapbytes!(std::ops::Range<usize>);
impl_index_heapbytes!(std::ops::RangeFull);
impl_index_heapbytes!(std::ops::RangeFrom<usize>);
impl_index_heapbytes!(std::ops::RangeInclusive<usize>);
impl_index_heapbytes!(std::ops::RangeTo<usize>);
impl_index_heapbytes!(std::ops::RangeToInclusive<usize>);

impl<const LENGTH: usize> From<&[u8; LENGTH]> for HeapByteArray<LENGTH> {
    fn from(src: &[u8; LENGTH]) -> Self {
        let mut arr = Self::default();
        arr.0.copy_from_slice(src);
        arr
    }
}

impl<const LENGTH: usize> From<[u8; LENGTH]> for HeapByteArray<LENGTH> {
    fn from(mut src: [u8; LENGTH]) -> Self {
        let ret = Self::from(&src);
        // need to zeroize this input
        src.zeroize();
        ret
    }
}

impl<const LENGTH: usize> TryFrom<&[u8]> for HeapByteArray<LENGTH> {
    type Error = error::Error;

    fn try_from(src: &[u8]) -> Result<Self, Self::Error> {
        if src.len() != LENGTH {
            Err(length_error!(crate::ErrorContext::Slice, src.len(), exact LENGTH))
        } else {
            let mut arr = Self::default();
            arr.0.copy_from_slice(src);
            Ok(arr)
        }
    }
}

impl From<&[u8]> for HeapBytes {
    fn from(src: &[u8]) -> Self {
        Self(ProtectedBuffer::from_slice(src).expect("protected allocation failed"))
    }
}

impl<const LENGTH: usize> ByteArray<LENGTH> for HeapByteArray<LENGTH> {
    #[inline]
    fn as_array(&self) -> &[u8; LENGTH] {
        let ptr = self.0.as_ptr() as *const [u8; LENGTH];
        // SAFETY: `HeapByteArray<LENGTH>` always allocates exactly `LENGTH`
        // initialized bytes, and `[u8; LENGTH]` has alignment 1.
        unsafe { &*ptr }
    }
}

impl<const LENGTH: usize> NewBytes for HeapByteArray<LENGTH> {
    fn new_bytes() -> Self {
        Self::default()
    }
}

impl NewBytes for Protected<HeapBytes, traits::ReadWrite, traits::Locked> {
    fn new_bytes() -> Self {
        match HeapBytes::new_locked() {
            Ok(r) => r,
            Err(err) => panic!("Error creating locked bytes: {:?}", err),
        }
    }
}

impl<const LENGTH: usize> NewBytes
    for Protected<HeapByteArray<LENGTH>, traits::ReadWrite, traits::Locked>
{
    fn new_bytes() -> Self {
        match HeapByteArray::<LENGTH>::new_locked() {
            Ok(r) => r,
            Err(err) => panic!("Error creating locked bytes: {:?}", err),
        }
    }
}

impl<const LENGTH: usize> NewByteArray<LENGTH>
    for Protected<HeapByteArray<LENGTH>, traits::ReadWrite, traits::Locked>
{
    fn new_byte_array() -> Self {
        match HeapByteArray::<LENGTH>::new_locked() {
            Ok(r) => r,
            Err(err) => panic!("Error creating locked bytes: {:?}", err),
        }
    }

    fn r#gen() -> Self {
        match HeapByteArray::<LENGTH>::new_locked() {
            Ok(mut r) => {
                copy_randombytes(r.as_mut_slice());
                r
            }
            Err(err) => panic!("Error creating locked bytes: {:?}", err),
        }
    }
}

impl<const LENGTH: usize> NewByteArray<LENGTH> for HeapByteArray<LENGTH> {
    fn new_byte_array() -> Self {
        Self::default()
    }

    /// Returns a new byte array filled with random data.
    fn r#gen() -> Self {
        let mut res = Self::default();
        copy_randombytes(res.as_mut_slice());
        res
    }
}

impl<const LENGTH: usize> MutByteArray<LENGTH> for HeapByteArray<LENGTH> {
    fn as_mut_array(&mut self) -> &mut [u8; LENGTH] {
        let ptr = self.0.as_mut_ptr() as *mut [u8; LENGTH];
        // SAFETY: `HeapByteArray<LENGTH>` always allocates exactly `LENGTH`
        // initialized bytes. `&mut self` provides exclusive access to them.
        unsafe { &mut *ptr }
    }
}

impl<const LENGTH: usize> ByteArray<LENGTH>
    for Protected<HeapByteArray<LENGTH>, traits::ReadOnly, traits::Unlocked>
{
    #[inline]
    fn as_array(&self) -> &[u8; LENGTH] {
        match &self.i {
            Some(d) => d.a.as_array(),
            None => panic!("invalid array"),
        }
    }
}

impl<const LENGTH: usize> ByteArray<LENGTH>
    for Protected<HeapByteArray<LENGTH>, traits::ReadOnly, traits::Locked>
{
    #[inline]
    fn as_array(&self) -> &[u8; LENGTH] {
        match &self.i {
            Some(d) => d.a.as_array(),
            None => panic!("invalid array"),
        }
    }
}

impl<const LENGTH: usize> ByteArray<LENGTH>
    for Protected<HeapByteArray<LENGTH>, traits::ReadWrite, traits::Unlocked>
{
    #[inline]
    fn as_array(&self) -> &[u8; LENGTH] {
        match &self.i {
            Some(d) => d.a.as_array(),
            None => panic!("invalid array"),
        }
    }
}

impl<const LENGTH: usize> ByteArray<LENGTH>
    for Protected<HeapByteArray<LENGTH>, traits::ReadWrite, traits::Locked>
{
    #[inline]
    fn as_array(&self) -> &[u8; LENGTH] {
        match &self.i {
            Some(d) => d.a.as_array(),
            None => panic!("invalid array"),
        }
    }
}

impl<const LENGTH: usize> MutByteArray<LENGTH>
    for Protected<HeapByteArray<LENGTH>, traits::ReadWrite, traits::Locked>
{
    #[inline]
    fn as_mut_array(&mut self) -> &mut [u8; LENGTH] {
        match &mut self.i {
            Some(d) => d.a.as_mut_array(),
            None => panic!("invalid array"),
        }
    }
}

impl<const LENGTH: usize> MutByteArray<LENGTH>
    for Protected<HeapByteArray<LENGTH>, traits::ReadWrite, traits::Unlocked>
{
    #[inline]
    fn as_mut_array(&mut self) -> &mut [u8; LENGTH] {
        match &mut self.i {
            Some(d) => d.a.as_mut_array(),
            None => panic!("invalid array"),
        }
    }
}

impl<const LENGTH: usize> AsMut<[u8; LENGTH]>
    for Protected<HeapByteArray<LENGTH>, traits::ReadWrite, traits::Locked>
{
    fn as_mut(&mut self) -> &mut [u8; LENGTH] {
        match &mut self.i {
            Some(d) => d.a.as_mut(),
            None => panic!("invalid array"),
        }
    }
}

impl<const LENGTH: usize> AsMut<[u8; LENGTH]>
    for Protected<HeapByteArray<LENGTH>, traits::ReadWrite, traits::Unlocked>
{
    fn as_mut(&mut self) -> &mut [u8; LENGTH] {
        match &mut self.i {
            Some(d) => d.a.as_mut(),
            None => panic!("invalid array"),
        }
    }
}

impl<A: Zeroize + Bytes, PM: traits::ProtectMode, LM: traits::LockMode> Drop
    for Protected<A, PM, LM>
{
    fn drop(&mut self) {
        let Some(mut data) = self.i.take() else {
            return;
        };

        let writable = data.a.as_slice().is_empty()
            || data.pm == int::ProtectMode::ReadWrite
            || match dryoc_mprotect_readwrite(data.a.as_slice()) {
                Ok(()) => true,
                Err(err) => abort_protected_memory_failure("making memory writable for drop", err),
            };

        if writable {
            data.a.zeroize();
        }

        if data.lm == int::LockMode::Locked {
            match dryoc_munlock(data.a.as_slice()) {
                Ok(()) => data.lm = int::LockMode::Unlocked,
                Err(err) => abort_protected_memory_failure("unlocking memory for drop", err),
            }
        }
    }
}

impl<A: Zeroize + Bytes, PM: traits::ProtectMode, LM: traits::LockMode> ZeroizeOnDrop
    for Protected<A, PM, LM>
{
}

impl<A: Zeroize + Bytes, PM: traits::ProtectMode, LM: traits::LockMode> Zeroize
    for Protected<A, PM, LM>
{
    fn zeroize(&mut self) {
        let Some(data) = &mut self.i else {
            return;
        };
        if data.a.as_slice().is_empty() {
            return;
        }

        let previous_mode = data.pm.clone();
        if previous_mode != int::ProtectMode::ReadWrite
            && let Err(error) = dryoc_mprotect_readwrite(data.a.as_slice())
        {
            abort_protected_memory_failure("making memory writable for zeroization", error);
        }

        data.a.zeroize();

        if previous_mode != int::ProtectMode::ReadWrite
            && let Err(error) = dryoc_mprotect_mode(data.a.as_slice(), &previous_mode)
        {
            abort_protected_memory_failure("restoring memory protection after zeroization", error);
        }
    }
}

fn abort_protected_memory_failure(_operation: &str, _error: std::io::Error) -> ! {
    std::process::abort()
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn protected_byte_array_debug_redacts_contents() {
        let bytes = HeapByteArray::from(StackByteArray::from([0xabu8; 4]));
        let debug = format!("{bytes:?}");

        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("171"));
    }

    fn interesting_lengths() -> impl Strategy<Value = usize> {
        let pagesize = *PAGESIZE;
        let max = pagesize.saturating_mul(2).saturating_add(8);

        prop_oneof![
            Just(0usize),
            Just(1),
            0usize..=128,
            pagesize.saturating_sub(8)..=pagesize.saturating_add(8),
            pagesize.saturating_mul(2).saturating_sub(8)..=max,
        ]
        .boxed()
    }

    fn small_lengths() -> impl Strategy<Value = usize> {
        prop_oneof![Just(0usize), Just(1), 0usize..=256].boxed()
    }

    fn interesting_bytes() -> impl Strategy<Value = Vec<u8>> {
        interesting_lengths()
            .prop_flat_map(|len| prop::collection::vec(any::<u8>(), len))
            .boxed()
    }

    fn small_bytes() -> impl Strategy<Value = Vec<u8>> {
        small_lengths()
            .prop_flat_map(|len| prop::collection::vec(any::<u8>(), len))
            .boxed()
    }

    #[cfg_attr(
        tarpaulin,
        ignore = "tarpaulin can segfault while tracing mlock/mprotect tests"
    )]
    #[test]
    fn test_lock_unlock() {
        use crate::dryocstream::Key;

        let key = Key::generate();
        let key_clone = key.clone();

        let locked_key = key.mlock().expect("lock failed");

        let unlocked_key = locked_key.munlock().expect("unlock failed");

        assert_eq!(unlocked_key.as_slice(), key_clone.as_slice());
    }

    #[cfg_attr(
        tarpaulin,
        ignore = "tarpaulin can segfault while tracing mlock/mprotect tests"
    )]
    #[test]
    fn explicit_zeroize_preserves_locked_readwrite_state() {
        let mut locked =
            HeapBytes::from_slice_into_locked(b"sensitive").expect("locked allocation failed");

        locked.zeroize();

        assert_eq!(locked.as_slice(), &[0; 9]);
        let state = locked.i.as_ref().expect("protected state missing");
        assert_eq!(state.lm, int::LockMode::Locked);
        assert_eq!(state.pm, int::ProtectMode::ReadWrite);

        let unlocked = locked.munlock().expect("unlock after zeroize failed");
        assert_eq!(unlocked.as_slice(), &[0; 9]);
    }

    #[cfg(unix)]
    #[cfg_attr(
        tarpaulin,
        ignore = "tarpaulin can segfault while tracing mlock/mprotect tests"
    )]
    #[test]
    fn explicit_zeroize_restores_readonly_protection() {
        let mut readonly = HeapBytes::from_slice_into_readonly_locked(b"sensitive")
            .expect("read-only locked allocation failed");

        readonly.zeroize();

        assert_eq!(readonly.as_slice(), &[0; 9]);
        let state = readonly.i.as_ref().expect("protected state missing");
        assert_eq!(state.lm, int::LockMode::Locked);
        assert_eq!(state.pm, int::ProtectMode::ReadOnly);

        // Verify the operating-system permissions, not just the typestate.
        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork failed");
        if child == 0 {
            let data = readonly.as_slice().as_ptr() as *mut u8;
            // SAFETY: The child intentionally probes the read-only page. A
            // correct implementation terminates it with SIGSEGV or SIGBUS.
            unsafe {
                std::ptr::write_volatile(data, 1);
                libc::_exit(0);
            }
        }

        let mut status = 0;
        // SAFETY: `child` is the positive PID returned by `fork`, and `status`
        // points to writable storage for the wait status.
        let wait_ret = unsafe { libc::waitpid(child, &mut status, 0) };
        assert_eq!(wait_ret, child);
        assert!(
            libc::WIFSIGNALED(status),
            "child unexpectedly wrote to explicitly zeroized read-only memory"
        );

        let readwrite = readonly
            .mprotect_readwrite()
            .expect("read-write transition failed");
        let unlocked = readwrite.munlock().expect("unlock failed");
        assert_eq!(unlocked.as_slice(), &[0; 9]);
    }

    #[cfg_attr(
        tarpaulin,
        ignore = "tarpaulin can segfault while tracing mlock/mprotect tests"
    )]
    #[test]
    fn test_protect_unprotect() {
        use crate::dryocstream::Key;

        let key = Key::generate();
        let key_clone = key.clone();

        let readonly_key = key.mprotect_readonly().expect("mprotect failed");
        assert_eq!(readonly_key.as_slice(), key_clone.as_slice());

        let mut readwrite_key = readonly_key.mprotect_readwrite().expect("mprotect failed");
        assert_eq!(readwrite_key.as_slice(), key_clone.as_slice());

        // should be able to write now without blowing up
        readwrite_key.as_mut_slice()[0] = 0;
    }

    #[cfg(feature = "nightly")]
    #[test]
    fn test_allocator() {
        let mut vec: Vec<i32, _> = Vec::new_in(PageAlignedAllocator);

        vec.push(1);
        vec.push(2);
        vec.push(3);

        for i in 0..5000 {
            vec.push(i);
        }

        vec.resize(5, 0);

        assert_eq!([1, 2, 3, 0, 1], vec.as_slice());
    }

    #[cfg(feature = "nightly")]
    #[test]
    fn test_allocator_honors_supported_alignment() {
        let allocator = PageAlignedAllocator;
        let layout = std::alloc::Layout::from_size_align(1, *PAGESIZE).unwrap();
        let allocation = allocator.allocate(layout).unwrap();
        let data = allocation.as_ptr() as *mut u8;

        assert_eq!(data.addr() % layout.align(), 0);

        // SAFETY: `data` was returned by `allocator` for this exact `layout`.
        unsafe { allocator.deallocate(NonNull::new_unchecked(data), layout) };
    }

    #[cfg(feature = "nightly")]
    #[test]
    fn test_allocator_rejects_unsupported_alignment() {
        let unsupported_alignment = PAGESIZE.checked_mul(2).unwrap();
        let layout = std::alloc::Layout::from_size_align(1, unsupported_alignment).unwrap();

        assert!(PageAlignedAllocator.allocate(layout).is_err());
    }

    #[cfg(feature = "nightly")]
    #[test]
    fn test_allocator_handles_zero_sized_layout() {
        let allocator = PageAlignedAllocator;
        let layout = std::alloc::Layout::from_size_align(0, 1).unwrap();
        let allocation = allocator.allocate(layout).unwrap();
        let data = allocation.as_ptr() as *mut u8;

        assert_eq!(allocation.len(), 0);
        assert_eq!(data.addr() % layout.align(), 0);

        // SAFETY: `data` was returned by `allocator` for this exact `layout`.
        unsafe { allocator.deallocate(NonNull::new_unchecked(data), layout) };
    }

    #[test]
    fn test_page_rounding() {
        let pagesize = *PAGESIZE;

        assert_eq!(_page_round(0, pagesize), Some(0));
        assert_eq!(_page_round(1, pagesize), Some(pagesize));
        assert_eq!(_page_round(pagesize, pagesize), Some(pagesize));
        assert_eq!(_page_round(pagesize + 1, pagesize), Some(pagesize * 2));
        assert_eq!(_page_round(usize::MAX, pagesize), None);
    }

    #[cfg(unix)]
    #[test]
    fn test_page_size_from_sysconf_handles_error_sentinel() {
        assert_eq!(page_size_from_sysconf(-1), DEFAULT_PAGESIZE);
        assert_eq!(page_size_from_sysconf(0), DEFAULT_PAGESIZE);
        assert_eq!(page_size_from_sysconf(8192), 8192);
    }

    #[test]
    fn test_empty_heapbytes_and_locking() {
        let empty = HeapBytes::default();
        assert!(empty.is_empty());
        assert_eq!(empty.as_slice().len(), 0);

        let locked: LockedBytes = HeapBytes::new_locked().expect("empty mlock failed");
        assert!(locked.is_empty());

        let unlocked = locked.munlock().expect("empty munlock failed");
        assert!(unlocked.is_empty());
    }

    #[test]
    fn test_heapbytes_resize_grow_shrink_and_fill() {
        let mut bytes = HeapBytes::default();
        bytes.resize(3, 0x7a);
        assert_eq!(bytes.as_slice(), &[0x7a, 0x7a, 0x7a]);

        bytes.as_mut_slice()[1] = 0x11;
        bytes.resize(5, 0x5a);
        assert_eq!(bytes.as_slice(), &[0x7a, 0x11, 0x7a, 0x5a, 0x5a]);

        bytes.resize(2, 0);
        assert_eq!(bytes.as_slice(), &[0x7a, 0x11]);

        bytes.resize(0, 0);
        assert!(bytes.is_empty());
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn proptest_heapbytes_roundtrip_clone_and_mutation(data in interesting_bytes()) {
            let bytes = HeapBytes::from(data.as_slice());
            prop_assert_eq!(bytes.len(), data.len());
            prop_assert_eq!(bytes.as_slice(), data.as_slice());
            prop_assert_eq!(bytes.as_ref(), data.as_slice());

            let mut cloned = bytes.clone();
            prop_assert_eq!(&cloned, &bytes);
            prop_assert_eq!(cloned.as_slice(), data.as_slice());

            if !data.is_empty() {
                prop_assert_eq!(cloned[0], data[0]);

                let last = data.len() - 1;
                prop_assert_eq!(cloned[last], data[last]);

                cloned[0] = cloned[0].wrapping_add(1);
                prop_assert_ne!(cloned[0], data[0]);
                prop_assert_eq!(&cloned[1..], &data[1..]);
            }
        }

        #[test]
        fn proptest_heapbytes_resize_matches_vec_model(
            initial in interesting_bytes(),
            ops in prop::collection::vec((interesting_lengths(), any::<u8>()), 0..12),
        ) {
            let mut bytes = HeapBytes::from(initial.as_slice());
            let mut model = initial;

            for (new_len, value) in ops {
                bytes.resize(new_len, value);
                model.resize(new_len, value);
                prop_assert_eq!(bytes.as_slice(), model.as_slice());
            }
        }

        #[test]
        fn proptest_protection_transitions_preserve_bytes(data in interesting_bytes()) {
            let protected =
                Protected::<HeapBytes, traits::ReadWrite, traits::Unlocked>::new_with(
                    HeapBytes::from(data.as_slice()),
                );

            let readonly = protected
                .mprotect_readonly()
                .expect("readonly mprotect failed");
            prop_assert_eq!(readonly.as_slice(), data.as_slice());

            let readwrite = readonly
                .mprotect_readwrite()
                .expect("readwrite mprotect failed");
            prop_assert_eq!(readwrite.as_slice(), data.as_slice());

            let noaccess = readwrite
                .mprotect_noaccess()
                .expect("noaccess mprotect failed");
            let readwrite = noaccess
                .mprotect_readwrite()
                .expect("readwrite mprotect failed");
            prop_assert_eq!(readwrite.as_slice(), data.as_slice());
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]

        #[test]
        fn proptest_locked_heapbytes_resize_matches_vec_model(
            initial in small_bytes(),
            ops in prop::collection::vec((small_lengths(), any::<u8>()), 0..8),
        ) {
            let mut locked = HeapBytes::from_slice_into_locked(initial.as_slice())
                .expect("locked allocation failed");
            let mut model = initial;

            for (new_len, value) in ops {
                locked.resize(new_len, value);
                model.resize(new_len, value);
                prop_assert_eq!(locked.as_slice(), model.as_slice());
            }

            let unlocked = locked.munlock().expect("munlock failed");
            prop_assert_eq!(unlocked.as_slice(), model.as_slice());
        }

        #[test]
        fn proptest_heapbytearray_exact_size_views(data in any::<[u8; 32]>()) {
            let mut bytes = HeapByteArray::<32>::from(&data);

            prop_assert_eq!(bytes.as_array(), &data);
            prop_assert_eq!(AsRef::<[u8; 32]>::as_ref(&bytes), &data);
            prop_assert_eq!(bytes.as_slice(), &data);

            let mut expected = data;
            bytes.as_mut_array()[7] ^= 0xa5;
            expected[7] ^= 0xa5;
            prop_assert_eq!(bytes.as_array(), &expected);

            AsMut::<[u8; 32]>::as_mut(&mut bytes)[24] = 0x5a;
            expected[24] = 0x5a;
            prop_assert_eq!(bytes.as_slice(), &expected);
        }
    }

    #[test]
    fn test_heapbytearray_exact_size_views() {
        let mut bytes = HeapByteArray::<4>::default();
        bytes.as_mut_array().copy_from_slice(&[1, 2, 3, 4]);

        assert_eq!(bytes.as_array(), &[1, 2, 3, 4]);
        assert_eq!(AsRef::<[u8; 4]>::as_ref(&bytes), &[1, 2, 3, 4]);

        AsMut::<[u8; 4]>::as_mut(&mut bytes)[2] = 9;
        assert_eq!(bytes.as_slice(), &[1, 2, 9, 4]);
    }

    #[cfg_attr(
        tarpaulin,
        ignore = "tarpaulin can segfault while tracing mlock/mprotect tests"
    )]
    #[test]
    fn test_mprotect_handles_single_byte_slice() {
        let mut vec = HeapBytes::from(&[1u8][..]);

        dryoc_mprotect_readonly(vec.as_slice()).expect("readonly mprotect failed");
        dryoc_mprotect_readwrite(vec.as_slice()).expect("readwrite mprotect failed");
        vec[0] = 2;

        assert_eq!(vec[0], 2);
    }

    #[cfg_attr(
        tarpaulin,
        ignore = "tarpaulin can segfault while tracing mlock/mprotect tests"
    )]
    #[test]
    fn test_mprotect_handles_exact_page_slice() {
        let pagesize = *PAGESIZE;
        let mut vec = HeapBytes::default();
        vec.resize(pagesize, 1);

        dryoc_mprotect_readonly(vec.as_slice()).expect("readonly mprotect failed");
        dryoc_mprotect_readwrite(vec.as_slice()).expect("readwrite mprotect failed");
        vec[0] = 2;
        vec[pagesize - 1] = 3;

        assert_eq!(vec[0], 2);
        assert_eq!(vec[pagesize - 1], 3);
    }

    #[cfg(unix)]
    #[cfg_attr(
        tarpaulin,
        ignore = "tarpaulin can segfault while tracing mlock/mprotect tests"
    )]
    #[test]
    fn test_mprotect_noaccess_covers_page_boundary_tail() {
        let pagesize = *PAGESIZE;
        let mut vec = HeapBytes::default();
        vec.resize(pagesize + 1, 0);

        dryoc_mprotect_noaccess(vec.as_slice()).expect("noaccess mprotect failed");

        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork failed");

        if child == 0 {
            let tail = unsafe { vec.as_slice().as_ptr().add(pagesize) as *mut u8 };
            unsafe {
                std::ptr::write_volatile(tail, 1);
                libc::_exit(0);
            }
        }

        let mut status = 0;
        let wait_ret = unsafe { libc::waitpid(child, &mut status, 0) };
        dryoc_mprotect_readwrite(vec.as_slice()).expect("readwrite mprotect failed");

        assert_eq!(wait_ret, child);
        assert!(
            libc::WIFSIGNALED(status),
            "child unexpectedly wrote to protected tail page"
        );
    }

    // #[test]
    // fn test_crash() {
    //     use crate::protected::*;

    //     // Create a read-only, locked region of memory
    //     let readonly_locked =
    // HeapBytes::from_slice_into_readonly_locked(b"some locked bytes")
    //         .expect("failed to get locked bytes");

    //     // Write to a protected region of memory, causing a crash.
    //     unsafe {
    //         ptr::write(readonly_locked.as_slice().as_ptr() as *mut u8, 0) //
    // <- crash happens here     };
    // }
}
