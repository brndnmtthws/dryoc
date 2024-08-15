//! # Memory protection utilities
//!
//! Provides access to the memory locking system calls, such as `mlock()` and
//! `mprotect()` on UNIX-like systems, `VirtualLock()` and `VirtualProtect()` on
//! Windows. Similar to libsodium's `sodium_mlock` and `sodium_mprotect_*`
//! functions.
//!
//! On Linux, sets `MADV_DONTDUMP` with `madvise()` on locked regions.
//!
//! The protected memory features leverage Rust's [`Allocator`] API, which
//! requires nightly Rust. This crate must be built with the `nightly` feature
//! flag enabled to activate these features.
//!
//! For details on the [`Allocator`] API, see:
//! <https://github.com/rust-lang/rust/issues/32838>
//!
//! If the `serde` feature is enabled, the [`serde::Deserialize`] and
//! [`serde::Serialize`] traits will be implemented for [`HeapBytes`] and
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
use std::alloc::{AllocError, Allocator, Layout};
use std::marker::PhantomData;
use std::ptr;

use lazy_static::lazy_static;
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
    fn mlock(self) -> Result<Protected<A, traits::ReadWrite, traits::Locked>, std::io::Error>;
}

/// Protected region of memory that can be locked.
pub trait Lock<A: Zeroize + Bytes, PM: traits::ProtectMode> {
    /// Locks a region of memory, using `mlock()` on UNIX, or `VirtualLock()` on
    /// Windows. By default, the protect mode is set to ReadWrite (i.e., no
    /// exec) using `mprotect()` on UNIX, or `VirtualProtect()` on Windows.
    /// On Linux, it will also set `MADV_DONTDUMP` using `madvise()`.
    fn mlock(self) -> Result<Protected<A, PM, traits::Locked>, std::io::Error>;
}

/// Protected region of memory that can be locked (i.e., is already locked).
pub trait Unlock<A: Zeroize + Bytes, PM: traits::ProtectMode> {
    /// Unlocks a region of memory, using `munlock()` on UNIX, or
    /// `VirtualLock()` on Windows.
    fn munlock(self) -> Result<Protected<A, PM, traits::Unlocked>, std::io::Error>;
}

/// Protected region of memory that can be set as read-only.
pub trait ProtectReadOnly<A: Zeroize + Bytes, PM: traits::ProtectMode, LM: traits::LockMode> {
    /// Protects a region of memory as read-only (and no exec), using
    /// `mprotect()` on UNIX, or `VirtualProtect()` on Windows.
    fn mprotect_readonly(self) -> Result<Protected<A, traits::ReadOnly, LM>, std::io::Error>;
}

/// Protected region of memory that can be set as read-write.
pub trait ProtectReadWrite<A: Zeroize + Bytes, PM: traits::ProtectMode, LM: traits::LockMode> {
    /// Protects a region of memory as read-write (and no exec), using
    /// `mprotect()` on UNIX, or `VirtualProtect()` on Windows.
    fn mprotect_readwrite(self) -> Result<Protected<A, traits::ReadWrite, LM>, std::io::Error>;
}

/// Protected region of memory that can be set as no-access. Must be unlocked.
pub trait ProtectNoAccess<A: Zeroize + Bytes, PM: traits::ProtectMode> {
    /// Protects an unlocked region of memory as no-access (and no exec), using
    /// `mprotect()` on UNIX, or `VirtualProtect()` on Windows.
    fn mprotect_noaccess(
        self,
    ) -> Result<Protected<A, traits::NoAccess, traits::Unlocked>, std::io::Error>;
}

/// Bytes which can be allocated and protected.
pub trait NewLocked<A: Zeroize + NewBytes + Lockable<A>> {
    /// Returns a new locked byte array.
    fn new_locked() -> Result<Protected<A, traits::ReadWrite, traits::Locked>, std::io::Error>;
    /// Returns a new locked byte array.
    fn new_readonly_locked()
    -> Result<Protected<A, traits::ReadOnly, traits::Locked>, std::io::Error>;
    /// Returns a new locked byte array, filled with random data.
    fn gen_locked() -> Result<Protected<A, traits::ReadWrite, traits::Locked>, std::io::Error>;
    /// Returns a new read-only, locked byte array, filled with random data.
    fn gen_readonly_locked()
    -> Result<Protected<A, traits::ReadOnly, traits::Locked>, std::io::Error>;
}

/// Create a new region of protected memory from a slice.
pub trait NewLockedFromSlice<A: Zeroize + NewBytes + Lockable<A>> {
    /// Returns a new locked region of memory from `src`.
    fn from_slice_into_locked(
        src: &[u8],
    ) -> Result<Protected<A, traits::ReadWrite, traits::Locked>, crate::error::Error>;
    /// Returns a new read-only locked region of memory from `src`.
    fn from_slice_into_readonly_locked(
        src: &[u8],
    ) -> Result<Protected<A, traits::ReadOnly, traits::Locked>, crate::error::Error>;
}

/// Holds Protected region of memory. Does not implement traits such as
/// [Copy], [Clone], or [std::fmt::Debug].
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
            use libc::{madvise, MADV_DONTDUMP};
            unsafe {
                madvise(data.as_ptr() as *mut c_void, data.len(), MADV_DONTDUMP);
            }
        }

        use libc::{c_void, mlock as c_mlock};
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

        let res = unsafe { VirtualLock(data.as_ptr() as LPVOID, data.len()) };
        match res {
            1 => Ok(()),
            _ => Err(std::io::Error::last_os_error()),
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
            use libc::{madvise, MADV_DODUMP};
            unsafe {
                madvise(data.as_ptr() as *mut c_void, data.len(), MADV_DODUMP);
            }
        }

        use libc::{c_void, munlock as c_munlock};
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

        let res = unsafe { VirtualUnlock(data.as_ptr() as LPVOID, data.len()) };
        match res {
            1 => Ok(()),
            _ => Err(std::io::Error::last_os_error()),
        }
    }
}

fn dryoc_mprotect_readonly(data: &[u8]) -> Result<(), std::io::Error> {
    if data.is_empty() {
        // no-op
        return Ok(());
    }
    #[cfg(unix)]
    {
        use libc::{c_void, mprotect as c_mprotect, PROT_READ};
        let ret = unsafe { c_mprotect(data.as_ptr() as *mut c_void, data.len() - 1, PROT_READ) };
        match ret {
            0 => Ok(()),
            _ => Err(std::io::Error::last_os_error()),
        }
    }
    #[cfg(windows)]
    {
        use winapi::shared::minwindef::{DWORD, LPVOID};
        use winapi::um::memoryapi::VirtualProtect;
        use winapi::um::winnt::PAGE_READONLY;

        let mut old: DWORD = 0;

        let res = unsafe {
            VirtualProtect(
                data.as_ptr() as LPVOID,
                data.len() - 1,
                PAGE_READONLY,
                &mut old,
            )
        };
        match res {
            1 => Ok(()),
            _ => Err(std::io::Error::last_os_error()),
        }
    }
}

fn dryoc_mprotect_readwrite(data: &[u8]) -> Result<(), std::io::Error> {
    if data.is_empty() {
        // no-op
        return Ok(());
    }
    #[cfg(unix)]
    {
        use libc::{c_void, mprotect as c_mprotect, PROT_READ, PROT_WRITE};
        let ret = unsafe {
            c_mprotect(
                data.as_ptr() as *mut c_void,
                data.len() - 1,
                PROT_READ | PROT_WRITE,
            )
        };
        match ret {
            0 => Ok(()),
            _ => Err(std::io::Error::last_os_error()),
        }
    }
    #[cfg(windows)]
    {
        use winapi::shared::minwindef::{DWORD, LPVOID};
        use winapi::um::memoryapi::VirtualProtect;
        use winapi::um::winnt::PAGE_READWRITE;

        let mut old: DWORD = 0;

        let res = unsafe {
            VirtualProtect(
                data.as_ptr() as LPVOID,
                data.len() - 1,
                PAGE_READWRITE,
                &mut old,
            )
        };
        match res {
            1 => Ok(()),
            _ => Err(std::io::Error::last_os_error()),
        }
    }
}

fn dryoc_mprotect_noaccess(data: &[u8]) -> Result<(), std::io::Error> {
    if data.is_empty() {
        // no-op
        return Ok(());
    }
    #[cfg(unix)]
    {
        use libc::{c_void, mprotect as c_mprotect, PROT_NONE};
        let ret = unsafe { c_mprotect(data.as_ptr() as *mut c_void, data.len() - 1, PROT_NONE) };
        match ret {
            0 => Ok(()),
            _ => Err(std::io::Error::last_os_error()),
        }
    }
    #[cfg(windows)]
    {
        use winapi::shared::minwindef::{DWORD, LPVOID};
        use winapi::um::memoryapi::VirtualProtect;
        use winapi::um::winnt::PAGE_NOACCESS;

        let mut old: DWORD = 0;

        let res = unsafe {
            VirtualProtect(
                data.as_ptr() as LPVOID,
                data.len() - 1,
                PAGE_NOACCESS,
                &mut old,
            )
        };
        match res {
            1 => Ok(()),
            _ => Err(std::io::Error::last_os_error()),
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
    ) -> Result<Protected<A, OPM, OLM>, std::io::Error>
    where
        F: Fn(&mut int::InternalData<A>) -> Result<Protected<A, OPM, OLM>, std::io::Error>,
    {
        match &mut self.i {
            Some(d) => {
                let mut new = f(d)?;
                // swap into new struct
                std::mem::swap(&mut new.i, &mut self.i);
                Ok(new)
            }
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "unexpected empty internal struct",
            )),
        }
    }
}

impl<A: Zeroize + Bytes, PM: traits::ProtectMode, LM: traits::LockMode> Unlock<A, PM>
    for Protected<A, PM, LM>
{
    fn munlock(mut self) -> Result<Protected<A, PM, traits::Unlocked>, std::io::Error> {
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
    fn mlock(mut self) -> Result<Protected<A, PM, traits::Locked>, std::io::Error> {
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
    fn mprotect_readonly(mut self) -> Result<Protected<A, traits::ReadOnly, LM>, std::io::Error> {
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
    fn mprotect_readwrite(mut self) -> Result<Protected<A, traits::ReadWrite, LM>, std::io::Error> {
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
    ) -> Result<Protected<A, traits::NoAccess, traits::Unlocked>, std::io::Error> {
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
    pub fn mlock(
        self,
    ) -> Result<Protected<HeapByteArray<LENGTH>, traits::ReadWrite, traits::Locked>, std::io::Error>
    {
        Protected::<HeapByteArray<LENGTH>, traits::ReadWrite, traits::Unlocked>::new_with(
            self.into(),
        )
        .mlock()
    }
}

impl<const LENGTH: usize> StackByteArray<LENGTH> {
    /// Returns a readonly protected [StackByteArray].
    pub fn mprotect_readonly(
        self,
    ) -> Result<Protected<HeapByteArray<LENGTH>, traits::ReadOnly, traits::Unlocked>, std::io::Error>
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
    ) -> Result<Protected<HeapByteArray<LENGTH>, traits::ReadWrite, traits::Locked>, std::io::Error>
    {
        Protected::<HeapByteArray<LENGTH>, traits::ReadWrite, traits::Unlocked>::new_with(self)
            .mlock()
    }
}

impl Lockable<HeapBytes> for HeapBytes {
    /// Locks a [HeapBytes], and returns a [Protected] wrapper.
    fn mlock(
        self,
    ) -> Result<Protected<HeapBytes, traits::ReadWrite, traits::Locked>, std::io::Error> {
        Protected::<HeapBytes, traits::ReadWrite, traits::Unlocked>::new_with(self).mlock()
    }
}

#[derive(Clone)]
/// Custom page-aligned allocator implementation. Creates blocks of page-aligned
/// heap-allocated memory regions, with no-access pages before and after the
/// allocated region of memory.
pub struct PageAlignedAllocator;

lazy_static! {
    static ref PAGESIZE: usize = {
        #[cfg(unix)]
        {
            use libc::{sysconf, _SC_PAGE_SIZE};
            unsafe { sysconf(_SC_PAGE_SIZE) as usize }
        }
        #[cfg(windows)]
        {
            use winapi::um::sysinfoapi::{GetSystemInfo, SYSTEM_INFO};
            let mut si = SYSTEM_INFO::default();
            unsafe { GetSystemInfo(&mut si) };
            si.dwPageSize as usize
        }
    };
}

fn _page_round(size: usize, pagesize: usize) -> usize {
    size + (pagesize - size % pagesize)
}

unsafe impl Allocator for PageAlignedAllocator {
    #[inline]
    fn allocate(&self, layout: Layout) -> Result<ptr::NonNull<[u8]>, AllocError> {
        let pagesize = *PAGESIZE;
        let size = _page_round(layout.size(), pagesize) + 2 * pagesize;
        #[cfg(unix)]
        let out = {
            use libc::posix_memalign;
            let mut out = ptr::null_mut();

            // allocate full pages, in addition to an extra page at the start and
            // end which will remain locked with no access permitted.
            let ret = unsafe { posix_memalign(&mut out, pagesize, size) };
            if ret != 0 {
                return Err(AllocError);
            }

            out
        };
        #[cfg(windows)]
        let out = {
            use winapi::um::memoryapi::VirtualAlloc;
            use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE};
            unsafe {
                VirtualAlloc(
                    ptr::null_mut(),
                    size,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_READWRITE,
                )
            }
        };

        // lock the pages at the fore of the region
        let fore_protected_region =
            unsafe { std::slice::from_raw_parts_mut(out as *mut u8, pagesize) };
        dryoc_mprotect_noaccess(fore_protected_region)
            .map_err(|err| eprintln!("mprotect error = {:?}, in allocator", err))
            .ok();

        // lock the pages at the aft of the region
        let aft_protected_region_offset = pagesize + _page_round(layout.size(), pagesize);
        let aft_protected_region = unsafe {
            std::slice::from_raw_parts_mut(
                out.add(aft_protected_region_offset) as *mut u8,
                pagesize,
            )
        };
        dryoc_mprotect_noaccess(aft_protected_region)
            .map_err(|err| eprintln!("mprotect error = {:?}, in allocator", err))
            .ok();

        let slice =
            unsafe { std::slice::from_raw_parts_mut(out.add(pagesize) as *mut u8, layout.size()) };

        dryoc_mprotect_readwrite(slice)
            .map_err(|err| eprintln!("mprotect error = {:?}, in allocator", err))
            .ok();

        unsafe { Ok(ptr::NonNull::new_unchecked(slice)) }
    }

    #[inline]
    unsafe fn deallocate(&self, ptr: ptr::NonNull<u8>, layout: Layout) {
        let pagesize = *PAGESIZE;

        let ptr = ptr.as_ptr().offset(-(pagesize as isize));

        // unlock the fore protected region
        let fore_protected_region = std::slice::from_raw_parts_mut(ptr, pagesize);
        dryoc_mprotect_readwrite(fore_protected_region)
            .map_err(|err| eprintln!("mprotect error = {:?}", err))
            .ok();

        // unlock the aft protected region
        let aft_protected_region_offset = pagesize + _page_round(layout.size(), pagesize);
        let aft_protected_region =
            std::slice::from_raw_parts_mut(ptr.add(aft_protected_region_offset), pagesize);

        dryoc_mprotect_readwrite(aft_protected_region)
            .map_err(|err| eprintln!("mprotect error = {:?}", err))
            .ok();

        #[cfg(unix)]
        {
            libc::free(ptr as *mut libc::c_void);
        }
        #[cfg(windows)]
        {
            use winapi::shared::minwindef::LPVOID;
            use winapi::um::memoryapi::VirtualFree;
            use winapi::um::winnt::MEM_RELEASE;
            VirtualFree(ptr as LPVOID, 0, MEM_RELEASE);
        }
    }
}

/// A heap-allocated fixed-length byte array, using the
/// [page-aligned allocator](PageAlignedAllocator). Required for working with
/// protected memory regions. Wraps a [`Vec`] with custom [`Allocator`]
/// implementation.
#[derive(Zeroize, ZeroizeOnDrop, Debug, PartialEq, Eq, Clone)]
pub struct HeapByteArray<const LENGTH: usize>(Vec<u8, PageAlignedAllocator>);

/// A heap-allocated resizable byte array, using the
/// [page-aligned allocator](PageAlignedAllocator). Required for working with
/// protected memory regions. Wraps a [`Vec`] with custom [`Allocator`]
/// implementation.
#[derive(Zeroize, ZeroizeOnDrop, Debug, PartialEq, Eq, Clone)]
pub struct HeapBytes(Vec<u8, PageAlignedAllocator>);

impl<A: Zeroize + NewBytes + Lockable<A>> NewLocked<A> for A {
    fn new_locked() -> Result<Protected<Self, traits::ReadWrite, traits::Locked>, std::io::Error> {
        Self::new_bytes().mlock()
    }

    fn new_readonly_locked()
    -> Result<Protected<Self, traits::ReadOnly, traits::Locked>, std::io::Error> {
        Self::new_bytes()
            .mlock()
            .and_then(|p| p.mprotect_readonly())
    }

    fn gen_locked() -> Result<Protected<Self, traits::ReadWrite, traits::Locked>, std::io::Error> {
        let mut res = Self::new_bytes().mlock()?;
        copy_randombytes(res.as_mut_slice());
        Ok(res)
    }

    fn gen_readonly_locked()
    -> Result<Protected<Self, traits::ReadOnly, traits::Locked>, std::io::Error> {
        Self::gen_locked().and_then(|s| s.mprotect_readonly())
    }
}

impl<A: Zeroize + NewBytes + ResizableBytes + Lockable<A>> NewLockedFromSlice<A> for A {
    /// Returns a new locked byte array from `other`. Panics if sizes do not
    /// match.
    fn from_slice_into_locked(
        src: &[u8],
    ) -> Result<Protected<Self, traits::ReadWrite, traits::Locked>, crate::error::Error> {
        let mut res = Self::new_bytes().mlock()?;
        res.resize(src.len(), 0);
        res.as_mut_slice().copy_from_slice(src);
        Ok(res)
    }

    /// Returns a new locked byte array from `other`. Panics if sizes do not
    /// match.
    fn from_slice_into_readonly_locked(
        src: &[u8],
    ) -> Result<Protected<Self, traits::ReadOnly, traits::Locked>, crate::error::Error> {
        Self::from_slice_into_locked(src)
            .and_then(|s| s.mprotect_readonly().map_err(|err| err.into()))
    }
}

impl<const LENGTH: usize> NewLockedFromSlice<HeapByteArray<LENGTH>> for HeapByteArray<LENGTH> {
    /// Returns a new locked byte array from `other`. Panics if sizes do not
    /// match.
    fn from_slice_into_locked(
        other: &[u8],
    ) -> Result<Protected<Self, traits::ReadWrite, traits::Locked>, crate::error::Error> {
        if other.len() != LENGTH {
            return Err(dryoc_error!(format!(
                "slice length {} doesn't match expected {}",
                other.len(),
                LENGTH
            )));
        }
        let mut res = Self::new_bytes().mlock()?;
        res.as_mut_slice().copy_from_slice(other);
        Ok(res)
    }

    fn from_slice_into_readonly_locked(
        other: &[u8],
    ) -> Result<Protected<Self, traits::ReadOnly, traits::Locked>, crate::error::Error> {
        Self::from_slice_into_locked(other)
            .and_then(|s| s.mprotect_readonly().map_err(|err| err.into()))
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
        unsafe { &*arr }
    }
}

impl<const LENGTH: usize> std::convert::AsMut<[u8; LENGTH]> for HeapByteArray<LENGTH> {
    fn as_mut(&mut self) -> &mut [u8; LENGTH] {
        let arr = self.0.as_mut_ptr() as *mut [u8; LENGTH];
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
        let mut v = Vec::new_in(PageAlignedAllocator);
        v.resize(LENGTH, 0);
        Self(v)
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

impl Default for HeapBytes {
    fn default() -> Self {
        Self(Vec::new_in(PageAlignedAllocator))
    }
}

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
            Err(dryoc_error!(format!(
                "Invalid size: expected {} found {}",
                LENGTH,
                src.len()
            )))
        } else {
            let mut arr = Self::default();
            arr.0.copy_from_slice(src);
            Ok(arr)
        }
    }
}

impl From<&[u8]> for HeapBytes {
    fn from(src: &[u8]) -> Self {
        let mut arr = Self::default();
        arr.0.copy_from_slice(src);
        arr
    }
}

impl<const LENGTH: usize> ByteArray<LENGTH> for HeapByteArray<LENGTH> {
    #[inline]
    fn as_array(&self) -> &[u8; LENGTH] {
        // this is safe for fixed-length arrays
        let ptr = self.0.as_ptr() as *const [u8; LENGTH];
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

    fn gen() -> Self {
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
    fn gen() -> Self {
        let mut res = Self::default();
        copy_randombytes(&mut res.0);
        res
    }
}

impl<const LENGTH: usize> MutByteArray<LENGTH> for HeapByteArray<LENGTH> {
    fn as_mut_array(&mut self) -> &mut [u8; LENGTH] {
        // this is safe for fixed-length arrays
        let ptr = self.0.as_ptr() as *mut [u8; LENGTH];
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
        self.zeroize()
    }
}

impl<A: Zeroize + Bytes, PM: traits::ProtectMode, LM: traits::LockMode> Zeroize
    for Protected<A, PM, LM>
{
    fn zeroize(&mut self) {
        if let Some(d) = &mut self.i {
            if !d.a.as_slice().is_empty() {
                if d.pm != int::ProtectMode::ReadWrite {
                    dryoc_mprotect_readwrite(d.a.as_slice())
                        .map_err(|err| eprintln!("mprotect_readwrite error on drop = {:?}", err))
                        .ok();
                }
                d.a.zeroize();
                if d.lm == int::LockMode::Locked {
                    dryoc_munlock(d.a.as_slice())
                        .map_err(|err| eprintln!("dryoc_munlock error on drop = {:?}", err))
                        .ok();
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lock_unlock() {
        use crate::dryocstream::Key;

        let key = Key::gen();
        let key_clone = key.clone();

        let locked_key = key.mlock().expect("lock failed");

        let unlocked_key = locked_key.munlock().expect("unlock failed");

        assert_eq!(unlocked_key.as_slice(), key_clone.as_slice());
    }

    #[test]
    fn test_protect_unprotect() {
        use crate::dryocstream::Key;

        let key = Key::gen();
        let key_clone = key.clone();

        let readonly_key = key.mprotect_readonly().expect("mprotect failed");
        assert_eq!(readonly_key.as_slice(), key_clone.as_slice());

        let mut readwrite_key = readonly_key.mprotect_readwrite().expect("mprotect failed");
        assert_eq!(readwrite_key.as_slice(), key_clone.as_slice());

        // should be able to write now without blowing up
        readwrite_key.as_mut_slice()[0] = 0;
    }

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
