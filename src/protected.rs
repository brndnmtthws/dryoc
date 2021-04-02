/*!
# Memory protection utilities

Provides access to the memory locking system calls, such as `mlock()` and
`mprotect()` on UNIX-like systems, `VirtualLock()` and `VirtualProtect()` on
Windows. Similar to libsodium's `sodium_mlock` and `sodium_mprotect_*`
functions.

The protected memory features use the new [Allocator] API, which requires
nightly Rust. This crate must be built with the `nightly` feature flag
enabled to activate these features.

For details on the [Allocator] API, see:
<https://github.com/rust-lang/rust/issues/32838>
 */
use crate::error;
use crate::rng::copy_randombytes;
use crate::types::*;

#[cfg(all(feature = "serde", feature = "base64"))]
use crate::bytes_serde::*;

use lazy_static::lazy_static;
use std::alloc::{AllocError, Allocator, Layout};
use std::convert::TryFrom;
use std::convert::{AsMut, AsRef};
use std::marker::PhantomData;
use std::ptr;
use zeroize::Zeroize;

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

pub trait Lock<A: Zeroize + MutBytes + Default, PM: ProtectMode> {
    fn mlock(self) -> Result<Protected<A, PM, Locked>, std::io::Error>;
}

pub trait Lockable<A: Zeroize + MutBytes + Default> {
    fn mlock(self) -> Result<Protected<A, ReadWrite, Locked>, std::io::Error>;
}

pub trait Unlock<A: Zeroize + MutBytes + Default, PM: ProtectMode> {
    fn munlock(self) -> Result<Protected<A, PM, Unlocked>, std::io::Error>;
}

pub trait ProtectReadOnly<A: Zeroize + MutBytes + Default, PM: ProtectMode, LM: LockMode> {
    fn mprotect_readonly(self) -> Result<Protected<A, ReadOnly, LM>, std::io::Error>;
}
pub trait ProtectReadWrite<A: Zeroize + MutBytes + Default, PM: ProtectMode, LM: LockMode> {
    fn mprotect_readwrite(self) -> Result<Protected<A, ReadWrite, LM>, std::io::Error>;
}
pub trait ProtectNoAccess<A: Zeroize + MutBytes + Default, PM: ProtectMode> {
    fn mprotect_noaccess(self) -> Result<Protected<A, NoAccess, Unlocked>, std::io::Error>;
}

mod int {
    #[derive(Clone, Debug, PartialEq)]
    pub(super) enum LockMode {
        Locked,
        Unlocked,
    }

    #[derive(Clone, Debug, PartialEq)]
    pub(super) enum ProtectMode {
        ReadOnly,
        ReadWrite,
        NoAccess,
    }
}

/// Holds a protected region of memory. Does not implement traits such as [Copy],
/// [Clone], or [std::fmt::Debug].
pub struct Protected<A: Zeroize + MutBytes + Default, PM: ProtectMode, LM: LockMode> {
    a: A,
    p: PhantomData<PM>,
    l: PhantomData<LM>,
    lm: int::LockMode,
    pm: int::ProtectMode,
}

fn dryoc_mlock(data: &mut [u8]) -> Result<(), std::io::Error> {
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

fn dryoc_munlock(data: &mut [u8]) -> Result<(), std::io::Error> {
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

fn dryoc_mprotect_readonly(data: &mut [u8]) -> Result<(), std::io::Error> {
    #[cfg(unix)]
    {
        use libc::{c_void, mprotect as c_mprotect, PROT_READ};
        let ret =
            unsafe { c_mprotect(data.as_mut_ptr() as *mut c_void, data.len() - 1, PROT_READ) };
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

fn dryoc_mprotect_readwrite(data: &mut [u8]) -> Result<(), std::io::Error> {
    #[cfg(unix)]
    {
        use libc::{c_void, mprotect as c_mprotect, PROT_READ, PROT_WRITE};
        let ret = unsafe {
            c_mprotect(
                data.as_mut_ptr() as *mut c_void,
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

fn dryoc_mprotect_noaccess(data: &mut [u8]) -> Result<(), std::io::Error> {
    #[cfg(unix)]
    {
        use libc::{c_void, mprotect as c_mprotect, PROT_NONE};
        let ret =
            unsafe { c_mprotect(data.as_mut_ptr() as *mut c_void, data.len() - 1, PROT_NONE) };
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

impl<A: Zeroize + MutBytes + Default, PM: ProtectMode, LM: LockMode> Unlock<A, PM>
    for Protected<A, PM, LM>
{
    fn munlock(mut self) -> Result<Protected<A, PM, Unlocked>, std::io::Error> {
        let mut new = Protected::<A, PM, Unlocked> {
            a: A::default(),
            p: PhantomData,
            l: PhantomData,
            lm: int::LockMode::Unlocked,
            pm: self.pm.clone(),
        };
        dryoc_munlock(self.a.as_mut_slice())?;
        // swap into new struct
        std::mem::swap(&mut new.a, &mut self.a);
        // memory in old (swapped) array is unlocked & RW
        self.lm = int::LockMode::Unlocked;
        self.pm = int::ProtectMode::ReadWrite;
        Ok(new)
    }
}

impl<A: Zeroize + MutBytes + Default, PM: ProtectMode> Lock<A, PM> for Protected<A, PM, Unlocked> {
    fn mlock(mut self) -> Result<Protected<A, PM, Locked>, std::io::Error> {
        let mut new = Protected::<A, PM, Locked> {
            a: A::default(),
            p: PhantomData,
            l: PhantomData,
            lm: int::LockMode::Locked,
            pm: self.pm.clone(),
        };
        dryoc_mlock(self.a.as_mut_slice())?;
        // swap into new struct
        std::mem::swap(&mut new.a, &mut self.a);
        // memory in old (swapped) array is unlocked & RW
        self.lm = int::LockMode::Unlocked;
        self.pm = int::ProtectMode::ReadWrite;
        Ok(new)
    }
}

impl<A: Zeroize + MutBytes + Default, PM: ProtectMode, LM: LockMode> ProtectReadOnly<A, PM, LM>
    for Protected<A, PM, LM>
{
    fn mprotect_readonly(mut self) -> Result<Protected<A, ReadOnly, LM>, std::io::Error> {
        let mut new = Protected::<A, ReadOnly, LM> {
            a: A::default(),
            p: PhantomData,
            l: PhantomData,
            lm: self.lm.clone(),
            pm: int::ProtectMode::ReadOnly,
        };
        dryoc_mprotect_readonly(self.a.as_mut_slice())?;
        // swap into new struct
        std::mem::swap(&mut new.a, &mut self.a);
        // memory in old (swapped) array is unlocked & RW
        self.lm = int::LockMode::Unlocked;
        self.pm = int::ProtectMode::ReadWrite;
        Ok(new)
    }
}

impl<A: Zeroize + MutBytes + Default, PM: ProtectMode, LM: LockMode> ProtectReadWrite<A, PM, LM>
    for Protected<A, PM, LM>
{
    fn mprotect_readwrite(mut self) -> Result<Protected<A, ReadWrite, LM>, std::io::Error> {
        let mut new = Protected::<A, ReadWrite, LM> {
            a: A::default(),
            p: PhantomData,
            l: PhantomData,
            lm: self.lm.clone(),
            pm: int::ProtectMode::ReadWrite,
        };
        dryoc_mprotect_readwrite(self.a.as_mut_slice())?;
        // swap into new struct
        std::mem::swap(&mut new.a, &mut self.a);
        // memory in old (swapped) array is unlocked & RW
        self.lm = int::LockMode::Unlocked;
        self.pm = int::ProtectMode::ReadWrite;
        Ok(new)
    }
}

impl<A: Zeroize + MutBytes + Default, PM: ProtectMode> ProtectNoAccess<A, PM>
    for Protected<A, PM, Unlocked>
{
    fn mprotect_noaccess(mut self) -> Result<Protected<A, NoAccess, Unlocked>, std::io::Error> {
        let mut new = Protected::<A, NoAccess, Unlocked> {
            a: A::default(),
            p: PhantomData,
            l: PhantomData,
            lm: self.lm.clone(),
            pm: int::ProtectMode::NoAccess,
        };
        dryoc_mprotect_noaccess(self.a.as_mut_slice())?;
        // swap into new struct
        std::mem::swap(&mut new.a, &mut self.a);
        // memory in old (swapped) array is unlocked & RW
        self.lm = int::LockMode::Unlocked;
        self.pm = int::ProtectMode::ReadWrite;
        Ok(new)
    }
}

impl<A: Zeroize + MutBytes + Default, PM: ProtectMode, LM: LockMode> AsRef<[u8]>
    for Protected<A, PM, LM>
{
    fn as_ref(&self) -> &[u8] {
        self.a.as_ref()
    }
}

impl<A: Zeroize + MutBytes + Default, PM: ProtectMode, LM: LockMode> AsMut<[u8]>
    for Protected<A, PM, LM>
{
    fn as_mut(&mut self) -> &mut [u8] {
        self.a.as_mut()
    }
}

impl<A: Zeroize + MutBytes + Default, LM: LockMode> Bytes for Protected<A, ReadOnly, LM> {
    fn as_slice(&self) -> &[u8] {
        self.a.as_slice()
    }
}

impl<A: Zeroize + MutBytes + Default, LM: LockMode> Bytes for Protected<A, ReadWrite, LM> {
    fn as_slice(&self) -> &[u8] {
        self.a.as_slice()
    }
}

impl Default for Protected<HeapBytes, ReadWrite, Locked> {
    fn default() -> Self {
        HeapBytes::new_locked().expect("mlock failed in default")
    }
}

impl<const LENGTH: usize> From<StackByteArray<LENGTH>> for HeapByteArray<LENGTH> {
    fn from(other: StackByteArray<LENGTH>) -> Self {
        let mut r = HeapByteArray::<LENGTH>::default();
        let mut s = other;
        r.copy_from_slice(s.as_slice());
        s.zeroize();
        r
    }
}

impl<const LENGTH: usize> StackByteArray<LENGTH> {
    /// Locks a [StackByteArray], consuming it, and returning a [Protected] wrapper.
    pub fn mlock(
        self,
    ) -> Result<Protected<HeapByteArray<LENGTH>, ReadWrite, Locked>, std::io::Error> {
        let protected = Protected::<HeapByteArray<LENGTH>, ReadWrite, Unlocked> {
            a: self.into(),
            p: PhantomData,
            l: PhantomData,
            lm: int::LockMode::Unlocked,
            pm: int::ProtectMode::ReadWrite,
        };
        protected.mlock()
    }
}

impl<const LENGTH: usize> StackByteArray<LENGTH> {
    /// Locks a [StackByteArray], consuming it, and returning a [Protected] wrapper.
    pub fn mprotect_readonly(
        self,
    ) -> Result<Protected<HeapByteArray<LENGTH>, ReadOnly, Locked>, std::io::Error> {
        let protected = Protected::<HeapByteArray<LENGTH>, ReadWrite, Unlocked> {
            a: self.into(),
            p: PhantomData,
            l: PhantomData,
            lm: int::LockMode::Unlocked,
            pm: int::ProtectMode::ReadWrite,
        };
        protected.mlock().and_then(|p| p.mprotect_readonly())
    }
}

impl<const LENGTH: usize> Lockable<HeapByteArray<LENGTH>> for HeapByteArray<LENGTH> {
    /// Locks a [HeapByteArray], and returns a [Protected] wrapper.
    fn mlock(self) -> Result<Protected<HeapByteArray<LENGTH>, ReadWrite, Locked>, std::io::Error> {
        let protected = Protected::<HeapByteArray<LENGTH>, ReadWrite, Unlocked> {
            a: self,
            p: PhantomData,
            l: PhantomData,
            lm: int::LockMode::Unlocked,
            pm: int::ProtectMode::ReadWrite,
        };
        protected.mlock()
    }
}

impl Lockable<HeapBytes> for HeapBytes {
    /// Locks a [HeapBytes], and returns a [Protected] wrapper.
    fn mlock(self) -> Result<Protected<HeapBytes, ReadWrite, Locked>, std::io::Error> {
        let protected = Protected::<HeapBytes, ReadWrite, Unlocked> {
            a: self,
            p: PhantomData,
            l: PhantomData,
            lm: int::LockMode::Unlocked,
            pm: int::ProtectMode::ReadWrite,
        };
        protected.mlock()
    }
}

#[derive(Clone)]
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
            let ret = unsafe { posix_memalign(&mut out, pagesize as usize, size) };
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
                (out.offset(aft_protected_region_offset as isize)) as *mut u8,
                pagesize,
            )
        };
        dryoc_mprotect_noaccess(aft_protected_region)
            .map_err(|err| eprintln!("mprotect error = {:?}, in allocator", err))
            .ok();

        let slice = unsafe {
            std::slice::from_raw_parts_mut(out.offset(pagesize as isize) as *mut u8, layout.size())
        };

        unsafe { Ok(ptr::NonNull::new_unchecked(slice)) }
    }
    #[inline]
    unsafe fn deallocate(&self, ptr: ptr::NonNull<u8>, layout: Layout) {
        let pagesize = *PAGESIZE;

        let ptr = ptr.as_ptr().offset(-(pagesize as isize));

        // unlock the fore protected region
        let fore_protected_region = std::slice::from_raw_parts_mut(ptr as *mut u8, pagesize);
        dryoc_mprotect_readwrite(fore_protected_region)
            .map_err(|err| eprintln!("mprotect error = {:?}", err))
            .ok();

        // unlock the aft protected region
        let aft_protected_region_offset = pagesize + _page_round(layout.size(), pagesize);
        let aft_protected_region = std::slice::from_raw_parts_mut(
            (ptr.offset(aft_protected_region_offset as isize)) as *mut u8,
            pagesize,
        );

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
/// protected memory regions. Wraps a [Vec] with custom [Allocator]
/// implementation.
#[derive(Zeroize, Debug, PartialEq, Clone)]
#[zeroize(drop)]
pub struct HeapByteArray<const LENGTH: usize>(Vec<u8, PageAlignedAllocator>);

/// A heap-allocated resizable byte array, using the
/// [page-aligned allocator](PageAlignedAllocator). Required for working with
/// protected memory regions. Wraps a [Vec] with custom [Allocator]
/// implementation.
#[derive(Zeroize, Debug, PartialEq, Clone)]
#[zeroize(drop)]
pub struct HeapBytes(Vec<u8, PageAlignedAllocator>);

pub type LockedBytes = Protected<HeapBytes, ReadWrite, Locked>;
pub type LockedReadOnlyBytes = Protected<HeapBytes, ReadOnly, Locked>;
pub type LockedNoAccessBytes = Protected<HeapBytes, NoAccess, Locked>;

impl<const LENGTH: usize> NewByteArray<LENGTH> for HeapByteArray<LENGTH> {
    /// Returns a new byte array filled with random data.
    fn gen() -> Self {
        let mut res = Self::default();
        copy_randombytes(&mut res.0);
        res
    }
    /// Returns a new byte array from `other`. Panics if sizes do not match.
    fn from_slice(other: &[u8]) -> Self {
        let mut res = Self::default();
        res.copy_from_slice(other);
        res
    }
}

pub trait NewLocked<A: Zeroize + MutBytes + Default + Lockable<A>> {
    fn new_locked() -> Result<Protected<A, ReadWrite, Locked>, std::io::Error>;
    fn gen_locked() -> Result<Protected<A, ReadWrite, Locked>, std::io::Error>;
    fn from_slice_locked(other: &[u8]) -> Result<Protected<A, ReadWrite, Locked>, std::io::Error>;
}

impl<A: Zeroize + MutBytes + Default + Lockable<A>> NewLocked<A> for A {
    /// Returns a new locked byte array.
    fn new_locked() -> Result<Protected<Self, ReadWrite, Locked>, std::io::Error> {
        Self::default().mlock()
    }
    /// Returns a new locked byte array filled with random data.
    fn gen_locked() -> Result<Protected<Self, ReadWrite, Locked>, std::io::Error> {
        let mut res = Self::default().mlock()?;
        copy_randombytes(res.as_mut_slice());
        Ok(res)
    }
    /// Returns a new locked byte array from `other`. Panics if sizes do not match.
    fn from_slice_locked(
        other: &[u8],
    ) -> Result<Protected<Self, ReadWrite, Locked>, std::io::Error> {
        let mut res = Self::default().mlock()?;
        res.as_mut_slice().copy_from_slice(other);
        Ok(res)
    }
}

impl<const LENGTH: usize> Bytes for HeapByteArray<LENGTH> {
    fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl Bytes for HeapBytes {
    fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl<const LENGTH: usize> MutBytes for HeapByteArray<LENGTH> {
    fn as_mut_slice(&mut self) -> &mut [u8] {
        self.0.as_mut_slice()
    }
}

impl MutBytes for HeapBytes {
    fn as_mut_slice(&mut self) -> &mut [u8] {
        self.0.as_mut_slice()
    }
}

impl ResizableBytes for HeapBytes {
    fn resize(&mut self, new_len: usize, value: u8) {
        self.0.resize(new_len, value);
    }
}

impl<A: Zeroize + MutBytes + Default + ResizableBytes + Lockable<A>> ResizableBytes
    for Protected<A, ReadWrite, Locked>
{
    fn resize(&mut self, new_len: usize, value: u8) {
        // because it's locked, we'll do a swaparoo here instead of a plain resize
        let mut new = A::new_locked().expect("resize failed");
        new.a.resize(new_len, value);
        let len_to_copy = std::cmp::min(new_len, self.a.as_slice().len());
        new.a.as_mut_slice()[..len_to_copy].copy_from_slice(&self.as_slice()[..len_to_copy]);
        std::mem::swap(&mut new.a, &mut self.a);
    }
}

impl<A: Zeroize + MutBytes + Default + ResizableBytes + Lockable<A>> ResizableBytes
    for Protected<A, ReadWrite, Unlocked>
{
    fn resize(&mut self, new_len: usize, value: u8) {
        self.a.resize(new_len, value);
    }
}

impl<A: Zeroize + MutBytes + Default, LM: LockMode> MutBytes for Protected<A, ReadWrite, LM> {
    fn as_mut_slice(&mut self) -> &mut [u8] {
        self.a.as_mut_slice()
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

macro_rules! impl_index {
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

impl_index!(std::ops::Range<usize>);
impl_index!(std::ops::RangeFull);
impl_index!(std::ops::RangeFrom<usize>);
impl_index!(std::ops::RangeInclusive<usize>);
impl_index!(std::ops::RangeTo<usize>);
impl_index!(std::ops::RangeToInclusive<usize>);

impl<const LENGTH: usize> Default for HeapByteArray<LENGTH> {
    fn default() -> Self {
        let mut v = Vec::new_in(PageAlignedAllocator);
        v.resize(LENGTH, 0);
        Self(v)
    }
}

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
    fn from(src: [u8; LENGTH]) -> Self {
        Self::from(&src)
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

impl<const LENGTH: usize> ByteArray<LENGTH> for HeapByteArray<LENGTH> {
    fn as_array(&self) -> &[u8; LENGTH] {
        // this is safe for fixed-length arrays
        let ptr = self.0.as_ptr() as *const [u8; LENGTH];
        unsafe { &*ptr }
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
    for Protected<HeapByteArray<LENGTH>, ReadOnly, Unlocked>
{
    fn as_array(&self) -> &[u8; LENGTH] {
        self.a.as_array()
    }
}

impl<const LENGTH: usize> ByteArray<LENGTH> for Protected<HeapByteArray<LENGTH>, ReadOnly, Locked> {
    fn as_array(&self) -> &[u8; LENGTH] {
        self.a.as_array()
    }
}

impl<const LENGTH: usize> ByteArray<LENGTH>
    for Protected<HeapByteArray<LENGTH>, ReadWrite, Unlocked>
{
    fn as_array(&self) -> &[u8; LENGTH] {
        self.a.as_array()
    }
}

impl<const LENGTH: usize> ByteArray<LENGTH>
    for Protected<HeapByteArray<LENGTH>, ReadWrite, Locked>
{
    fn as_array(&self) -> &[u8; LENGTH] {
        self.a.as_array()
    }
}

impl<const LENGTH: usize> MutByteArray<LENGTH>
    for Protected<HeapByteArray<LENGTH>, ReadWrite, Locked>
{
    fn as_mut_array(&mut self) -> &mut [u8; LENGTH] {
        self.a.as_mut_array()
    }
}

impl<const LENGTH: usize> MutByteArray<LENGTH>
    for Protected<HeapByteArray<LENGTH>, ReadWrite, Unlocked>
{
    fn as_mut_array(&mut self) -> &mut [u8; LENGTH] {
        self.a.as_mut_array()
    }
}

impl<const LENGTH: usize> AsMut<[u8; LENGTH]>
    for Protected<HeapByteArray<LENGTH>, ReadWrite, Locked>
{
    fn as_mut(&mut self) -> &mut [u8; LENGTH] {
        self.a.as_mut()
    }
}

impl<const LENGTH: usize> AsMut<[u8; LENGTH]>
    for Protected<HeapByteArray<LENGTH>, ReadWrite, Unlocked>
{
    fn as_mut(&mut self) -> &mut [u8; LENGTH] {
        self.a.as_mut()
    }
}

impl<A: Zeroize + MutBytes + Default, PM: ProtectMode, LM: LockMode> Drop for Protected<A, PM, LM> {
    fn drop(&mut self) {
        if self.a.as_slice().len() > 0 {
            if self.pm != int::ProtectMode::ReadWrite {
                dryoc_mprotect_readwrite(self.a.as_mut_slice())
                    .map_err(|err| eprintln!("mprotect_readwrite error on drop = {:?}", err))
                    .ok();
            }
            self.a.zeroize();
            if self.lm == int::LockMode::Locked {
                dryoc_munlock(self.a.as_mut_slice())
                    .map_err(|err| eprintln!("dryoc_munlock error on drop = {:?}", err))
                    .ok();
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

        vec.resize(5, 0);

        assert_eq!([1, 2, 3, 0, 0], vec.as_slice());
    }
}
