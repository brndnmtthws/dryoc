/*!
# Memory protection utilities

Provides access to the memory locking system calls, such as `mlock()` and
`mprotect()` on UNIX-like systems, `VirtualLock()` and `VirtualProtect()` on
Windows. Similar to libsodium's `sodium_mlock` and `sodium_mprotect_*`
functions.
 */
use crate::error;
use crate::rng::copy_randombytes;
use crate::types::*;

#[cfg(all(feature = "serde", feature = "base64"))]
use crate::bytes_serde::*;

use libc::c_void;
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
pub trait Unlock<A: Zeroize + MutBytes + Default, PM: ProtectMode> {
    fn munlock(self) -> Result<Protected<A, PM, Unlocked>, std::io::Error>;
}

pub trait ProtectReadOnly<A: Zeroize + MutBytes + Default, PM: ProtectMode, LM: LockMode> {
    fn mprotect_readonly(self) -> Result<Protected<A, ReadOnly, LM>, std::io::Error>;
}
pub trait ProtectReadWrite<A: Zeroize + MutBytes + Default, PM: ProtectMode, LM: LockMode> {
    fn mprotect_readwrite(self) -> Result<Protected<A, ReadWrite, LM>, std::io::Error>;
}
pub trait ProtectNoAccess<A: Zeroize + MutBytes + Default, PM: ProtectMode, LM: LockMode> {
    fn mprotect_noaccess(self) -> Result<Protected<A, NoAccess, LM>, std::io::Error>;
}

/// Holds a protected region of memory. Does not implement traits such as [Copy],
/// [Clone], or [std::fmt::Debug].
pub struct Protected<A: Zeroize + MutBytes + Default, PM: ProtectMode, LM: LockMode> {
    a: A,
    p: PhantomData<PM>,
    l: PhantomData<LM>,
}

fn dryoc_mlock(data: &[u8]) -> Result<(), std::io::Error> {
    use libc::mlock;
    let ret = unsafe { mlock(data.as_ptr() as *const c_void, data.len()) };
    if ret == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn dryoc_munlock(data: &[u8]) -> Result<(), std::io::Error> {
    use libc::munlock;
    let ret = unsafe { munlock(data.as_ptr() as *const c_void, data.len()) };
    if ret == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn dryoc_mprotect_readonly(data: &mut [u8]) -> Result<(), std::io::Error> {
    use libc::mprotect;
    use libc::PROT_READ;
    let ret = unsafe { mprotect(data.as_mut_ptr() as *mut c_void, data.len(), PROT_READ) };
    if ret == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn dryoc_mprotect_readwrite(data: &mut [u8]) -> Result<(), std::io::Error> {
    use libc::mprotect;
    use libc::{PROT_READ, PROT_WRITE};
    let ret = unsafe {
        mprotect(
            data.as_mut_ptr() as *mut c_void,
            data.len(),
            PROT_READ | PROT_WRITE,
        )
    };
    if ret == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn dryoc_mprotect_noaccess(data: &mut [u8]) -> Result<(), std::io::Error> {
    use libc::mprotect;
    use libc::PROT_NONE;
    let ret = unsafe { mprotect(data.as_mut_ptr() as *mut c_void, data.len(), PROT_NONE) };
    if ret == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
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
        };
        dryoc_munlock(self.a.as_slice())?;
        // swap into new struct
        std::mem::swap(&mut new.a, &mut self.a);
        Ok(new)
    }
}

impl<A: Zeroize + MutBytes + Default, PM: ProtectMode> Lock<A, PM> for Protected<A, PM, Unlocked> {
    fn mlock(mut self) -> Result<Protected<A, PM, Locked>, std::io::Error> {
        let mut new = Protected::<A, PM, Locked> {
            a: A::default(),
            p: PhantomData,
            l: PhantomData,
        };
        dryoc_mlock(self.a.as_slice())?;
        // swap into new struct
        std::mem::swap(&mut new.a, &mut self.a);
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
        };
        dryoc_mprotect_readonly(self.a.as_mut_slice())?;
        // swap into new struct
        std::mem::swap(&mut new.a, &mut self.a);
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
        };
        dryoc_mprotect_readwrite(self.a.as_mut_slice())?;
        // swap into new struct
        std::mem::swap(&mut new.a, &mut self.a);
        Ok(new)
    }
}

impl<A: Zeroize + MutBytes + Default, PM: ProtectMode, LM: LockMode> ProtectNoAccess<A, PM, LM>
    for Protected<A, PM, LM>
{
    fn mprotect_noaccess(mut self) -> Result<Protected<A, NoAccess, LM>, std::io::Error> {
        let mut new = Protected::<A, NoAccess, LM> {
            a: A::default(),
            p: PhantomData,
            l: PhantomData,
        };
        dryoc_mprotect_noaccess(self.a.as_mut_slice())?;
        // swap into new struct
        std::mem::swap(&mut new.a, &mut self.a);
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

impl<const LENGTH: usize> From<StackByteArray<LENGTH>> for ProtectedByteArray<LENGTH> {
    fn from(other: StackByteArray<LENGTH>) -> Self {
        let mut r = ProtectedByteArray::<LENGTH>::default();
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
    ) -> Result<Protected<ProtectedByteArray<LENGTH>, ReadWrite, Locked>, std::io::Error> {
        let protected = Protected::<ProtectedByteArray<LENGTH>, ReadWrite, Unlocked> {
            a: self.into(),
            p: PhantomData,
            l: PhantomData,
        };
        protected.mlock()
    }
}

impl<const LENGTH: usize> StackByteArray<LENGTH> {
    /// Locks a [StackByteArray], consuming it, and returning a [Protected] wrapper.
    pub fn mprotect_readonly(
        self,
    ) -> Result<Protected<ProtectedByteArray<LENGTH>, ReadOnly, Locked>, std::io::Error> {
        let protected = Protected::<ProtectedByteArray<LENGTH>, ReadWrite, Unlocked> {
            a: self.into(),
            p: PhantomData,
            l: PhantomData,
        };
        protected.mlock().and_then(|p| p.mprotect_readonly())
    }
}

impl<const LENGTH: usize> ProtectedByteArray<LENGTH> {
    /// Locks a [ProtectedByteArray], and returns a [Protected] wrapper.
    pub fn mlock(
        self,
    ) -> Result<Protected<ProtectedByteArray<LENGTH>, ReadWrite, Locked>, std::io::Error> {
        let protected = Protected::<ProtectedByteArray<LENGTH>, ReadWrite, Unlocked> {
            a: self,
            p: PhantomData,
            l: PhantomData,
        };
        protected.mlock()
    }
}

#[derive(Clone)]
pub struct PageAlignedAllocator;

unsafe impl Allocator for PageAlignedAllocator {
    #[inline]
    fn allocate(&self, layout: Layout) -> Result<ptr::NonNull<[u8]>, AllocError> {
        use libc::{posix_memalign, sysconf, _SC_PAGE_SIZE};
        let pagesize = unsafe { sysconf(_SC_PAGE_SIZE) } as usize;
        let mut out = ptr::null_mut();
        // allocate full pages, in addition to an extra page at the end which will remain locked
        let size = layout.size() + (pagesize - layout.size() % pagesize) + pagesize;
        let ret = unsafe { posix_memalign(&mut out, pagesize as usize, size) };
        if ret != 0 {
            Err(AllocError)
        } else {
            let slice = unsafe { std::slice::from_raw_parts_mut(out as *mut u8, layout.size()) };
            // lock the page at the end of the region
            let protected_region_start = layout.size() + (pagesize - layout.size() % pagesize);
            let protected_region = unsafe {
                std::slice::from_raw_parts_mut(
                    (out.offset(protected_region_start as isize)) as *mut u8,
                    pagesize,
                )
            };
            dryoc_mlock(protected_region)
                .map_err(|err| eprintln!("mlock error = {:?}", err))
                .ok();
            dryoc_mprotect_noaccess(protected_region)
                .map_err(|err| eprintln!("mprotect error = {:?}", err))
                .ok();
            unsafe { Ok(ptr::NonNull::new_unchecked(slice)) }
        }
    }
    #[inline]
    unsafe fn deallocate(&self, ptr: ptr::NonNull<u8>, layout: Layout) {
        use libc::{sysconf, _SC_PAGE_SIZE};
        let pagesize = sysconf(_SC_PAGE_SIZE) as usize;
        // unlock the protected region
        let protected_region_start = layout.size() + (pagesize - layout.size() % pagesize);
        let protected_region = std::slice::from_raw_parts_mut(
            (ptr.as_ptr().offset(protected_region_start as isize)) as *mut u8,
            pagesize,
        );
        dryoc_munlock(protected_region)
            .map_err(|err| eprintln!("mlock error = {:?}", err))
            .ok();
        dryoc_mprotect_readwrite(protected_region)
            .map_err(|err| eprintln!("mprotect error = {:?}", err))
            .ok();

        libc::free(ptr.as_ptr() as *mut libc::c_void)
    }
}

/// A heap allocated fixed-length byte array for working with protected memory
/// regions, with optional [Serde](https://serde.rs) features.
#[derive(Zeroize, Debug, PartialEq, Clone)]
#[zeroize(drop)]
pub struct ProtectedByteArray<const LENGTH: usize>(Vec<u8, PageAlignedAllocator>);

/// A heap allocated fixed-length byte array for working with protected memory
/// regions, with optional [Serde](https://serde.rs) features.
#[derive(Zeroize, Debug, PartialEq, Clone)]
#[zeroize(drop)]
pub struct ProtectedBytes(Vec<u8, PageAlignedAllocator>);

impl<const LENGTH: usize> NewByteArray<LENGTH> for ProtectedByteArray<LENGTH> {
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

impl<const LENGTH: usize> ProtectedByteArray<LENGTH> {
    /// Returns a new byte array filled with random data.
    pub fn gen_locked(
    ) -> Result<Protected<ProtectedByteArray<LENGTH>, ReadWrite, Locked>, std::io::Error> {
        let mut res = Self::default().mlock()?;
        copy_randombytes(res.as_mut_slice());
        Ok(res)
    }
    /// Returns a new byte array from `other`. Panics if sizes do not match.
    pub fn from_slice_locked(
        other: &[u8],
    ) -> Result<Protected<ProtectedByteArray<LENGTH>, ReadWrite, Locked>, std::io::Error> {
        let mut res = Self::default().mlock()?;
        res.as_mut_array().copy_from_slice(other);
        Ok(res)
    }
}

impl<const LENGTH: usize> Bytes for ProtectedByteArray<LENGTH> {
    fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl<const LENGTH: usize> MutBytes for ProtectedByteArray<LENGTH> {
    fn as_mut_slice(&mut self) -> &mut [u8] {
        self.0.as_mut_slice()
    }
}

impl<A: Zeroize + MutBytes + Default, LM: LockMode> MutBytes for Protected<A, ReadWrite, LM> {
    fn as_mut_slice(&mut self) -> &mut [u8] {
        self.a.as_mut_slice()
    }
}

impl<const LENGTH: usize> ProtectedByteArray<LENGTH> {}

impl<const LENGTH: usize> std::convert::AsRef<[u8; LENGTH]> for ProtectedByteArray<LENGTH> {
    fn as_ref(&self) -> &[u8; LENGTH] {
        let arr = self.0.as_ptr() as *const [u8; LENGTH];
        unsafe { &*arr }
    }
}

impl<const LENGTH: usize> std::convert::AsMut<[u8; LENGTH]> for ProtectedByteArray<LENGTH> {
    fn as_mut(&mut self) -> &mut [u8; LENGTH] {
        let arr = self.0.as_mut_ptr() as *mut [u8; LENGTH];
        unsafe { &mut *arr }
    }
}

impl<const LENGTH: usize> std::convert::AsRef<[u8]> for ProtectedByteArray<LENGTH> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<const LENGTH: usize> std::convert::AsMut<[u8]> for ProtectedByteArray<LENGTH> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

impl<const LENGTH: usize> std::ops::Deref for ProtectedByteArray<LENGTH> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const LENGTH: usize> std::ops::DerefMut for ProtectedByteArray<LENGTH> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<const LENGTH: usize> std::ops::Index<usize> for ProtectedByteArray<LENGTH> {
    type Output = u8;
    #[inline]
    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}
impl<const LENGTH: usize> std::ops::IndexMut<usize> for ProtectedByteArray<LENGTH> {
    #[inline]
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index]
    }
}

macro_rules! impl_index {
    ($range:ty) => {
        impl<const LENGTH: usize> std::ops::Index<$range> for ProtectedByteArray<LENGTH> {
            type Output = [u8];
            #[inline]
            fn index(&self, index: $range) -> &Self::Output {
                &self.0[index]
            }
        }
        impl<const LENGTH: usize> std::ops::IndexMut<$range> for ProtectedByteArray<LENGTH> {
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

impl<const LENGTH: usize> Default for ProtectedByteArray<LENGTH> {
    fn default() -> Self {
        let mut v = Vec::new_in(PageAlignedAllocator);
        v.resize(LENGTH, 0);
        Self(v)
    }
}

impl<const LENGTH: usize> From<&[u8; LENGTH]> for ProtectedByteArray<LENGTH> {
    fn from(src: &[u8; LENGTH]) -> Self {
        let mut arr = Self::default();
        arr.0.copy_from_slice(src);
        arr
    }
}

impl<const LENGTH: usize> From<[u8; LENGTH]> for ProtectedByteArray<LENGTH> {
    fn from(src: [u8; LENGTH]) -> Self {
        Self::from(&src)
    }
}

impl<const LENGTH: usize> TryFrom<&[u8]> for ProtectedByteArray<LENGTH> {
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

impl<const LENGTH: usize> ByteArray<LENGTH> for ProtectedByteArray<LENGTH> {
    fn as_array(&self) -> &[u8; LENGTH] {
        // this is safe for fixed-length arrays
        let ptr = self.0.as_ptr() as *const [u8; LENGTH];
        unsafe { &*ptr }
    }
}

impl<const LENGTH: usize> MutByteArray<LENGTH> for ProtectedByteArray<LENGTH> {
    fn as_mut_array(&mut self) -> &mut [u8; LENGTH] {
        // this is safe for fixed-length arrays
        let ptr = self.0.as_ptr() as *mut [u8; LENGTH];
        unsafe { &mut *ptr }
    }
}

impl<const LENGTH: usize> ByteArray<LENGTH>
    for Protected<ProtectedByteArray<LENGTH>, ReadOnly, Unlocked>
{
    fn as_array(&self) -> &[u8; LENGTH] {
        self.a.as_array()
    }
}

impl<const LENGTH: usize> ByteArray<LENGTH>
    for Protected<ProtectedByteArray<LENGTH>, ReadOnly, Locked>
{
    fn as_array(&self) -> &[u8; LENGTH] {
        self.a.as_array()
    }
}

impl<const LENGTH: usize> ByteArray<LENGTH>
    for Protected<ProtectedByteArray<LENGTH>, ReadWrite, Unlocked>
{
    fn as_array(&self) -> &[u8; LENGTH] {
        self.a.as_array()
    }
}

impl<const LENGTH: usize> ByteArray<LENGTH>
    for Protected<ProtectedByteArray<LENGTH>, ReadWrite, Locked>
{
    fn as_array(&self) -> &[u8; LENGTH] {
        self.a.as_array()
    }
}

impl<const LENGTH: usize> MutByteArray<LENGTH>
    for Protected<ProtectedByteArray<LENGTH>, ReadWrite, Locked>
{
    fn as_mut_array(&mut self) -> &mut [u8; LENGTH] {
        self.a.as_mut_array()
    }
}

impl<const LENGTH: usize> MutByteArray<LENGTH>
    for Protected<ProtectedByteArray<LENGTH>, ReadWrite, Unlocked>
{
    fn as_mut_array(&mut self) -> &mut [u8; LENGTH] {
        self.a.as_mut_array()
    }
}

impl<const LENGTH: usize> AsMut<[u8; LENGTH]>
    for Protected<ProtectedByteArray<LENGTH>, ReadWrite, Locked>
{
    fn as_mut(&mut self) -> &mut [u8; LENGTH] {
        self.a.as_mut()
    }
}

impl<const LENGTH: usize> AsMut<[u8; LENGTH]>
    for Protected<ProtectedByteArray<LENGTH>, ReadWrite, Unlocked>
{
    fn as_mut(&mut self) -> &mut [u8; LENGTH] {
        self.a.as_mut()
    }
}

impl<A: Zeroize + MutBytes + Default, PM: ProtectMode, LM: LockMode> Drop for Protected<A, PM, LM> {
    fn drop(&mut self) {
        dryoc_mprotect_readwrite(self.a.as_mut_slice())
            .map_err(|err| eprintln!("mprotect_readwrite error on drop = {:?}", err))
            .ok();
        self.a.zeroize();
        dryoc_munlock(self.a.as_slice())
            .map_err(|err| eprintln!("dryoc_munlock error on drop = {:?}", err))
            .ok();
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
