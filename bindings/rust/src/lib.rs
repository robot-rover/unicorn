//! Bindings for the Unicorn emulator.
//!
//!
//!
//! # Example use
//!
//! ```rust
//!
//! use unicorn_engine::RegisterARM;
//! use unicorn_engine::unicorn_const::{Arch, Mode, Permission, SECOND_SCALE};
//!
//! fn emulate() {
//!     let arm_code32 = [0x17, 0x00, 0x40, 0xe2]; // sub r0, #23
//!
//!     let mut emu = unicorn_engine::Unicorn::new(Arch::ARM, Mode::LITTLE_ENDIAN).expect("failed to initialize Unicorn instance");
//!     emu.mem_map(0x1000, 0x4000, Permission::ALL).expect("failed to map code page");
//!     emu.mem_write(0x1000, &arm_code32).expect("failed to write instructions");
//!
//!     emu.reg_write(RegisterARM::R0, 123).expect("failed write R0");
//!     emu.reg_write(RegisterARM::R5, 1337).expect("failed write R5");
//!
//!     emu.emu_start(0x1000, (0x1000 + arm_code32.len()) as u64, 10 * SECOND_SCALE, 1000).unwrap();
//!     assert_eq!(emu.reg_read(RegisterARM::R0), Ok(100));
//!     assert_eq!(emu.reg_read(RegisterARM::R5), Ok(1337));
//! }
//! ```
//!

#![no_std]

#[macro_use]
extern crate alloc;
extern crate std;

use alloc::boxed::Box;
use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::ptr;

use libc::c_void;

use ffi::uc_handle;

#[macro_use]
pub mod unicorn_const;
pub use unicorn_const::*;
pub mod ffi; // lets consumers call ffi if desired

// include arm support if conditionally compiled in
#[cfg(feature = "arch_arm")]
mod arm;
#[cfg(feature = "arch_arm")]
pub use crate::arm::*;

// include arm64 support if conditionally compiled in
// NOTE: unicorn-c only separates on top-level arch name,
//       not on the bit-length, so we include both
#[cfg(feature = "arch_arm")]
mod arm64;
#[cfg(feature = "arch_arm")]
pub use crate::arm64::*;

// include m68k support if conditionally compiled in
#[cfg(feature = "arch_m68k")]
mod m68k;
#[cfg(feature = "arch_m68k")]
pub use crate::m68k::*;

// include mips support if conditionally compiled in
#[cfg(feature = "arch_mips")]
mod mips;
#[cfg(feature = "arch_mips")]
pub use crate::mips::*;

// include ppc support if conditionally compiled in
#[cfg(feature = "arch_ppc")]
mod ppc;
#[cfg(feature = "arch_ppc")]
pub use crate::ppc::*;

// include riscv support if conditionally compiled in
#[cfg(feature = "arch_riscv")]
mod riscv;
#[cfg(feature = "arch_riscv")]
pub use crate::riscv::*;

// include s390x support if conditionally compiled in
#[cfg(feature = "arch_s390x")]
mod s390x;
#[cfg(feature = "arch_s390x")]
pub use crate::s390x::*;

// include sparc support if conditionally compiled in
#[cfg(feature = "arch_sparc")]
mod sparc;
#[cfg(feature = "arch_sparc")]
pub use crate::sparc::*;

// include tricore support if conditionally compiled in
#[cfg(feature = "arch_tricore")]
mod tricore;
#[cfg(feature = "arch_tricore")]
pub use crate::tricore::*;

// include x86 support if conditionally compiled in
#[cfg(feature = "arch_x86")]
mod x86;
#[cfg(feature = "arch_x86")]
pub use crate::x86::*;

/// Opaque storage for CPU context.
/// Used to quickly save and restore cpu state.
///
/// Instances of this type are created and used by the context_* functions
/// on the [Unicorn] struct.
#[derive(Debug)]
pub struct Context {
    context: ffi::uc_context,
}

impl Context {
    #[must_use]
    pub fn is_initialized(&self) -> bool {
        !self.context.is_null()
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        if self.is_initialized() {
            unsafe {
                ffi::uc_context_free(self.context);
            }
        }
        self.context = ptr::null_mut();
    }
}

/// Storage for any existing memory mapped I/O callbacks.
/// Instances of this type are stored in the [UnicornInner::mmio_callbacks] vector.
pub struct MmioCallbackScope<'a> {
    /// A list of memory regions that are mapped to this callback,
    /// stored in (address, size) tuples.
    pub regions: Vec<(u64, usize)>,
    // The callback for when the memory region is read from.
    // None if this region is write only.
    pub read_callback: Option<Box<dyn ffi::IsUcHook<'a> + 'a>>,
    // The callback for when the memory region is written to.
    // None if this region is read only.
    pub write_callback: Option<Box<dyn ffi::IsUcHook<'a> + 'a>>,
}

impl MmioCallbackScope<'_> {
    fn has_regions(&self) -> bool {
        !self.regions.is_empty()
    }

    fn unmap(&mut self, begin: u64, size: usize) {
        let end: u64 = begin + size as u64;
        self.regions = self
            .regions
            .iter()
            .flat_map(|(b, s)| {
                let e: u64 = b + *s as u64;
                if begin > *b {
                    if begin >= e {
                        // The unmapped region is completely after this region
                        vec![(*b, *s)]
                    } else if end >= e {
                        // The unmapped region overlaps with the end of this region
                        vec![(*b, (begin - *b) as usize)]
                    } else {
                        // The unmapped region is in the middle of this region
                        let second_b = end + 1;
                        vec![
                            (*b, (begin - *b) as usize),
                            (second_b, (e - second_b) as usize),
                        ]
                    }
                } else if end > *b {
                    if end >= e {
                        // The unmapped region completely contains this region
                        vec![]
                    } else {
                        // The unmapped region overlaps with the start of this region
                        vec![(end, (e - end) as usize)]
                    }
                } else {
                    // The unmapped region is completely before this region
                    vec![(*b, *s)]
                }
            })
            .collect();
    }
}

/// An opaque pointer to a unicorn hook callback. Returned by the add_*_hook functions on
/// [Unicorn] and used to unregister hooks with [Unicorn::remove_hook].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct UcHookId(ffi::uc_hook);

pub struct UnicornInner<'a, D> {
    /// An opaque pointer to the unicorn instance.
    pub handle: uc_handle,
    /// If false, this struct's [UnicornInner::handle] was created in rust and will
    /// be freed by its [Drop] implementation.
    pub ffi: bool,
    /// The architecture of the unicorn instance.
    pub arch: Arch,
    /// to keep ownership over the hook for this uc instance's lifetime
    pub hooks: Vec<(UcHookId, Box<dyn ffi::IsUcHook<'a> + 'a>)>,
    /// To keep ownership over the mmio callbacks for this uc instance's lifetime
    pub mmio_callbacks: Vec<MmioCallbackScope<'a>>,
    /// Accompanying data that is accessible to callbacks
    pub data: D,
}

impl<D> Drop for UnicornInner<'_, D> {
    fn drop(&mut self) {
        if !self.ffi && !self.handle.is_null() {
            unsafe { ffi::uc_close(self.handle) };
        }
        self.handle = ptr::null_mut();
    }
}

/// A Unicorn emulator instance.
pub struct Unicorn<'a, D: 'a> {
    inner: Rc<UnsafeCell<UnicornInner<'a, D>>>,
}

impl<'a> Unicorn<'a, ()> {
    /// Create a new instance of the unicorn engine for the specified architecture
    /// and hardware mode.
    pub fn new(arch: Arch, mode: Mode) -> Result<Unicorn<'a, ()>, uc_error> {
        Self::new_with_data(arch, mode, ())
    }

    /// Create a new [Unicorn] value from an existing [uc_handle] pointer.
    ///
    /// # Safety
    /// The function has to be called with a valid uc_handle pointer
    /// that was previously allocated by a call to uc_open.
    /// Calling the function with a non null pointer value that
    /// does not point to a unicorn instance will cause undefined
    /// behavior.
    pub unsafe fn from_handle(handle: uc_handle) -> Result<Unicorn<'a, ()>, uc_error> {
        if handle.is_null() {
            return Err(uc_error::HANDLE);
        }
        let mut arch: libc::size_t = Default::default();
        let err = unsafe { ffi::uc_query(handle, Query::ARCH, &mut arch) };
        if err != uc_error::OK {
            return Err(err);
        }
        Ok(Unicorn {
            inner: Rc::new(UnsafeCell::from(UnicornInner {
                handle,
                ffi: true,
                arch: arch.try_into()?,
                data: (),
                hooks: vec![],
                mmio_callbacks: vec![],
            })),
        })
    }
}

impl<'a, D> Unicorn<'a, D>
where
    D: 'a,
{
    /// Create a new instance of the unicorn engine for the specified architecture
    /// and hardware mode.
    ///
    /// Unlike [Unicorn::new], this function allows you to pass in custom data
    /// that is attatched to the [Unicorn] instance and is accessible to callbacks.
    pub fn new_with_data(arch: Arch, mode: Mode, data: D) -> Result<Unicorn<'a, D>, uc_error> {
        let mut handle = ptr::null_mut();
        unsafe { ffi::uc_open(arch, mode, &mut handle) }.and_then(|| {
            Ok(Unicorn {
                inner: Rc::new(UnsafeCell::from(UnicornInner {
                    handle,
                    ffi: false,
                    arch,
                    data,
                    hooks: vec![],
                    mmio_callbacks: vec![],
                })),
            })
        })
    }
}

impl<D> core::fmt::Debug for Unicorn<'_, D> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(formatter, "Unicorn {{ uc: {:p} }}", self.get_handle())
    }
}

impl<'a, D> Unicorn<'a, D> {
    fn inner(&self) -> &UnicornInner<'a, D> {
        unsafe { self.inner.get().as_ref().unwrap() }
    }

    fn inner_mut(&mut self) -> &mut UnicornInner<'a, D> {
        unsafe { self.inner.get().as_mut().unwrap() }
    }

    /// Return whatever data was passed during initialization.
    ///
    /// For an example, have a look at `utils::init_emu_with_heap` where
    /// a struct is passed which is used for a custom allocator.
    #[must_use]
    pub fn get_data(&self) -> &D {
        &self.inner().data
    }

    /// Return a mutable reference to whatever data was passed during initialization.
    #[must_use]
    pub fn get_data_mut(&mut self) -> &mut D {
        &mut self.inner_mut().data
    }

    /// Return the architecture of the current emulator.
    #[must_use]
    pub fn get_arch(&self) -> Arch {
        self.inner().arch
    }

    /// Return the handle of the current emulator.
    #[must_use]
    pub fn get_handle(&self) -> uc_handle {
        self.inner().handle
    }

    /// Returns a vector with the memory regions that are mapped in the emulator.
    pub fn mem_regions(&self) -> Result<Vec<MemRegion>, uc_error> {
        let mut nb_regions: u32 = 0;
        let p_regions: *const MemRegion = ptr::null_mut();
        // TODO: Use slice::from_raw_parts here
        unsafe { ffi::uc_mem_regions(self.get_handle(), &p_regions, &mut nb_regions) }.and_then(
            || {
                let mut regions = Vec::new();
                for i in 0..nb_regions {
                    regions.push(unsafe { core::mem::transmute_copy(&*p_regions.add(i as usize)) });
                }
                unsafe { libc::free(p_regions as _) };
                Ok(regions)
            },
        )
    }

    /// Read a range of bytes from memory at the specified emulated physical address.
    pub fn mem_read(&self, address: u64, buf: &mut [u8]) -> Result<(), uc_error> {
        unsafe { ffi::uc_mem_read(self.get_handle(), address, buf.as_mut_ptr(), buf.len()) }.into()
    }

    /// Return a range of bytes from memory at the specified emulated physical address as vector.
    pub fn mem_read_as_vec(&self, address: u64, size: usize) -> Result<Vec<u8>, uc_error> {
        let mut buf = vec![0; size];
        unsafe { ffi::uc_mem_read(self.get_handle(), address, buf.as_mut_ptr(), size) }.and(Ok(buf))
    }

    /// Write the data in `bytes` to the emulated physical address `address`
    pub fn mem_write(&mut self, address: u64, bytes: &[u8]) -> Result<(), uc_error> {
        unsafe { ffi::uc_mem_write(self.get_handle(), address, bytes.as_ptr(), bytes.len()) }.into()
    }

    /// Map an existing memory region in the emulator at the specified address.
    ///
    /// # Safety
    ///
    /// This function is marked unsafe because it is the responsibility of the caller to
    /// ensure that `size` matches the size of the passed buffer, an invalid `size` value will
    /// likely cause a crash in unicorn.
    ///
    /// `address` must be aligned to 4kb or this will return `Error::ARG`.
    /// `size` must be a multiple of 4kb or this will return `Error::ARG`.
    ///
    /// `ptr` is a pointer to the provided memory region that will be used by the emulator.
    pub unsafe fn mem_map_ptr(
        &mut self,
        address: u64,
        size: usize,
        perms: Permission,
        ptr: *mut c_void,
    ) -> Result<(), uc_error> {
        ffi::uc_mem_map_ptr(self.get_handle(), address, size, perms.bits(), ptr).into()
    }

    /// Map a memory region in the emulator at the specified address.
    ///
    /// `address` must be aligned to 4kb or this will return `Error::ARG`.
    /// `size` must be a multiple of 4kb or this will return `Error::ARG`.
    pub fn mem_map(
        &mut self,
        address: u64,
        size: libc::size_t,
        perms: Permission,
    ) -> Result<(), uc_error> {
        unsafe { ffi::uc_mem_map(self.get_handle(), address, size, perms.bits()) }.into()
    }

    /// Map in am MMIO region backed by callbacks.
    ///
    /// `address` must be aligned to 4kb or this will return `Error::ARG`.
    /// `size` must be a multiple of 4kb or this will return `Error::ARG`.
    pub fn mmio_map<R, W>(
        &mut self,
        address: u64,
        size: libc::size_t,
        read_callback: Option<R>,
        write_callback: Option<W>,
    ) -> Result<(), uc_error>
    where
        R: FnMut(&mut Unicorn<D>, u64, usize) -> u64 + 'a,
        W: FnMut(&mut Unicorn<D>, u64, usize, u64) + 'a,
    {
        let mut read_data = read_callback.map(|c| {
            Box::new(ffi::UcHook {
                callback: c,
                uc: Rc::downgrade(&self.inner),
            })
        });
        let mut write_data = write_callback.map(|c| {
            Box::new(ffi::UcHook {
                callback: c,
                uc: Rc::downgrade(&self.inner),
            })
        });

        unsafe {
            ffi::uc_mmio_map(
                self.get_handle(),
                address,
                size,
                match read_data {
                    Some(_) => ffi::mmio_read_callback_proxy::<D, R> as _,
                    None => ptr::null_mut(),
                },
                match read_data {
                    Some(ref mut d) => d.as_mut() as *mut _ as _,
                    None => ptr::null_mut(),
                },
                match write_data {
                    Some(_) => ffi::mmio_write_callback_proxy::<D, W> as _,
                    None => ptr::null_mut(),
                },
                match write_data {
                    Some(ref mut d) => d.as_mut() as *mut _ as _,
                    None => ptr::null_mut(),
                },
            )
        }
        .and_then(|| {
            let rd = read_data.map(|c| c as Box<dyn ffi::IsUcHook>);
            let wd = write_data.map(|c| c as Box<dyn ffi::IsUcHook>);
            self.inner_mut().mmio_callbacks.push(MmioCallbackScope {
                regions: vec![(address, size)],
                read_callback: rd,
                write_callback: wd,
            });

            Ok(())
        })
    }

    /// Map in a read-only MMIO region backed by a callback.
    ///
    /// `address` must be aligned to 4kb or this will return `Error::ARG`.
    /// `size` must be a multiple of 4kb or this will return `Error::ARG`.
    pub fn mmio_map_ro<F>(
        &mut self,
        address: u64,
        size: libc::size_t,
        callback: F,
    ) -> Result<(), uc_error>
    where
        F: FnMut(&mut Unicorn<D>, u64, usize) -> u64 + 'a,
    {
        self.mmio_map(
            address,
            size,
            Some(callback),
            None::<fn(&mut Unicorn<D>, u64, usize, u64)>,
        )
    }

    /// Map in a write-only MMIO region backed by a callback.
    ///
    /// `address` must be aligned to 4kb or this will return `Error::ARG`.
    /// `size` must be a multiple of 4kb or this will return `Error::ARG`.
    pub fn mmio_map_wo<F>(
        &mut self,
        address: u64,
        size: libc::size_t,
        callback: F,
    ) -> Result<(), uc_error>
    where
        F: FnMut(&mut Unicorn<D>, u64, usize, u64) + 'a,
    {
        self.mmio_map(
            address,
            size,
            None::<fn(&mut Unicorn<D>, u64, usize) -> u64>,
            Some(callback),
        )
    }

    /// Unmap a memory region.
    ///
    /// `address` must be aligned to 4kb or this will return `Error::ARG`.
    /// `size` must be a multiple of 4kb or this will return `Error::ARG`.
    pub fn mem_unmap(&mut self, address: u64, size: libc::size_t) -> Result<(), uc_error> {
        let err = unsafe { ffi::uc_mem_unmap(self.get_handle(), address, size) };
        self.mmio_unmap(address, size);
        err.into()
    }

    fn mmio_unmap(&mut self, address: u64, size: libc::size_t) {
        for scope in self.inner_mut().mmio_callbacks.iter_mut() {
            scope.unmap(address, size);
        }
        self.inner_mut()
            .mmio_callbacks
            .retain(|scope| scope.has_regions());
    }

    /// Set the memory permissions for an existing memory region.
    ///
    /// `address` must be aligned to 4kb or this will return `Error::ARG`.
    /// `size` must be a multiple of 4kb or this will return `Error::ARG`.
    pub fn mem_protect(
        &mut self,
        address: u64,
        size: libc::size_t,
        perms: Permission,
    ) -> Result<(), uc_error> {
        unsafe { ffi::uc_mem_protect(self.get_handle(), address, size, perms.bits()) }.into()
    }

    /// Write an unsigned value from a register.
    pub fn reg_write<T: Into<i32>>(&mut self, regid: T, value: u64) -> Result<(), uc_error> {
        unsafe { ffi::uc_reg_write(self.get_handle(), regid.into(), &value as *const _ as _) }
            .into()
    }

    /// Write variable sized values into registers.
    ///
    /// The user has to make sure that the buffer length matches the register size.
    /// This adds support for registers >64 bit (GDTR/IDTR, XMM, YMM, ZMM (x86); Q, V (arm64)).
    pub fn reg_write_long<T: Into<i32>>(&self, regid: T, value: &[u8]) -> Result<(), uc_error> {
        unsafe { ffi::uc_reg_write(self.get_handle(), regid.into(), value.as_ptr() as _) }.into()
    }

    // TODO: What happens when used with a too large register
    /// Read an unsigned value from a register.
    ///
    /// Not to be used with registers larger than 64 bit.
    pub fn reg_read<T: Into<i32>>(&self, regid: T) -> Result<u64, uc_error> {
        let mut value: u64 = 0;
        unsafe { ffi::uc_reg_read(self.get_handle(), regid.into(), &mut value as *mut u64 as _) }
            .and(Ok(value))
    }

    // TODO: What happens when used with a smaller register
    /// Read 128, 256 or 512 bit register value into heap allocated byte array.
    ///
    /// This adds safe support for registers >64 bit (GDTR/IDTR, XMM, YMM, ZMM, ST (x86); Q, V (arm64)).
    pub fn reg_read_long<T: Into<i32>>(&self, regid: T) -> Result<Box<[u8]>, uc_error> {
        let curr_reg_id = regid.into();
        let curr_arch = self.get_arch();

        let value_size = match curr_arch {
            #[cfg(feature = "arch_x86")]
            Arch::X86 => Self::value_size_x86(curr_reg_id)?,
            #[cfg(feature = "arch_arm")]
            Arch::ARM64 => Self::value_size_arm64(curr_reg_id)?,
            _ => Err(uc_error::ARCH)?,
        };
        let mut value = vec![0; value_size];
        unsafe { ffi::uc_reg_read(self.get_handle(), curr_reg_id, value.as_mut_ptr() as _) }
            .and_then(|| Ok(value.into_boxed_slice()))
    }

    #[cfg(feature = "arch_arm")]
    fn value_size_arm64(curr_reg_id: i32) -> Result<usize, uc_error> {
        match curr_reg_id {
            r if (RegisterARM64::Q0 as i32..=RegisterARM64::Q31 as i32).contains(&r)
                || (RegisterARM64::V0 as i32..=RegisterARM64::V31 as i32).contains(&r) =>
            {
                Ok(16)
            }
            _ => Err(uc_error::ARG),
        }
    }

    #[cfg(feature = "arch_x86")]
    fn value_size_x86(curr_reg_id: i32) -> Result<usize, uc_error> {
        match curr_reg_id {
            r if (RegisterX86::XMM0 as i32..=RegisterX86::XMM31 as i32).contains(&r) => Ok(16),
            r if (RegisterX86::YMM0 as i32..=RegisterX86::YMM31 as i32).contains(&r) => Ok(32),
            r if (RegisterX86::ZMM0 as i32..=RegisterX86::ZMM31 as i32).contains(&r) => Ok(64),
            r if r == RegisterX86::GDTR as i32
                || r == RegisterX86::IDTR as i32
                || (RegisterX86::ST0 as i32..=RegisterX86::ST7 as i32).contains(&r) =>
            {
                Ok(10)
            }
            _ => Err(uc_error::ARG),
        }
    }

    /// Read a signed 32-bit value from a register.
    pub fn reg_read_i32<T: Into<i32>>(&self, regid: T) -> Result<i32, uc_error> {
        let mut value: i32 = 0;
        unsafe { ffi::uc_reg_read(self.get_handle(), regid.into(), &mut value as *mut i32 as _) }
            .and(Ok(value))
    }

    /// Add a code hook. A code hook is a finer-grained block hook. It is called before each
    /// instruction is executed. The arguments for `F` are
    ///
    /// * A reference to this [Unicorn] instance
    /// * The address of the instruction
    /// * The size of the instruction (or 0 when unknown)
    ///
    /// The code hook is applied to all code between the `begin` and `end` addresses (both
    /// inclusive).
    ///
    /// Note: this causes a considerable performance hit, as it prevents the QEMU JIT optimizer
    /// from optimizing basic blocks. Unless the granularity is needed, consider using a block hook
    /// instead.
    pub fn add_code_hook<F>(
        &mut self,
        begin: u64,
        end: u64,
        callback: F,
    ) -> Result<UcHookId, uc_error>
    where
        F: FnMut(&mut Unicorn<D>, u64, u32) + 'a,
    {
        let mut hook_id = ptr::null_mut();
        let mut user_data = Box::new(ffi::UcHook {
            callback,
            uc: Rc::downgrade(&self.inner),
        });

        unsafe {
            ffi::uc_hook_add(
                self.get_handle(),
                &mut hook_id,
                HookType::CODE,
                ffi::code_hook_proxy::<D, F> as _,
                user_data.as_mut() as *mut _ as _,
                begin,
                end,
            )
        }
        .and_then(|| {
            let hook_id = UcHookId(hook_id);
            self.inner_mut().hooks.push((hook_id, user_data));
            Ok(hook_id)
        })
    }

    /// Add a block hook. This hook is called whenever execution starts within a "basic block", aka
    /// a sequence of instructions without any conditional branching, I/O, or other special behavior.
    ///
    /// * A reference to this [Unicorn] instance
    /// * The address of the instruction
    /// * The size of the instruction (or 0 when unknown)
    ///
    /// The code hook is applied to all code between the `begin` and `end` addresses (both
    /// inclusive).
    pub fn add_block_hook<F>(
        &mut self,
        begin: u64,
        end: u64,
        callback: F,
    ) -> Result<UcHookId, uc_error>
    where
        F: FnMut(&mut Unicorn<D>, u64, u32) + 'a,
    {
        let mut hook_id = ptr::null_mut();
        let mut user_data = Box::new(ffi::UcHook {
            callback,
            uc: Rc::downgrade(&self.inner),
        });

        unsafe {
            ffi::uc_hook_add(
                self.get_handle(),
                &mut hook_id,
                HookType::BLOCK,
                ffi::block_hook_proxy::<D, F> as _,
                user_data.as_mut() as *mut _ as _,
                begin,
                end,
            )
        }
        .and_then(|| {
            let hook_id = UcHookId(hook_id);
            self.inner_mut().hooks.push((hook_id, user_data));
            Ok(hook_id)
        })
    }

    // TODO: Make a new enum for each of these functions.
    /// Add a memory hook. This hook will be called when a memory access occurs. The types of
    /// accesses that trigger a callback depends on the value of `hook_type`.
    ///
    /// * `MEM_READ`: Called before a read access
    /// * `MEM_WRITE`: Called before a write access
    /// * `MEM_READ_AFTER`: Called after a read access (value is populated)
    /// * `MEM_FETCH_*`: Called when the emulator cannot read memory to load new
    ///   instructions (due to unmapped, no read, or no execute memory).
    ///   Note: `MEM_FETCH` with no suffix is deprecated.
    /// * `MEM_*_UNMAPPED`: Called when memory accesses an unmapped address
    /// * `MEM_*_PROT`: Called when a memory access occurs that is forbidden by memory
    ///   protection (e.g. writing to read only memory).
    ///
    /// The arguments for the callback are
    /// * A reference to this [Unicorn] instance
    /// * The type of access (Read or Write)
    /// * The address of the access
    /// * The size of the access (in bytes)
    /// * The value that is being read/written (indeterminate for MEM_READ hooks)
    ///
    /// For the UNMAPPED hook types, the return value should be true if execution should
    /// continue, or false if it should abort. In order to return true, you need to map
    /// the memory region being accessed in the callback.
    pub fn add_mem_hook<F>(
        &mut self,
        hook_type: HookType,
        begin: u64,
        end: u64,
        callback: F,
    ) -> Result<UcHookId, uc_error>
    where
        F: FnMut(&mut Unicorn<D>, MemType, u64, usize, i64) -> bool + 'a,
    {
        if !(HookType::MEM_ALL | HookType::MEM_READ_AFTER).contains(hook_type) {
            return Err(uc_error::ARG);
        }

        let mut hook_id = ptr::null_mut();
        let mut user_data = Box::new(ffi::UcHook {
            callback,
            uc: Rc::downgrade(&self.inner),
        });

        unsafe {
            ffi::uc_hook_add(
                self.get_handle(),
                &mut hook_id,
                hook_type,
                ffi::mem_hook_proxy::<D, F> as _,
                user_data.as_mut() as *mut _ as _,
                begin,
                end,
            )
        }
        .and_then(|| {
            let hook_id = UcHookId(hook_id);
            self.inner_mut().hooks.push((hook_id, user_data));
            Ok(hook_id)
        })
    }

    /// Add an interrupt hook. This hook will be called when an interrupt occurs.
    /// This happens because of an interrupt, used for things like invoking a syscall.
    ///
    /// The arguments for the callback are
    /// * A reference to this [Unicorn] instance
    /// * The interrupt number
    pub fn add_intr_hook<F>(&mut self, callback: F) -> Result<UcHookId, uc_error>
    where
        F: FnMut(&mut Unicorn<D>, u32) + 'a,
    {
        let mut hook_id = ptr::null_mut();
        let mut user_data = Box::new(ffi::UcHook {
            callback,
            uc: Rc::downgrade(&self.inner),
        });

        unsafe {
            ffi::uc_hook_add(
                self.get_handle(),
                &mut hook_id,
                HookType::INTR,
                ffi::intr_hook_proxy::<D, F> as _,
                user_data.as_mut() as *mut _ as _,
                0,
                0,
            )
        }
        .and_then(|| {
            let hook_id = UcHookId(hook_id);
            self.inner_mut().hooks.push((hook_id, user_data));
            Ok(hook_id)
        })
    }

    /// Add hook for invalid instructions. This hook is called when the emulator
    /// encounters an instruction that is not a legal opcode.
    ///
    /// The arguments for the callback are
    /// * A reference to this [Unicorn] instance
    ///
    /// The return value is whether execution should continue (true) or abort (false)
    pub fn add_insn_invalid_hook<F>(&mut self, callback: F) -> Result<UcHookId, uc_error>
    where
        F: FnMut(&mut Unicorn<D>) -> bool + 'a,
    {
        let mut hook_id = ptr::null_mut();
        let mut user_data = Box::new(ffi::UcHook {
            callback,
            uc: Rc::downgrade(&self.inner),
        });

        unsafe {
            ffi::uc_hook_add(
                self.get_handle(),
                &mut hook_id,
                HookType::INSN_INVALID,
                ffi::insn_invalid_hook_proxy::<D, F> as _,
                user_data.as_mut() as *mut _ as _,
                0,
                0,
            )
        }
        .and_then(|| {
            let hook_id = UcHookId(hook_id);
            self.inner_mut().hooks.push((hook_id, user_data));
            Ok(hook_id)
        })
    }

    /// Add hook for x86 IN instruction. This hook is called when the emulator encounters an x86 IN
    /// instruction.
    ///
    /// The arguments for the callback are
    /// * A reference to this [Unicorn] instance
    /// * The port number
    /// * the data size to be read from this port, in bytes (1/2/4)
    ///
    /// The return value is the data read from the port.
    #[cfg(feature = "arch_x86")]
    pub fn add_insn_in_hook<F>(&mut self, callback: F) -> Result<UcHookId, uc_error>
    where
        F: FnMut(&mut Unicorn<D>, u32, usize) -> u32 + 'a,
    {
        let mut hook_id = ptr::null_mut();
        let mut user_data = Box::new(ffi::UcHook {
            callback,
            uc: Rc::downgrade(&self.inner),
        });

        unsafe {
            ffi::uc_hook_add(
                self.get_handle(),
                &mut hook_id,
                HookType::INSN,
                ffi::insn_in_hook_proxy::<D, F> as _,
                user_data.as_mut() as *mut _ as _,
                0,
                0,
                InsnX86::IN,
            )
        }
        .and_then(|| {
            let hook_id = UcHookId(hook_id);
            self.inner_mut().hooks.push((hook_id, user_data));
            Ok(hook_id)
        })
    }

    /// Add hook for x86 OUT instruction. This hook is called when the emulator encounters an x86 OUT
    /// instruction.
    ///
    /// The arguments for the callback are
    /// * A reference to this [Unicorn] instance
    /// * The port number
    /// * The data size to be written from this port, in bytes (1/2/4)
    /// * The data to be written to the port
    #[cfg(feature = "arch_x86")]
    pub fn add_insn_out_hook<F>(&mut self, callback: F) -> Result<UcHookId, uc_error>
    where
        F: FnMut(&mut Unicorn<D>, u32, usize, u32) + 'a,
    {
        let mut hook_id = ptr::null_mut();
        let mut user_data = Box::new(ffi::UcHook {
            callback,
            uc: Rc::downgrade(&self.inner),
        });

        unsafe {
            ffi::uc_hook_add(
                self.get_handle(),
                &mut hook_id,
                HookType::INSN,
                ffi::insn_out_hook_proxy::<D, F> as _,
                user_data.as_mut() as *mut _ as _,
                0,
                0,
                InsnX86::OUT,
            )
        }
        .and_then(|| {
            let hook_id = UcHookId(hook_id);
            self.inner_mut().hooks.push((hook_id, user_data));
            Ok(hook_id)
        })
    }

    /// Add hook for x86 SYSCALL or SYSENTER. This hook will be called when an the emulator
    /// encounters either instruction.
    ///
    /// The arguments for the callback are
    /// * A reference to this [Unicorn] instance
    #[cfg(feature = "arch_x86")]
    pub fn add_insn_sys_hook<F>(
        &mut self,
        insn_type: InsnSysX86,
        begin: u64,
        end: u64,
        callback: F,
    ) -> Result<UcHookId, uc_error>
    where
        F: FnMut(&mut Unicorn<D>) + 'a,
    {
        let mut hook_id = ptr::null_mut();
        let mut user_data = Box::new(ffi::UcHook {
            callback,
            uc: Rc::downgrade(&self.inner),
        });

        unsafe {
            ffi::uc_hook_add(
                self.get_handle(),
                &mut hook_id,
                HookType::INSN,
                ffi::insn_sys_hook_proxy::<D, F> as _,
                user_data.as_mut() as *mut _ as _,
                begin,
                end,
                insn_type,
            )
        }
        .and_then(|| {
            let hook_id = UcHookId(hook_id);
            self.inner_mut().hooks.push((hook_id, user_data));
            Ok(hook_id)
        })
    }


    /// Add hook for a TLB lookup. This hook will be called when an the emulator
    /// needs to de-virtualize a memory address.
    ///
    /// The arguments for the callback are
    /// * A reference to this [Unicorn] instance
    /// * The virtual address to lookup
    /// * The mode of the access
    ///
    /// The return value is a TLB entry for the address.
    pub fn add_tlb_hook<F>(
        &mut self,
        begin: u64,
        end: u64,
        callback: F,
    ) -> Result<UcHookId, uc_error>
    where
        F: FnMut(&mut Unicorn<D>, u64, MemType) -> Option<TlbEntry> + 'a,
    {
        let mut hook_id = ptr::null_mut();
        let mut user_data = Box::new(ffi::UcHook {
            callback,
            uc: Rc::downgrade(&self.inner),
        });

        unsafe {
            ffi::uc_hook_add(
                self.get_handle(),
                &mut hook_id,
                HookType::TLB,
                ffi::tlb_lookup_hook_proxy::<D, F> as _,
                user_data.as_mut() as *mut _ as _,
                begin,
                end,
            )
        }
        .and_then(|| {
            let hook_id = UcHookId(hook_id);
            self.inner_mut().hooks.push((hook_id, user_data));
            Ok(hook_id)
        })
    }

    /// Remove a hook.
    ///
    /// `hook_id` is the value returned by `add_*_hook` functions.
    pub fn remove_hook(&mut self, hook_id: UcHookId) -> Result<(), uc_error> {
        // drop the hook
        let inner = self.inner_mut();
        inner.hooks.retain(|(id, _)| id != &hook_id);

        unsafe { ffi::uc_hook_del(inner.handle, hook_id.0) }.into()
    }

    /// Allocate and return an empty Unicorn context.
    ///
    /// To be populated via `context_save`.
    pub fn context_alloc(&self) -> Result<Context, uc_error> {
        let mut empty_context: ffi::uc_context = ptr::null_mut();
        unsafe { ffi::uc_context_alloc(self.get_handle(), &mut empty_context) }.and(Ok(Context {
            context: empty_context,
        }))
    }

    /// Save current Unicorn context to previously allocated Context struct.
    pub fn context_save(&self, context: &mut Context) -> Result<(), uc_error> {
        unsafe { ffi::uc_context_save(self.get_handle(), context.context) }.into()
    }

    /// Allocate and return a Context struct initialized with the current CPU context.
    ///
    /// This can be used for fast rollbacks with `context_restore`.
    /// In case of many non-concurrent context saves, use `context_alloc` and *_save
    /// individually to avoid unnecessary allocations.
    pub fn context_init(&self) -> Result<Context, uc_error> {
        let mut new_context: ffi::uc_context = ptr::null_mut();
        unsafe {
            ffi::uc_context_alloc(self.get_handle(), &mut new_context).and_then(|| {
                ffi::uc_context_save(self.get_handle(), new_context)
                    .and(Ok(Context {
                        context: new_context,
                    }))
                    .inspect_err(|_| {
                        ffi::uc_context_free(new_context);
                    })
            })
        }
    }

    /// Restore a previously saved Unicorn context.
    ///
    /// Perform a quick rollback of the CPU context, including registers and some
    /// internal metadata. Contexts may not be shared across engine instances with
    /// differing arches or modes. Memory has to be restored manually, if needed.
    pub fn context_restore(&self, context: &Context) -> Result<(), uc_error> {
        unsafe { ffi::uc_context_restore(self.get_handle(), context.context) }.into()
    }

    /// Emulate machine code for a specified duration.
    ///
    /// TODO: What happens when until is begin (infinite?)
    /// `begin` is the address where to start the emulation. The emulation stops if `until`
    /// is hit. `timeout` specifies a duration in microseconds after which the emulation is
    /// stopped (infinite execution if set to 0). `count` is the maximum number of instructions
    /// to emulate (emulate all the available instructions if set to 0).
    pub fn emu_start(
        &mut self,
        begin: u64,
        until: u64,
        timeout: u64,
        count: usize,
    ) -> Result<(), uc_error> {
        unsafe { ffi::uc_emu_start(self.get_handle(), begin, until, timeout, count as _) }.into()
    }

    /// Stop the emulation.
    ///
    /// This is usually called from callback function in hooks.
    /// NOTE: For now, this will stop the execution only after the current block.
    pub fn emu_stop(&mut self) -> Result<(), uc_error> {
        unsafe { ffi::uc_emu_stop(self.get_handle()).into() }
    }

    /// Query the internal status of the engine.
    ///
    /// supported: `MODE`, `PAGE_SIZE`, `ARCH`
    pub fn query(&self, query: Query) -> Result<usize, uc_error> {
        let mut result: libc::size_t = Default::default();
        unsafe { ffi::uc_query(self.get_handle(), query, &mut result) }.and(Ok(result))
    }

    /// Get the `i32` register value for the program counter for the specified architecture.
    ///
    /// If an architecture is not compiled in, this function will return `uc_error::ARCH`.
    #[inline]
    fn arch_to_pc_register(arch: Arch) -> Result<i32, uc_error> {
        match arch {
            #[cfg(feature = "arch_x86")]
            Arch::X86 => Ok(RegisterX86::RIP as i32),
            #[cfg(feature = "arch_arm")]
            Arch::ARM => Ok(RegisterARM::PC as i32),
            #[cfg(feature = "arch_arm")]
            Arch::ARM64 => Ok(RegisterARM64::PC as i32),
            #[cfg(feature = "arch_mips")]
            Arch::MIPS => Ok(RegisterMIPS::PC as i32),
            #[cfg(feature = "arch_sparc")]
            Arch::SPARC => Ok(RegisterSPARC::PC as i32),
            #[cfg(feature = "arch_m68k")]
            Arch::M68K => Ok(RegisterM68K::PC as i32),
            #[cfg(feature = "arch_ppc")]
            Arch::PPC => Ok(RegisterPPC::PC as i32),
            #[cfg(feature = "arch_riscv")]
            Arch::RISCV => Ok(RegisterRISCV::PC as i32),
            #[cfg(feature = "arch_s390x")]
            Arch::S390X => Ok(RegisterS390X::PC as i32),
            #[cfg(feature = "arch_tricore")]
            Arch::TRICORE => Ok(RegisterTRICORE::PC as i32),
            // returns `uc_error::ARCH` for `Arch::MAX`, and any
            // other architecture that are not compiled in
            _ => Err(uc_error::ARCH),
        }
    }

    /// Gets the current program counter for this `unicorn` instance.
    #[inline]
    pub fn pc_read(&self) -> Result<u64, uc_error> {
        let arch = self.get_arch();

        self.reg_read(Self::arch_to_pc_register(arch)?)
    }

    /// Sets the program counter for this `unicorn` instance.
    #[inline]
    pub fn set_pc(&mut self, value: u64) -> Result<(), uc_error> {
        let arch = self.get_arch();

        self.reg_write(Self::arch_to_pc_register(arch)?, value)
    }

    /// Returns the current mode of the emulator. This includes endianness
    /// and architecture extensions.
    pub fn ctl_get_mode(&self) -> Result<Mode, uc_error> {
        let mut result: i32 = Default::default();
        unsafe {
            ffi::uc_ctl(
                self.get_handle(),
                uc_ctl_read(ControlType::UC_CTL_UC_MODE),
                &mut result,
            )
        }
        .and_then(|| Ok(Mode::from_bits_truncate(result)))
    }

    /// Returns the current page size of the emulator (in bytes).
    pub fn ctl_get_page_size(&self) -> Result<u32, uc_error> {
        let mut result: u32 = Default::default();
        unsafe {
            ffi::uc_ctl(
                self.get_handle(),
                uc_ctl_read(ControlType::UC_CTL_UC_PAGE_SIZE),
                &mut result,
            )
        }
        .and_then(|| Ok(result))
    }

    /// Sets the current page size of the emulator (in bytes).
    pub fn ctl_set_page_size(&self, page_size: u32) -> Result<(), uc_error> {
        unsafe {
            ffi::uc_ctl(
                self.get_handle(),
                uc_ctl_write(ControlType::UC_CTL_UC_PAGE_SIZE),
                page_size,
            )
        }
        .into()
    }

    // TODO: Why does this exist when we have `get_arch`?
    pub fn ctl_get_arch(&self) -> Result<Arch, uc_error> {
        let mut result: i32 = Default::default();
        unsafe {
            ffi::uc_ctl(
                self.get_handle(),
                uc_ctl_read(ControlType::UC_CTL_UC_ARCH),
                &mut result,
            )
        }
        .and_then(|| Arch::try_from(result as usize))
    }

    // TODO: What is this timeout
    pub fn ctl_get_timeout(&self) -> Result<u64, uc_error> {
        let mut result: u64 = Default::default();
        unsafe {
            ffi::uc_ctl(
                self.get_handle(),
                uc_ctl_read(ControlType::UC_CTL_UC_TIMEOUT),
                &mut result,
            )
        }
        .and(Ok(result))
    }

    // TODO: What are "exits"
    pub fn ctl_exits_enable(&self) -> Result<(), uc_error> {
        unsafe {
            ffi::uc_ctl(
                self.get_handle(),
                uc_ctl_write(ControlType::UC_CTL_UC_USE_EXITS),
                1,
            )
        }
        .into()
    }

    pub fn ctl_exits_disable(&self) -> Result<(), uc_error> {
        unsafe {
            ffi::uc_ctl(
                self.get_handle(),
                uc_ctl_write(ControlType::UC_CTL_UC_USE_EXITS),
                0,
            )
        }
        .into()
    }

    pub fn ctl_get_exits_count(&self) -> Result<usize, uc_error> {
        let mut result: libc::size_t = 0usize;
        unsafe {
            ffi::uc_ctl(
                self.get_handle(),
                uc_ctl_read(ControlType::UC_CTL_UC_EXITS_CNT),
                &mut result,
            )
        }
        .and(Ok(result))
    }

    pub fn ctl_get_exits(&self) -> Result<Vec<u64>, uc_error> {
        let exits_count: libc::size_t = self.ctl_get_exits_count()?;
        let mut exits: Vec<u64> = Vec::with_capacity(exits_count);
        unsafe {
            ffi::uc_ctl(
                self.get_handle(),
                uc_ctl_read(ControlType::UC_CTL_UC_EXITS),
                exits.as_mut_ptr(),
                exits_count,
            )
        }
        .and_then(|| unsafe {
            exits.set_len(exits_count);
            Ok(exits)
        })
    }

    pub fn ctl_set_exits(&self, exits: &[u64]) -> Result<(), uc_error> {
        unsafe {
            ffi::uc_ctl(
                self.get_handle(),
                uc_ctl_write(ControlType::UC_CTL_UC_EXITS),
                exits.as_ptr(),
                exits.len() as libc::size_t,
            )
        }
        .into()
    }

    // TODO: Make this return an enum
    pub fn ctl_get_cpu_model(&self) -> Result<i32, uc_error> {
        let mut result: i32 = Default::default();
        unsafe {
            ffi::uc_ctl(
                self.get_handle(),
                uc_ctl_read(ControlType::UC_CTL_CPU_MODEL),
                &mut result,
            )
        }
        .and(Ok(result))
    }

    // TODO: Make this take an enum
    pub fn ctl_set_cpu_model(&self, cpu_model: i32) -> Result<(), uc_error> {
        unsafe {
            ffi::uc_ctl(
                self.get_handle(),
                uc_ctl_write(ControlType::UC_CTL_CPU_MODEL),
                cpu_model,
            )
        }
        .into()
    }

    /// Invalidate a tb cache at a specified address
    /// TODO: What is "end"
    pub fn ctl_remove_cache(&self, address: u64, end: u64) -> Result<(), uc_error> {
        unsafe {
            ffi::uc_ctl(
                self.get_handle(),
                uc_ctl_write(ControlType::UC_CTL_TB_REMOVE_CACHE),
                address,
                end,
            )
        }
        .into()
    }

    /// Create a tb cache at the specified address
    /// TODO: What does "tb" do
    pub fn ctl_request_cache(
        &self,
        address: u64,
        tb: &mut TranslationBlock,
    ) -> Result<(), uc_error> {
        unsafe {
            ffi::uc_ctl(
                self.get_handle(),
                uc_ctl_read_write(ControlType::UC_CTL_TB_REQUEST_CACHE),
                address,
                tb,
            )
        }
        .into()
    }

    /// Invalidate all translation blocks
    pub fn ctl_flush_tb(&self) -> Result<(), uc_error> {
        unsafe {
            ffi::uc_ctl(
                self.get_handle(),
                uc_ctl_write(ControlType::UC_CTL_TB_FLUSH),
            )
        }
        .into()
    }

    /// Invalidate all tlb cache entries and translation blocks
    pub fn ctl_flush_tlb(&self) -> Result<(), uc_error> {
        unsafe {
            ffi::uc_ctl(
                self.get_handle(),
                uc_ctl_write(ControlType::UC_CTL_TLB_FLUSH),
            )
        }
        .into()
    }

    // TODO: "control if context_save/restore should work with snapshots"
    pub fn ctl_context_mode(&self, mode: ContextMode) -> Result<(), uc_error> {
        unsafe {
            ffi::uc_ctl(
                self.get_handle(),
                uc_ctl_write(ControlType::UC_CTL_CONTEXT_MODE),
                mode,
            )
        }
        .into()
    }

    /// Change the current tlb implementation
    pub fn ctl_tlb_type(&self, t: TlbType) -> Result<(), uc_error> {
        unsafe {
            ffi::uc_ctl(
                self.get_handle(),
                uc_ctl_write(ControlType::UC_CTL_TLB_TYPE),
                t as i32,
            )
        }
        .into()
    }
}
