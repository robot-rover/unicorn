//! This module contains the constants and enums used by the Unicorn library.
//!
//! Most of its members are directly mapped from the C API.

#![allow(non_camel_case_types)]
use bitflags::bitflags;

pub const API_MAJOR: u64 = 2;
pub const API_MINOR: u64 = 0;
pub const VERSION_MAJOR: u64 = 2;
pub const VERSION_MINOR: u64 = 0;
pub const VERSION_PATCH: u64 = 0;
pub const VERSION_EXTRA: u64 = 7;
pub const SECOND_SCALE: u64 = 1_000_000;
pub const MILISECOND_SCALE: u64 = 1_000;

/// All errors that can be returned by this libraries API
/// are mapped to values of this type.
/// TODO: remap this to be nonzero
/// TODO: split this type to an error type for each function that can error
#[repr(C)]
#[derive(PartialEq, Debug, Clone, Copy)]
#[allow(clippy::upper_case_acronyms)]
pub enum uc_error {
    // TODO: Find the rust equivalent functions for doc comments

    /// No error
    OK = 0,
    /// Out of memory was returned by the allocator.
    /// Caused by a call to uc_open() or uc_emulate()
    NOMEM = 1,
    /// Invalid architecture passed to uc_open()
    ARCH = 2,
    /// Invalid handle pointer passed
    HANDLE = 3,
    /// Invalid mode passed to uc_open()
    MODE = 4,
    /// Unsupported underlying library version
    VERSION = 5,
    /// uc_emu_start() exitted due to a READ to unmapped memory
    READ_UNMAPPED = 6,
    /// uc_emu_start() exitted due to a WRITE to unmapped memory
    WRITE_UNMAPPED = 7,
    /// uc_emu_start() exitted due to a FETCH to unmapped memory
    FETCH_UNMAPPED = 8,
    /// An invalid hook type was passed to uc_hook_add()
    HOOK = 9,
    /// uc_emu_start() exitted due to an invalid instruction
    INSN_INVALID = 10,
    /// uc_mem_map() was passed an invalid memory mapping
    MAP = 11,
    /// uc_emu_start() exitted due to a write to non-writable memory
    WRITE_PROT = 12,
    /// uc_emu_start() exitted due to a read from non-readable memory
    READ_PROT = 13,
    /// uc_emu_start() exitted due to a fetch from non-readable memory
    FETCH_PROT = 14,
    /// Invalid argument passed to a function
    ARG = 15,
    /// uc_emu_start() exitted due to an insufficiently aligned read
    READ_UNALIGNED = 16,
    /// uc_emu_start() exitted due to an insufficiently aligned write
    WRITE_UNALIGNED = 17,
    /// uc_emu_start() exitted due to an insufficiently aligned fetch
    FETCH_UNALIGNED = 18,
    /// A hook for the requested event already exists
    HOOK_EXIST = 19,
    /// TODO: what does "insufficient resource: uc_emu_start()" mean
    RESOURCE = 20,
    /// uc_emu_start() exitted due to an exception that has no assigned handler
    EXCEPTION = 21,
}

impl uc_error {
    /// Calls op if the result is Ok, otherwise returns the Err value of self.
    /// This function can be used for control flow based on Result values.
    pub fn and_then<U, F: FnOnce() -> Result<U, uc_error>>(self, op: F) -> Result<U, uc_error> {
        if let Self::OK = self {
            op()
        } else {
            Err(self)
        }
    }

    /// Returns res if the result is Ok, otherwise returns the Err value of self.
    /// Arguments passed to and are eagerly evaluated; if you are passing the result
    /// of a function call, it is recommended to use and_then, which is lazily evaluated.
    pub fn and<U>(self, res: Result<U, uc_error>) -> Result<U, uc_error> {
        if let Self::OK = self {
            res
        } else {
            Err(self)
        }
    }
}

impl From<uc_error> for Result<(), uc_error> {
    fn from(value: uc_error) -> Self {
        if let uc_error::OK = value {
            Ok(())
        } else {
            Err(value)
        }
    }
}

/// The types of memory accesses that can be monitored with a hook via
/// TODO: Find rust equivalent of UC_HOOK_MEM_
#[repr(C)]
#[derive(PartialEq, Debug, Clone, Copy)]
pub enum MemType {
    /// Memory is read from
    READ = 16,
    /// Memory is written to
    WRITE = 17,
    /// Memory is fetched
    FETCH = 18,
    /// Unmapped memory is read from
    READ_UNMAPPED = 19,
    /// Unmapped memory is written to
    WRITE_UNMAPPED = 20,
    /// Unmapped memory is fetched
    FETCH_UNMAPPED = 21,
    /// Non-writeable (but mapped) memory is written to
    WRITE_PROT = 22,
    /// Non-readable (but mapped) memory is read
    READ_PROT = 23,
    /// Non-readable (but mapped) memory is fetched
    FETCH_PROT = 24,
    /// Memory is read from (called after the read value is available)
    READ_AFTER = 25,
}

/// The types of TLBs that can be emulated
#[repr(C)]
#[derive(PartialEq, Debug, Clone, Copy)]
pub enum TlbType {
    // TODO: Grammar
    /// The default unicorn virtuall TLB implementation.
    /// The tlb implementation of the CPU, best to use for full system emulation.
    CPU = 0,
    // TODO: What does the hook do?
    /// This tlb defaults to virtuall address == physical address
    /// Also a hook is availible to override the tlb entries (see
    /// uc_cb_tlbevent_t).
    VIRTUAL = 1,
}

bitflags! {
    /// A bitfield that represents the different hook types that can be registered with the emulator.
    #[repr(C)]
    #[derive(Copy, Clone)]
    pub struct HookType: i32 {
        const INTR = 1;
        const INSN = 2;
        const CODE = 4;
        const BLOCK = 8;

        const MEM_READ_UNMAPPED = 0x10;
        const MEM_WRITE_UNMAPPED = 0x20;
        const MEM_FETCH_UNMAPPED = 0x40;
        const MEM_UNMAPPED = Self::MEM_READ_UNMAPPED.bits() | Self::MEM_WRITE_UNMAPPED.bits() | Self::MEM_FETCH_UNMAPPED.bits();

        const MEM_READ_PROT = 0x80;
        const MEM_WRITE_PROT = 0x100;
        const MEM_FETCH_PROT = 0x200;
        const MEM_PROT = Self::MEM_READ_PROT.bits() | Self::MEM_WRITE_PROT.bits() | Self::MEM_FETCH_PROT.bits();

        const MEM_READ = 0x400;
        const MEM_WRITE = 0x800;
        const MEM_FETCH = 0x1000;
        const MEM_VALID = Self::MEM_READ.bits() | Self::MEM_WRITE.bits() | Self::MEM_FETCH.bits();

        const MEM_READ_AFTER = 0x2000;

        const INSN_INVALID = 0x4000;

        const MEM_READ_INVALID = Self::MEM_READ_UNMAPPED.bits() | Self::MEM_READ_PROT.bits();
        const MEM_WRITE_INVALID = Self::MEM_WRITE_UNMAPPED.bits() | Self::MEM_WRITE_PROT.bits();
        const MEM_FETCH_INVALID = Self::MEM_FETCH_UNMAPPED.bits() | Self::MEM_FETCH_PROT.bits();
        const MEM_INVALID = Self::MEM_READ_INVALID.bits() | Self::MEM_WRITE_INVALID.bits() | Self::MEM_FETCH_INVALID.bits();

        const MEM_ALL = Self::MEM_VALID.bits() | Self::MEM_INVALID.bits();

        const TLB = (1 << 17);
    }
}

#[repr(C)]
#[derive(PartialEq, Debug, Clone, Copy)]
#[allow(clippy::upper_case_acronyms)]
pub enum Query {
    MODE = 1,
    PAGE_SIZE = 2,
    ARCH = 3,
    TIMEOUT = 4,
}

bitflags! {
#[repr(C)]
    #[derive(Copy, Clone, Debug)]
pub struct Permission : u32 {
        const NONE = 0;
        const READ = 1;
        const WRITE = 2;
        const EXEC = 4;
        const ALL = Self::READ.bits() | Self::WRITE.bits() | Self::EXEC.bits();
    }
}

/// Represents a region of memory that is mapped and has certain access permissions.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct MemRegion {
    /// The address that the region begins at (inclusive).
    pub begin: u64,
    /// The address that the region begins at (inclusive).
    /// TODO: Inclusive?
    pub end: u64,
    /// The access permissions of the region (can it be read, written, and executed).
    pub perms: Permission,
}

#[repr(C)]
#[derive(PartialEq, Debug, Clone, Copy)]
pub enum Arch {
    ARM = 1,
    ARM64 = 2,
    MIPS = 3,
    X86 = 4,
    PPC = 5,
    SPARC = 6,
    M68K = 7,
    RISCV = 8,
    S390X = 9,
    TRICORE = 10,
    MAX = 11,
}

impl TryFrom<usize> for Arch {
    type Error = uc_error;

    fn try_from(v: usize) -> Result<Self, Self::Error> {
        match v {
            x if x == Self::ARM as usize => Ok(Self::ARM),
            x if x == Self::ARM64 as usize => Ok(Self::ARM64),
            x if x == Self::MIPS as usize => Ok(Self::MIPS),
            x if x == Self::X86 as usize => Ok(Self::X86),
            x if x == Self::PPC as usize => Ok(Self::PPC),
            x if x == Self::SPARC as usize => Ok(Self::SPARC),
            x if x == Self::M68K as usize => Ok(Self::M68K),
            x if x == Self::RISCV as usize => Ok(Self::RISCV),
            x if x == Self::S390X as usize => Ok(Self::S390X),
            x if x == Self::TRICORE as usize => Ok(Self::TRICORE),
            x if x == Self::MAX as usize => Ok(Self::MAX),
            _ => Err(uc_error::ARCH),
        }
    }
}

bitflags! {
    #[derive(Copy, Clone)]
    #[repr(C)]
    pub struct Mode: i32 {
        const LITTLE_ENDIAN = 0;
        const BIG_ENDIAN = 0x4000_0000;

        const ARM = 0;
        const THUMB = 0x10;
        const MCLASS = 0x20;
        const V8 = 0x40;
        const ARMBE8 = 0x400;
        const ARM926 = 0x80;
        const ARM946 = 0x100;
        const ARM1176 = 0x200;
        const MICRO = Self::THUMB.bits();
        const MIPS3 = Self::MCLASS.bits();
        const MIPS32R6 = Self::V8.bits();
        const MIPS32 = 4;
        const MIPS64 = 8;
        const MODE_16 = 2;
        const MODE_32 = Self::MIPS32.bits();
        const MODE_64 = Self::MIPS64.bits();
        const PPC32 = Self::MIPS32.bits();
        const PPC64 = Self::MIPS64.bits();
        const QPX = Self::THUMB.bits();
        const SPARC32 = Self::MIPS32.bits();
        const SPARC64 = Self::MIPS64.bits();
        const V9 = Self::THUMB.bits();
        const RISCV32 = Self::MIPS32.bits();
        const RISCV64 = Self::MIPS64.bits();
    }
}

// Represent a TranslationBlock.
#[repr(C)]
pub struct TranslationBlock {
    pub pc: u64,
    pub icount: u16,
    pub size: u16,
}

pub(crate) fn uc_ctl_read(ct: ControlType) -> u32 {
    ct as u32 | ControlType::UC_CTL_IO_READ as u32
}

pub(crate) fn uc_ctl_write(ct: ControlType) -> u32 {
    ct as u32 | ControlType::UC_CTL_IO_WRITE as u32
}

pub(crate) fn uc_ctl_read_write(ct: ControlType) -> u32 {
    ct as u32  | ControlType::UC_CTL_IO_WRITE as u32 | ControlType::UC_CTL_IO_READ as u32
}

#[allow(clippy::upper_case_acronyms)]
#[repr(u64)]
pub enum ControlType {
    UC_CTL_UC_MODE = 0,
    UC_CTL_UC_PAGE_SIZE = 1,
    UC_CTL_UC_ARCH = 2,
    UC_CTL_UC_TIMEOUT = 3,
    UC_CTL_UC_USE_EXITS = 4,
    UC_CTL_UC_EXITS_CNT = 5,
    UC_CTL_UC_EXITS = 6,
    UC_CTL_CPU_MODEL = 7,
    UC_CTL_TB_REQUEST_CACHE = 8,
    UC_CTL_TB_REMOVE_CACHE = 9,
    UC_CTL_TB_FLUSH = 10,
    UC_CTL_TLB_FLUSH = 11,
    UC_CTL_TLB_TYPE = 12,
    UC_CTL_TCG_BUFFER_SIZE = 13,
    UC_CTL_CONTEXT_MODE = 14,
    UC_CTL_IO_READ = 1 << 31,
    UC_CTL_IO_WRITE = 1 << 30,
}

bitflags! {
    #[derive(Debug, Copy, Clone)]
    #[repr(C)]
    pub struct ContextMode : u32 {
        const CPU    = 1;
        const Memory = 2;
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TlbEntry {
    pub paddr: u64,
    pub perms: Permission,
}
