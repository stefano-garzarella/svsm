use super::*;

use crate::address::PhysAddr;
use crate::error::SvsmError;
use crate::locking::{RWLock, SpinLock};
use crate::mm::PerCPUPageMappingGuard;
use crate::virtio::SvsmHal;

use core::ops::DerefMut;
use core::ptr::NonNull;

use virtio_drivers::{
    device::blk::{VirtIOBlk, SECTOR_SIZE},
    transport::mmio::{MmioTransport, VirtIOHeader},
};

pub trait BlockDriver {
    fn read_blocks(&self, _block_id: usize, _buf: &mut [u8]) -> Result<(), FsError>;
    fn write_blocks(&self, _block_id: usize, _buf: &[u8]) -> Result<(), FsError>;
    fn block_size_log2(&self) -> u8;
}

type VirtIOBlkDevice = VirtIOBlk<SvsmHal, MmioTransport<SvsmHal>>;

struct VirtIOBlkDriver(SpinLock<VirtIOBlkDevice>);

impl BlockDriver for VirtIOBlkDriver {
    fn read_blocks(&self, block_id: usize, buf: &mut [u8]) -> Result<(), FsError> {
        self.0
            .lock()
            .read_blocks(block_id, buf)
            .map_err(|_| FsError::Inval)
    }

    fn write_blocks(&self, block_id: usize, buf: &[u8]) -> Result<(), FsError> {
        self.0
            .lock()
            .write_blocks(block_id, buf)
            .map_err(|_| FsError::Inval)
    }

    fn block_size_log2(&self) -> u8 {
        SECTOR_SIZE.ilog2().try_into().unwrap()
    }
}

unsafe impl Send for VirtIOBlkDriver {}
unsafe impl Sync for VirtIOBlkDriver {}

static BLOCK_DEVICE: RWLock<Option<VirtIOBlkDriver>> = RWLock::new(None);

pub fn initialize_blk(mmio_base: u64) {
    let paddr = PhysAddr::from(mmio_base);
    let mem = PerCPUPageMappingGuard::create_4k(paddr).expect("Error mapping MMIO region");
    let header = NonNull::new(mem.virt_addr().as_mut_ptr() as *mut VirtIOHeader).unwrap();
    let transport = unsafe { MmioTransport::<SvsmHal>::new(header).unwrap() };
    let blk: VirtIOBlkDevice = VirtIOBlk::new(transport).expect("Failed to create blk driver");

    *BLOCK_DEVICE.lock_write().deref_mut() = Some(VirtIOBlkDriver(SpinLock::new(blk)));
}

// Code from https://github.com/rcore-os/rcore-fs/blob/master/rcore-fs/src/dev/mod.rs
// TODO: add proper copyright
pub struct BlockIter {
    pub begin: usize,
    pub end: usize,
    pub block_size_log2: u8,
}

#[derive(Debug, Eq, PartialEq)]
pub struct BlockRange {
    pub block: usize,
    pub begin: usize,
    pub end: usize,
    pub block_size_log2: u8,
}

impl BlockRange {
    pub fn is_empty(&self) -> bool {
        self.end == self.begin
    }
    pub fn len(&self) -> usize {
        self.end - self.begin
    }
    pub fn is_full(&self) -> bool {
        self.len() == (1usize << self.block_size_log2)
    }
    pub fn origin_begin(&self) -> usize {
        (self.block << self.block_size_log2) + self.begin
    }
    pub fn origin_end(&self) -> usize {
        (self.block << self.block_size_log2) + self.end
    }
}

impl Iterator for BlockIter {
    type Item = BlockRange;

    fn next(&mut self) -> Option<<Self as Iterator>::Item> {
        if self.begin >= self.end {
            return None;
        }
        let block_size_log2 = self.block_size_log2;
        let block_size = 1usize << self.block_size_log2;
        let block = self.begin / block_size;
        let begin = self.begin % block_size;
        let end = if block == self.end / block_size {
            self.end % block_size
        } else {
            block_size
        };
        self.begin += end - begin;
        Some(BlockRange {
            block,
            begin,
            end,
            block_size_log2,
        })
    }
}

macro_rules! try0 {
    ($len:expr, $res:expr) => {
        if $res.is_err() {
            return Ok($len);
        }
    };
}

#[derive(Debug, Default)]
struct RawBlockFile {
    sector: usize,
    size: usize,
}

impl RawBlockFile {
    pub fn new(sector: usize, size: usize) -> Self {
        RawBlockFile { sector, size }
    }

    fn read_blocks(
        &self,
        device: &dyn BlockDriver,
        block_id: usize,
        buf: &mut [u8],
    ) -> Result<(), FsError> {
        device.read_blocks(self.sector + block_id, buf)
    }

    fn write_blocks(
        &self,
        device: &dyn BlockDriver,
        block_id: usize,
        buf: &[u8],
    ) -> Result<(), FsError> {
        device.write_blocks(self.sector + block_id, buf)
    }

    fn read(&self, buf: &mut [u8], offset: usize) -> Result<usize, SvsmError> {
        let device_guard = BLOCK_DEVICE.lock_read();
        let device = device_guard
            .as_ref()
            .ok_or(SvsmError::from(FsError::Inval))?;

        let iter = BlockIter {
            begin: offset,
            end: offset + buf.len(),
            block_size_log2: device.block_size_log2(),
        };

        // For each block
        for range in iter {
            let len = range.origin_begin() - offset;
            let buf = &mut buf[range.origin_begin() - offset..range.origin_end() - offset];
            if range.is_full() {
                // Read to target buf directly
                try0!(len, self.read_blocks(device, range.block, buf));
            } else {
                let mut block_buf = [0u8; 1 << 10];
                assert!(device.block_size_log2() <= 10);
                // Read to local buf first
                try0!(len, self.read_blocks(device, range.block, &mut block_buf));
                // Copy to target buf then
                buf.copy_from_slice(&block_buf[range.begin..range.end]);
            }
        }
        Ok(buf.len())
    }

    fn write(&self, buf: &[u8], offset: usize) -> Result<usize, SvsmError> {
        let device_guard = BLOCK_DEVICE.lock_read();
        let device = device_guard
            .as_ref()
            .ok_or(SvsmError::from(FsError::Inval))?;

        let iter = BlockIter {
            begin: offset,
            end: offset + buf.len(),
            block_size_log2: device.block_size_log2(),
        };

        // For each block
        for range in iter {
            let len = range.origin_begin() - offset;
            let buf = &buf[range.origin_begin() - offset..range.origin_end() - offset];
            if range.is_full() {
                // Write to target buf directly
                try0!(len, self.write_blocks(device, range.block, buf));
            } else {
                #[allow(clippy::uninit_assumed_init)]
                let mut block_buf = [0u8; 1 << 10];
                assert!(device.block_size_log2() <= 10);
                // Read to local buf first
                try0!(len, self.read_blocks(device, range.block, &mut block_buf));
                // Write to local buf
                block_buf[range.begin..range.end].copy_from_slice(buf);
                // Write back to target buf
                try0!(len, self.write_blocks(device, range.block, &block_buf));
            }
        }
        Ok(buf.len())
    }

    fn truncate(&self, size: usize) -> Result<usize, SvsmError> {
        if size > self.size {
            return Err(SvsmError::from(FsError::Inval));
        }

        Ok(self.size)
    }

    fn size(&self) -> usize {
        self.size
    }
}

#[derive(Debug)]
pub struct BlockFile {
    rawfile: RWLock<RawBlockFile>,
}

impl BlockFile {
    /// Used to get a new instance of [`BlockFile`].
    #[allow(dead_code)]
    pub fn new(sector: usize, size: usize) -> Self {
        BlockFile {
            rawfile: RWLock::new(RawBlockFile::new(sector, size)),
        }
    }
}

impl File for BlockFile {
    fn read(&self, buf: &mut [u8], offset: usize) -> Result<usize, SvsmError> {
        self.rawfile.lock_read().read(buf, offset)
    }

    fn write(&self, buf: &[u8], offset: usize) -> Result<usize, SvsmError> {
        self.rawfile.lock_write().write(buf, offset)
    }

    fn truncate(&self, size: usize) -> Result<usize, SvsmError> {
        self.rawfile.lock_write().truncate(size)
    }

    fn size(&self) -> usize {
        self.rawfile.lock_read().size()
    }
}
