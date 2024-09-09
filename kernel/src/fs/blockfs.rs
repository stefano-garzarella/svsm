use super::*;

use crate::address::PhysAddr;
use crate::error::SvsmError;
use crate::locking::{RWLock, SpinLock};
use crate::mm::PerCPUPageMappingGuard;
use crate::virtio::SvsmHal;

use core::cmp::min;
use core::ops::DerefMut;
use core::ptr::NonNull;

use aes_gcm::{aes::cipher::generic_array::GenericArray, aes::cipher::KeyInit, aes::Aes256};
use postcard;
use serde::{Deserialize, Serialize};
use virtio_drivers::{
    device::blk::{VirtIOBlk, SECTOR_SIZE},
    transport::mmio::{MmioTransport, VirtIOHeader},
};
use xts_mode::{get_tweak_default, Xts128};

pub trait BlockDriver {
    fn read_blocks(&self, _block_id: usize, _buf: &mut [u8]) -> Result<(), FsError>;
    fn write_blocks(&self, _block_id: usize, _buf: &[u8]) -> Result<(), FsError>;
    fn block_size_log2(&self) -> u8;
}

type VirtIOBlkDevice = VirtIOBlk<SvsmHal, MmioTransport<SvsmHal>>;

struct VirtIOBlkDriver {
    device: SpinLock<VirtIOBlkDevice>,
    mem: PerCPUPageMappingGuard,
    xts: Option<Xts128<Aes256>>,
}

impl VirtIOBlkDriver {
    fn new(mmio_base: u64, encryption_key: Option<&[u8; 64]>) -> Self {
        let paddr = PhysAddr::from(mmio_base);
        let mem = PerCPUPageMappingGuard::create_4k(paddr).expect("Error mapping MMIO region");
        let header = NonNull::new(mem.virt_addr().as_mut_ptr() as *mut VirtIOHeader).unwrap();
        let transport = unsafe { MmioTransport::<SvsmHal>::new(header).unwrap() };
        let blk: VirtIOBlkDevice = VirtIOBlk::new(transport).expect("Failed to create blk driver");

        let xts = if let Some(key) = encryption_key {
            let cipher_1 = Aes256::new(GenericArray::from_slice(&key[..32]));
            let cipher_2 = Aes256::new(GenericArray::from_slice(&key[32..]));
            Some(Xts128::<Aes256>::new(cipher_1, cipher_2))
        } else {
            None
        };

        VirtIOBlkDriver {
            device: SpinLock::new(blk),
            mem,
            xts,
        }
    }
}

impl BlockDriver for VirtIOBlkDriver {
    fn read_blocks(&self, block_id: usize, buf: &mut [u8]) -> Result<(), FsError> {
        self.device
            .lock()
            .read_blocks(block_id, buf)
            .map_err(|_| FsError::Inval)?;

        if let Some(xts) = &self.xts {
            xts.decrypt_area(buf, SECTOR_SIZE, 0, get_tweak_default);
        }

        Ok(())
    }

    fn write_blocks(&self, block_id: usize, buf: &[u8]) -> Result<(), FsError> {
        if let Some(xts) = &self.xts {
            let mut buf_enc = buf.to_vec();

            xts.encrypt_area(&mut buf_enc, SECTOR_SIZE, 0, get_tweak_default);

            self.device
                .lock()
                .write_blocks(block_id, &buf_enc)
                .map_err(|_| FsError::Inval)
        } else {
            self.device
                .lock()
                .write_blocks(block_id, buf)
                .map_err(|_| FsError::Inval)
        }
    }

    fn block_size_log2(&self) -> u8 {
        SECTOR_SIZE.ilog2().try_into().unwrap()
    }
}

unsafe impl Send for VirtIOBlkDriver {}
unsafe impl Sync for VirtIOBlkDriver {}

static BLOCK_DEVICE: RWLock<Option<VirtIOBlkDriver>> = RWLock::new(None);

pub fn initialize_blk(mmio_base: u64, key: Option<&[u8; 64]>) {
    *BLOCK_DEVICE.lock_write().deref_mut() = Some(VirtIOBlkDriver::new(mmio_base, key));
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

#[derive(Serialize, Deserialize, Debug)]
struct RawMetadata {
    magic: u32,
    size: usize,
}

impl RawMetadata {
    const MAGIC: u32 = 0xDEADBEEF;

    fn check(&self) -> bool {
        self.magic == Self::MAGIC
    }
}

impl Default for RawMetadata {
    fn default() -> Self {
        RawMetadata {
            magic: Self::MAGIC,
            size: 0,
        }
    }
}

#[derive(Debug, Default)]
struct RawBlockFile {
    sector: usize,
    capacity: usize,
    metadata: RawMetadata,
}

impl RawBlockFile {
    pub fn new(sector: usize, capacity: usize) -> Self {
        let mut file = RawBlockFile {
            sector,
            capacity,
            metadata: RawMetadata::default(),
        };

        file.read_metadata().unwrap();
        file
    }

    fn read_metadata(&mut self) -> Result<(), FsError> {
        let device_guard = BLOCK_DEVICE.lock_read();
        let device = device_guard.as_ref().ok_or(FsError::Inval)?;

        let mut buf = [0u8; SECTOR_SIZE];
        device.read_blocks(self.sector, &mut buf)?;

        self.metadata = match postcard::from_bytes::<RawMetadata>(&buf) {
            Ok(metadata) => {
                if metadata.check() {
                    metadata
                } else {
                    RawMetadata::default()
                }
            }
            Err(_) => RawMetadata::default(),
        };

        Ok(())
    }

    fn write_metadata(&self) -> Result<(), FsError> {
        let device_guard = BLOCK_DEVICE.lock_read();
        let device = device_guard.as_ref().ok_or(FsError::Inval)?;

        let mut buf = [0u8; SECTOR_SIZE];
        let _ = postcard::to_slice(&self.metadata, &mut buf).unwrap();
        device.write_blocks(self.sector, &buf)
    }

    fn update_size(&mut self, size: usize) -> Result<(), FsError> {
        self.metadata.size = size;
        self.write_metadata()
    }

    fn read_blocks(
        &self,
        device: &dyn BlockDriver,
        block_id: usize,
        buf: &mut [u8],
    ) -> Result<(), FsError> {
        device.read_blocks(self.sector + 1 + block_id, buf)
    }

    fn write_blocks(
        &self,
        device: &dyn BlockDriver,
        block_id: usize,
        buf: &[u8],
    ) -> Result<(), FsError> {
        device.write_blocks(self.sector + 1 + block_id, buf)
    }

    fn read_device(&self, buf: &mut [u8], offset: usize) -> Result<usize, SvsmError> {
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
                let mut block_buf = [0u8; SECTOR_SIZE];
                assert!(device.block_size_log2() as u32 <= SECTOR_SIZE.ilog2());
                // Read to local buf first
                try0!(len, self.read_blocks(device, range.block, &mut block_buf));
                // Copy to target buf then
                buf.copy_from_slice(&block_buf[range.begin..range.end]);
            }
        }
        Ok(buf.len())
    }

    fn write_device(&mut self, buf: &[u8], offset: usize) -> Result<usize, SvsmError> {
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
                let mut block_buf = [0u8; SECTOR_SIZE];
                assert!(device.block_size_log2() as u32 <= SECTOR_SIZE.ilog2());
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

    fn read(&self, buf: &mut [u8], offset: usize) -> Result<usize, SvsmError> {
        if offset > self.capacity {
            return Err(SvsmError::from(FsError::Inval));
        }

        if offset > self.metadata.size {
            return Ok(0);
        }

        let len = min(self.metadata.size - offset, buf.len());

        self.read_device(&mut buf[..len], offset)
    }

    fn write(&mut self, buf: &[u8], offset: usize) -> Result<usize, SvsmError> {
        if offset + buf.len() > self.capacity {
            return Err(SvsmError::from(FsError::Inval));
        }

        let written = self.write_device(buf, offset)?;

        if offset + written > self.metadata.size {
            self.update_size(offset + written)?;
        }

        Ok(written)
    }

    fn truncate(&mut self, size: usize) -> Result<usize, SvsmError> {
        if size > self.capacity {
            return Err(SvsmError::from(FsError::Inval));
        }

        // TODO: support it writing zeros
        if size > self.metadata.size {
            return Err(SvsmError::FileSystem(FsError::inval()));
        }

        self.update_size(size)?;

        Ok(size)
    }

    fn size(&self) -> usize {
        self.metadata.size
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
