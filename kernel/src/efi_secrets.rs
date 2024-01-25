extern crate alloc;

use alloc::string::String;
use core::mem::size_of;
use core::ptr;
use core::str::FromStr;

use crate::{
    address::{Address, PhysAddr},
    error::SvsmError,
    fw_meta::{SevFWMetaData, Uuid},
    mm::PerCPUPageMappingGuard,
    types::PAGE_SIZE,
};

const EFI_SECRET_TABLE_HEADER_GUID: &str = "1e74f542-71dd-4d66-963e-ef4287ff173b";
const LUKS_KEY_GUID: &str = "736869e5-84f0-4973-92ec-06879ce3da0b";

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
struct EFISecretEntryHeader {
    guid: [u8; size_of::<Uuid>()],
    len: u32,
}

impl EFISecretEntryHeader {
    fn new(guid: [u8; size_of::<Uuid>()], data_len: usize) -> Self {
        EFISecretEntryHeader {
            guid,
            len: (data_len + size_of::<Self>()) as u32,
        }
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
struct EFISecretHeader {
    guid: [u8; size_of::<Uuid>()],
    len: u32,
}

impl Default for EFISecretHeader {
    fn default() -> Self {
        EFISecretHeader {
            guid: Uuid::from_str(EFI_SECRET_TABLE_HEADER_GUID).unwrap().into(),
            len: size_of::<Self>() as u32,
        }
    }
}

pub fn inject_efi_secrets_to_fw(fw_meta: &SevFWMetaData, secret: String) -> Result<(), SvsmError> {
    let efi_secret_page = match fw_meta.efi_secret_page {
        Some(addr) => addr,
        None => {
            log::info!("FW does not specify SEV_SECRET location",);
            return Ok(());
        }
    };

    let mut hdr = EFISecretHeader::default();

    let entry_payload_src = secret.as_bytes();
    let entry_hdr = EFISecretEntryHeader::new(
        Uuid::from_str(LUKS_KEY_GUID)?.into(),
        entry_payload_src.len(),
    );

    let total_len = hdr.len + entry_hdr.len;

    hdr.len = if total_len as usize > PAGE_SIZE {
        log::error!(
            "EFI secret: table size [{}] exceeds the max size [{}]",
            total_len,
            PAGE_SIZE,
        );
        return Err(SvsmError::Firmware);
    } else {
        total_len
    };

    let guard = PerCPUPageMappingGuard::create_4k(efi_secret_page)?;
    let start = guard.virt_addr();

    let hdr_ptr = ptr::NonNull::new(start.as_mut_ptr::<EFISecretHeader>()).unwrap();

    let entry_hdr_vaddr = start
        .checked_add(size_of::<EFISecretHeader>())
        .ok_or(SvsmError::Firmware)?;
    let entry_hdr_ptr =
        ptr::NonNull::new(entry_hdr_vaddr.as_mut_ptr::<EFISecretEntryHeader>()).unwrap();

    let entry_payload_vaddr = entry_hdr_vaddr
        .checked_add(size_of::<EFISecretEntryHeader>())
        .ok_or(SvsmError::Firmware)?;
    let entry_payload_dst = ptr::NonNull::new(entry_payload_vaddr.as_mut_ptr::<u8>()).unwrap();

    // Copy data
    unsafe {
        *hdr_ptr.as_ptr() = hdr;
        *entry_hdr_ptr.as_ptr() = entry_hdr;

        ptr::copy(
            entry_payload_src.as_ptr(),
            entry_payload_dst.as_ptr(),
            entry_payload_src.len(),
        );
    }

    Ok(())
}

pub fn set_sev_secret_addr(
    meta: &mut SevFWMetaData,
    efi_secret_bytes: &[u8],
) -> Result<(), SvsmError> {
    let (base_bytes, size_bytes) = efi_secret_bytes.split_at(size_of::<u32>());
    let efi_secret_base =
        u32::from_le_bytes(base_bytes.try_into().map_err(|_| SvsmError::Firmware)?) as usize;

    log::debug!("EFI secret: base {}", efi_secret_base);

    let efi_secret_size =
        u32::from_le_bytes(size_bytes.try_into().map_err(|_| SvsmError::Firmware)?) as usize;

    log::debug!("EFI secret: size {}", efi_secret_size);

    if efi_secret_size != PAGE_SIZE {
        log::error!(
            "EFI secret: expected PAGE_SIZE[{}] len, found {}",
            PAGE_SIZE,
            efi_secret_size
        );
        return Err(SvsmError::Firmware);
    }

    meta.efi_secret_page = Some(PhysAddr::from(efi_secret_base));

    Ok(())
}
