
#[derive(Debug)]
pub struct PageMemory {
    addr: crate::address::VirtAddr,
    size: usize,
}

impl PageMemory {
    fn allocate(size: usize) -> Result<VirtAddr, SvsmError> {
        use crate::mm::alloc::{allocate_pages, get_order};
        allocate_pages(get_order(size))
    }

    #[allow(dead_code)]
    pub fn new_zeroed(size: usize) -> PageMemory {
        let va = PageMemory::allocate(size).unwrap();
        crate::utils::zero_mem_region(va, va + size);
        PageMemory { addr: va, size }
    }

    #[allow(dead_code)]
    pub fn new(size: usize) -> PageMemory {
        let va = PageMemory::allocate(size).unwrap();
        PageMemory { addr: va, size }
    }
}

impl Drop for PageMemory {
    fn drop(&mut self) {
        crate::mm::alloc::free_page(self.addr);
    }
}

use core::ops::Deref;
impl Deref for PageMemory {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.addr.as_ptr::<u8>(), self.size) }
    }
}

use core::ops::DerefMut;

use crate::address::VirtAddr;
use crate::error::SvsmError;
impl DerefMut for PageMemory {
    fn deref_mut(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.addr.as_mut_ptr::<u8>(), self.size) }
    }
}

