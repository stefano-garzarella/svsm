(function() {
    var implementors = Object.fromEntries([["svsm",[["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/ops/drop/trait.Drop.html\" title=\"trait core::ops::drop::Drop\">Drop</a> for <a class=\"struct\" href=\"svsm/cpu/gdt/struct.GDT.html\" title=\"struct svsm::cpu::gdt::GDT\">GDT</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/ops/drop/trait.Drop.html\" title=\"trait core::ops::drop::Drop\">Drop</a> for <a class=\"struct\" href=\"svsm/cpu/irq_state/struct.IrqGuard.html\" title=\"struct svsm::cpu::irq_state::IrqGuard\">IrqGuard</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/ops/drop/trait.Drop.html\" title=\"trait core::ops::drop::Drop\">Drop</a> for <a class=\"struct\" href=\"svsm/cpu/irq_state/struct.IrqState.html\" title=\"struct svsm::cpu::irq_state::IrqState\">IrqState</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/ops/drop/trait.Drop.html\" title=\"trait core::ops::drop::Drop\">Drop</a> for <a class=\"struct\" href=\"svsm/cpu/irq_state/struct.TprGuard.html\" title=\"struct svsm::cpu::irq_state::TprGuard\">TprGuard</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/ops/drop/trait.Drop.html\" title=\"trait core::ops::drop::Drop\">Drop</a> for <a class=\"struct\" href=\"svsm/debug/gdbstub/svsm_gdbstub/struct.GdbTaskContext.html\" title=\"struct svsm::debug::gdbstub::svsm_gdbstub::GdbTaskContext\">GdbTaskContext</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/ops/drop/trait.Drop.html\" title=\"trait core::ops::drop::Drop\">Drop</a> for <a class=\"struct\" href=\"svsm/mm/alloc/struct.PageRef.html\" title=\"struct svsm::mm::alloc::PageRef\">PageRef</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/ops/drop/trait.Drop.html\" title=\"trait core::ops::drop::Drop\">Drop</a> for <a class=\"struct\" href=\"svsm/mm/global_memory/struct.GlobalRangeGuard.html\" title=\"struct svsm::mm::global_memory::GlobalRangeGuard\">GlobalRangeGuard</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/ops/drop/trait.Drop.html\" title=\"trait core::ops::drop::Drop\">Drop</a> for <a class=\"struct\" href=\"svsm/mm/guestmem/struct.UserAccessGuard.html\" title=\"struct svsm::mm::guestmem::UserAccessGuard\">UserAccessGuard</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/ops/drop/trait.Drop.html\" title=\"trait core::ops::drop::Drop\">Drop</a> for <a class=\"struct\" href=\"svsm/mm/mappings/struct.VMMappingGuard.html\" title=\"struct svsm::mm::mappings::VMMappingGuard\">VMMappingGuard</a>&lt;'_&gt;"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/ops/drop/trait.Drop.html\" title=\"trait core::ops::drop::Drop\">Drop</a> for <a class=\"struct\" href=\"svsm/mm/pagetable/struct.RawPageTablePart.html\" title=\"struct svsm::mm::pagetable::RawPageTablePart\">RawPageTablePart</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/ops/drop/trait.Drop.html\" title=\"trait core::ops::drop::Drop\">Drop</a> for <a class=\"struct\" href=\"svsm/mm/ptguards/struct.PerCPUPageMappingGuard.html\" title=\"struct svsm::mm::ptguards::PerCPUPageMappingGuard\">PerCPUPageMappingGuard</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/ops/drop/trait.Drop.html\" title=\"trait core::ops::drop::Drop\">Drop</a> for <a class=\"struct\" href=\"svsm/mm/virtualrange/struct.VRangeAlloc.html\" title=\"struct svsm::mm::virtualrange::VRangeAlloc\">VRangeAlloc</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/ops/drop/trait.Drop.html\" title=\"trait core::ops::drop::Drop\">Drop</a> for <a class=\"struct\" href=\"svsm/mm/vm/struct.VMRMapping.html\" title=\"struct svsm::mm::vm::VMRMapping\">VMRMapping</a>&lt;'_&gt;"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/ops/drop/trait.Drop.html\" title=\"trait core::ops::drop::Drop\">Drop</a> for <a class=\"struct\" href=\"svsm/sev/ghcb/struct.GhcbPage.html\" title=\"struct svsm::sev::ghcb::GhcbPage\">GhcbPage</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/ops/drop/trait.Drop.html\" title=\"trait core::ops::drop::Drop\">Drop</a> for <a class=\"struct\" href=\"svsm/sev/vmsa/struct.VmsaPage.html\" title=\"struct svsm::sev::vmsa::VmsaPage\">VmsaPage</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/ops/drop/trait.Drop.html\" title=\"trait core::ops::drop::Drop\">Drop</a> for <a class=\"struct\" href=\"svsm/task/tasks/struct.TaskVirtualRegionGuard.html\" title=\"struct svsm::task::tasks::TaskVirtualRegionGuard\">TaskVirtualRegionGuard</a>"],["impl&lt;T&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/ops/drop/trait.Drop.html\" title=\"trait core::ops::drop::Drop\">Drop</a> for <a class=\"struct\" href=\"svsm/mm/page_visibility/struct.SharedBox.html\" title=\"struct svsm::mm::page_visibility::SharedBox\">SharedBox</a>&lt;T&gt;"],["impl&lt;T&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/ops/drop/trait.Drop.html\" title=\"trait core::ops::drop::Drop\">Drop</a> for <a class=\"struct\" href=\"svsm/utils/immut_after_init/struct.ImmutAfterInitCell.html\" title=\"struct svsm::utils::immut_after_init::ImmutAfterInitCell\">ImmutAfterInitCell</a>&lt;T&gt;"],["impl&lt;T&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/ops/drop/trait.Drop.html\" title=\"trait core::ops::drop::Drop\">Drop</a> for <a class=\"struct\" href=\"svsm/utils/scoped/struct.ScopedMut.html\" title=\"struct svsm::utils::scoped::ScopedMut\">ScopedMut</a>&lt;'_, T&gt;"],["impl&lt;T&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/ops/drop/trait.Drop.html\" title=\"trait core::ops::drop::Drop\">Drop</a> for <a class=\"struct\" href=\"svsm/utils/scoped/struct.ScopedRef.html\" title=\"struct svsm::utils::scoped::ScopedRef\">ScopedRef</a>&lt;'_, T&gt;"],["impl&lt;T, I&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/ops/drop/trait.Drop.html\" title=\"trait core::ops::drop::Drop\">Drop</a> for <a class=\"struct\" href=\"svsm/locking/rwlock/struct.RawReadLockGuard.html\" title=\"struct svsm::locking::rwlock::RawReadLockGuard\">RawReadLockGuard</a>&lt;'_, T, I&gt;"],["impl&lt;T, I&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/ops/drop/trait.Drop.html\" title=\"trait core::ops::drop::Drop\">Drop</a> for <a class=\"struct\" href=\"svsm/locking/rwlock/struct.RawWriteLockGuard.html\" title=\"struct svsm::locking::rwlock::RawWriteLockGuard\">RawWriteLockGuard</a>&lt;'_, T, I&gt;"],["impl&lt;T, I&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/ops/drop/trait.Drop.html\" title=\"trait core::ops::drop::Drop\">Drop</a> for <a class=\"struct\" href=\"svsm/locking/spinlock/struct.RawLockGuard.html\" title=\"struct svsm::locking::spinlock::RawLockGuard\">RawLockGuard</a>&lt;'_, T, I&gt;"],["impl&lt;T: ?<a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/marker/trait.Sized.html\" title=\"trait core::marker::Sized\">Sized</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.86.0/core/ops/drop/trait.Drop.html\" title=\"trait core::ops::drop::Drop\">Drop</a> for <a class=\"struct\" href=\"svsm/mm/struct.PageBox.html\" title=\"struct svsm::mm::PageBox\">PageBox</a>&lt;T&gt;"]]]]);
    if (window.register_implementors) {
        window.register_implementors(implementors);
    } else {
        window.pending_implementors = implementors;
    }
})()
//{"start":57,"fragment_lengths":[7349]}