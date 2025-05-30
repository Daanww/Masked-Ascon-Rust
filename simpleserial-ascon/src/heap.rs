// sim_test/src/heap.rs

//! Provides the kernel heap.

use embedded_alloc::Heap;

#[global_allocator]
static HEAP: Heap = Heap::empty();

/// Initialise the kernel heap.
/// # Safety
/// Must be called at most once.
pub unsafe fn init() {
    use core::arch::asm;
    let heap_bottom;
    let heap_size;
    // UNSAFE: This is fine, just loading some constants.
    unsafe {
        // using inline assembly is easier to access linker constants
        asm!(
          "la {heap_bottom}, _kernel_heap_bottom",
          "la {heap_size}, _kernel_heap_size",
          heap_bottom = out(reg) heap_bottom,
          heap_size = out(reg) heap_size,
          options(nomem)
        )
    };
    unsafe { HEAP.init(heap_bottom, heap_size) };
}
