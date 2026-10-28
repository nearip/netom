//! Thread-local measurements keep parallel tests out of allocation/clone counts.
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
};

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Counts {
    pub ingress_clones: usize,
    pub route_clones: usize,
    pub peak_bytes: usize,
    live_bytes: isize,
}
thread_local! {
    static COUNTS: Cell<Option<Counts>> = const { Cell::new(None) };
}
pub(crate) fn ingress_clone() {
    update(|c| c.ingress_clones += 1);
}
pub(crate) fn route_clone() {
    update(|c| c.route_clones += 1);
}
fn update(f: impl FnOnce(&mut Counts)) {
    let _ = COUNTS.try_with(|slot| {
        if let Some(mut c) = slot.get() {
            f(&mut c);
            slot.set(Some(c));
        }
    });
}
struct MeasuringAllocator;
#[global_allocator]
static ALLOCATOR: MeasuringAllocator = MeasuringAllocator;
unsafe impl GlobalAlloc for MeasuringAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = System.alloc(layout);
        if !ptr.is_null() {
            update(|c| {
                c.live_bytes += layout.size() as isize;
                c.peak_bytes = c.peak_bytes.max(c.live_bytes.max(0) as usize);
            });
        }
        ptr
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        update(|c| c.live_bytes -= layout.size() as isize);
        System.dealloc(ptr, layout);
    }
    unsafe fn realloc(
        &self,
        ptr: *mut u8,
        layout: Layout,
        size: usize,
    ) -> *mut u8 {
        let ptr = System.realloc(ptr, layout, size);
        if !ptr.is_null() {
            update(|c| {
                c.live_bytes += size as isize - layout.size() as isize;
                c.peak_bytes = c.peak_bytes.max(c.live_bytes.max(0) as usize);
            });
        }
        ptr
    }
}
pub(crate) fn measure<T>(f: impl FnOnce() -> T) -> (T, Counts) {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            COUNTS.with(|c| c.set(None));
        }
    }
    COUNTS.with(|c| {
        assert!(c.get().is_none());
        c.set(Some(Counts::default()));
    });
    let _reset = Reset;
    let result = f();
    let counts = COUNTS.with(|c| c.get().unwrap());
    (result, counts)
}
