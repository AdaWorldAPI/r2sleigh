//! The process allocator, an allocation count for the timing gate (ROADMAP PF4), and a heap
//! profile (`dhat-heap`, which takes the allocator where both are asked for).

#[cfg(not(any(feature = "alloc-count", feature = "dhat-heap")))]
#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[cfg(feature = "dhat-heap")]
#[global_allocator]
static ALLOCATOR: dhat::Alloc = dhat::Alloc;

#[cfg(all(feature = "alloc-count", not(feature = "dhat-heap")))]
#[global_allocator]
static ALLOCATOR: Counting = Counting;

#[cfg(all(feature = "alloc-count", not(feature = "dhat-heap")))]
static ALLOCATIONS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// mimalloc, counting each allocation and reallocation.
#[cfg(all(feature = "alloc-count", not(feature = "dhat-heap")))]
struct Counting;

// SAFETY: each method forwards its arguments unchanged to mimalloc's own.
#[cfg(all(feature = "alloc-count", not(feature = "dhat-heap")))]
unsafe impl std::alloc::GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        unsafe { mimalloc::MiMalloc.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: std::alloc::Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        unsafe { mimalloc::MiMalloc.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: std::alloc::Layout, size: usize) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        unsafe { mimalloc::MiMalloc.realloc(ptr, layout, size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: std::alloc::Layout) {
        unsafe { mimalloc::MiMalloc.dealloc(ptr, layout) }
    }
}

/// The heap profile of one run, where the build takes one; written when it drops.
pub struct Profile {
    #[cfg(feature = "dhat-heap")]
    _heap: dhat::Profiler,
}

/// Start profiling the heap, where the build profiles it.
pub fn profile() -> Profile {
    Profile {
        #[cfg(feature = "dhat-heap")]
        _heap: dhat::Profiler::new_heap(),
    }
}

/// The allocation count on stderr where this build counts them and `R2S_ALLOCATIONS` asks
/// (`census.py time` reads it), and the heap profile written, before a script exits.
pub fn report(_profile: Profile) {
    #[cfg(all(feature = "alloc-count", not(feature = "dhat-heap")))]
    if std::env::var_os("R2S_ALLOCATIONS").is_some() {
        eprintln!(
            "r2s: allocations: {}",
            ALLOCATIONS.load(std::sync::atomic::Ordering::Relaxed)
        );
    }
}
