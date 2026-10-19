#![cfg(feature = "v2-crypto")]
// Reviewer allocation probe: peak live heap during interpret() versus the
// declared budgets. Run with --test-threads=1 (global counters).
use kan::evidence_interpretation as p;
use std::{
    alloc::{GlobalAlloc, Layout, System},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering::Relaxed},
        Arc,
    },
    time::{Duration, Instant},
};
struct Counting;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let n = LIVE.fetch_add(l.size(), Relaxed) + l.size();
        PEAK.fetch_max(n, Relaxed);
        System.alloc(l)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, l: Layout) {
        LIVE.fetch_sub(l.size(), Relaxed);
        System.dealloc(ptr, l)
    }
    unsafe fn realloc(&self, ptr: *mut u8, l: Layout, new: usize) -> *mut u8 {
        if new > l.size() {
            let n = LIVE.fetch_add(new - l.size(), Relaxed) + new - l.size();
            PEAK.fetch_max(n, Relaxed);
        } else {
            LIVE.fetch_sub(l.size() - new, Relaxed);
        }
        System.realloc(ptr, l, new)
    }
}
#[global_allocator]
static G: Counting = Counting;

fn measure(name: &str, bytes: &[u8], f: p::Format) {
    let l = p::Limits {
        input_bytes: bytes.len(),
        items: 10_000_000,
        // Budget set to the smallest successful value below, so the ratio is
        // peak heap per *permitted* output byte.
        output_bytes: u64::MAX,
        scan_bytes: u64::MAX,
        citations: 0,
        duration: Duration::from_secs(120),
        cancelled: Arc::new(AtomicBool::new(false)),
    };
    let probe = p::interpret(bytes, f, l.clone()).unwrap();
    let (out, items) = (probe.output_bytes, probe.items.len());
    drop(probe);
    let mut exact = l;
    exact.output_bytes = out;
    exact.items = items;
    let base = LIVE.load(Relaxed);
    PEAK.store(base, Relaxed);
    let t = Instant::now();
    let d = p::interpret(bytes, f, exact).unwrap();
    let el = t.elapsed();
    let peak = PEAK.load(Relaxed) - base;
    let retained = LIVE.load(Relaxed) - base;
    println!(
        "ALLOC {name}: input={} items={} output_budget_used={} scanned={} peak_heap={} retained_heap={} peak/input={:.1} peak/output_budget={:.1} time={:?}",
        bytes.len(), d.items.len(), out, d.scanned_bytes, peak, retained,
        peak as f64 / bytes.len() as f64, peak as f64 / out as f64, el
    );
    drop(d);
}
#[test]
fn alloc_amplification() {
    let n = 1 << 20;
    // JSON array of zeros: 2 bytes/element in, one Value per element.
    let mut zeros = b"{\"type\":\"message\",\"content\":[],\"x\":[".to_vec();
    while zeros.len() < n {
        zeros.extend(b"0,");
    }
    zeros.extend(b"0]}");
    measure("json-zero-array", &zeros, p::Format::Response);
    let mut empties = b"{\"type\":\"message\",\"content\":[],\"x\":[".to_vec();
    while empties.len() < n {
        empties.extend(b"{},");
    }
    empties.extend(b"{}]}");
    measure("json-empty-object-array", &empties, p::Format::Response);
    // Many tiny content blocks: one Item each with pointer+role strings.
    let mut blocks = b"{\"messages\":[{\"role\":\"assistant\",\"content\":[".to_vec();
    while blocks.len() < n {
        blocks.extend(b"\"\",");
    }
    blocks.extend(b"\"\"]}]}");
    measure("request-many-empty-text-blocks", &blocks, p::Format::Request);
    // Many tiny SSE events retaining event JSON.
    let ev = b"data:{}\n\n";
    let sse = ev.repeat(n / ev.len());
    measure("sse-many-empty-events", &sse, p::Format::Sse);
    let ev = b"\n";
    measure("sse-many-blank-lines", &ev.repeat(n), p::Format::Sse);
    // Sparse indices: many distinct huge block indices.
    let mut s = b"data:{\"type\":\"message_start\",\"message\":{\"type\":\"message\",\"role\":\"assistant\",\"content\":[]}}\n\n".to_vec();
    let mut k: u64 = u64::MAX;
    while s.len() < n {
        s.extend(format!("data:{{\"type\":\"content_block_start\",\"index\":{k},\"content_block\":{{\"type\":\"tool_use\",\"name\":\"\",\"input\":{{}}}}}}\n\n").as_bytes());
        k -= 1_000_000_007;
    }
    measure("sse-sparse-indices", &s, p::Format::Sse);
    // One giant line without newline (Truncated) and one giant data line.
    measure("sse-giant-unterminated-line", &vec![b'x'; n], p::Format::Sse);
    let mut g = b"data: \"".to_vec();
    g.extend(vec![b'y'; n]);
    g.extend(b"\"\n\n");
    measure("sse-giant-data-string", &g, p::Format::Sse);
}
