//! Robustness: the engine parses hostile network input as administrator. No input may panic it,
//! and nothing that is held back may be lost (every captured packet is sent or deliberately replaced).
use crate::engine::{Addr, Engine, PacketIo, Plan};
use crate::quic_sni::tests::build_initial;
use crate::tcp::tests::mk4;
use crate::tls::tests::{hello, hello_late_sni};

#[derive(Default)]
struct Sink(usize);
impl PacketIo for Sink {
    fn recv(&mut self, _: &mut [u8]) -> Option<(usize, Addr)> { None }
    fn send(&mut self, p: &[u8], _: &Addr) { self.0 += p.len(); }
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 { self.0 ^= self.0 << 13; self.0 ^= self.0 >> 7; self.0 ^= self.0 << 17; self.0 }
    fn below(&mut self, n: usize) -> usize { (self.next() % n.max(1) as u64) as usize }
}

fn reader(p: &str) -> std::io::Result<Vec<u8>> {
    Ok(match p { "FAKE" => hello(Some("www.example.org")), "BL" => b"blocked.test\n".to_vec(), _ => vec![0xAB; 20] })
}

fn udp4(payload: &[u8]) -> Vec<u8> {
    let mut p = vec![0x45, 0, 0, 0, 0, 7, 0x40, 0, 64, 17, 0, 0, 10, 0, 0, 2, 162, 159, 197, 5, 0xC3, 0x50, 1, 0xBB, 0, 0, 0, 0];
    p.extend_from_slice(payload);
    let n = p.len() as u16;
    p[2..4].copy_from_slice(&n.to_be_bytes());
    p[24..26].copy_from_slice(&(n - 20).to_be_bytes());
    p
}

#[test]
fn random_and_mutated_packets_never_panic_the_engine() {
    let a: Vec<String> = ["--filter-tcp=443", "--hostlist=BL", "--dpi-desync=fake,multisplit", "--dpi-desync-split-pos=1,midsld,sniext+1", "--dpi-desync-split-seqovl=10", "--dpi-desync-split-seqovl-pattern=PAT",
        "--dpi-desync-fooling=ts", "--dpi-desync-fake-tls=FAKE", "--new", "--filter-tcp=80", "--filter-l7=http", "--dpi-desync=fake,multisplit", "--dpi-desync-split-pos=method+2", "--new",
        "--filter-udp=443", "--hostlist=BL", "--dpi-desync=fake", "--dpi-desync-fake-quic=PAT"].iter().map(|s| s.to_string()).collect();
    let mut plan = Plan::from_args(&a, &reader);
    if plan.is_err() { let mut b = vec!["--wf-raw=x".to_string()]; b.extend(a.clone()); plan = Plan::from_args(&b, &reader); }
    let plan = plan.unwrap();
    let mut e = Engine::new(plan.rules, 9).with_tcp(plan.tcp);
    let mut io = Sink::default();
    let long = hello_late_sni("www.blocked.test", 1800);
    let rec = hello_late_sni("late.blocked.test", 1500);
    let hs = rec[5..].to_vec();
    let mut corpus: Vec<Vec<u8>> = vec![
        mk4(1000, 1, &long[..1400]), mk4(2400, 1, &long[1400..]), mk4(1, 1, &hello(Some("www.blocked.test"))),
        mk4(5, 5, b"GET / HTTP/1.1\r\nHost: blocked.test\r\n\r\n"),
        udp4(&build_initial(&[9; 8], 0, &[(0, &hs[..1000])])), udp4(&build_initial(&[9; 8], 1, &[(1000, &hs[1000..])])),
    ];
    corpus.push(vec![0x60, 0, 0, 0, 0, 20, 6, 64, 0x20, 1, 0xdb, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x20, 1, 0xdb, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 1, 0xBB]);
    let mut r = Rng(0x9E3779B97F4A7C15);
    let mut now = 0u64;
    for i in 0..60_000u32 {
        let mut p = if r.below(10) == 0 { (0..r.below(1600)).map(|_| r.next() as u8).collect() } else { corpus[r.below(corpus.len())].clone() };
        for _ in 0..r.below(4) {
            match r.below(6) {
                0 if !p.is_empty() => { let k = r.below(p.len()); p[k] = r.next() as u8; }
                1 => { let k = r.below(p.len() + 1); p.truncate(k); }
                2 => p.extend((0..r.below(40)).map(|_| r.next() as u8)),
                3 if p.len() > 40 => { let k = r.below(40); p[k] = r.next() as u8; }
                4 if p.len() > 4 => { let k = 2 + r.below(2); p[k] = r.next() as u8; }
                _ => {}
            }
        }
        now += r.below(200) as u64;
        e.handle(&p, &Addr::default(), now, &mut io);
        if i % 1000 == 0 { e.flush_expired(now + 1000, &mut io); }
    }
    e.flush_all(&mut io);
    assert!(io.0 > 0);
}
