#![cfg(any(feature = "ring", feature = "aws_lc_rs"))]
#![allow(clippy::disallowed_types)]

//! The heap an idle connection keeps, measured with a counting allocator.
//!
//! A phone's packet tunnel holds hundreds of idle TLS connections inside a
//! 50 MB budget, so a connection that has read everything it was sent must
//! not keep its deframer buffer (18,437 bytes, 32 KiB on iOS).
//!
//! The counts are per thread, so other tests running at the same time do not
//! disturb them.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::io::{self, Read, Write};
use std::ops::DerefMut;
use std::sync::Arc;

use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{
    ClientConfig, ClientConnection, ConnectionCommon, RootCertStore, ServerConfig,
    ServerConnection, SideData, SupportedProtocolVersion,
};

#[test]
fn idle_connection_keeps_no_record_buffer() {
    for (name, provider, ceiling) in providers() {
        for version in versions() {
            let provider = Arc::new(provider.clone());
            let (held, certificates) = held_by_idle_client(&provider, version);
            println!(
                "idle client ({name}, {version:?}) holds {held} B, \
                 of which {certificates} B the server's certificates"
            );
            assert!(
                held - certificates <= ceiling,
                "idle client ({name}, {version:?}) holds {held} B, {certificates} B of them \
                 certificates: over {ceiling} B without them"
            );
        }
    }
}

/// The bytes freed by dropping a client that finished its handshake, sent
/// and received application data and read all of it; and the bytes of the
/// server's certificates among them, which a client keeps by design
/// (`peer_certificates()`).
fn held_by_idle_client(
    provider: &Arc<CryptoProvider>,
    version: &'static SupportedProtocolVersion,
) -> (isize, isize) {
    // The configs outlive the connection, as an app's do.
    let (client_config, server_config) = configs(provider, version);
    let mut client = ClientConnection::new(
        client_config.clone(),
        ServerName::try_from("localhost").unwrap(),
    )
    .unwrap();
    let mut server = ServerConnection::new(server_config.clone()).unwrap();
    while client.is_handshaking() || server.is_handshaking() {
        deliver(&mut client, &mut server, usize::MAX);
        deliver(&mut server, &mut client, usize::MAX);
    }
    deliver(&mut server, &mut client, usize::MAX);

    let down = vec![0x5a; 64 * 1024];
    server
        .writer()
        .write_all(&down)
        .unwrap();
    assert_eq!(deliver(&mut server, &mut client, 1_500), down);
    let up = vec![0xa5; 20 * 1024];
    client.writer().write_all(&up).unwrap();
    assert_eq!(deliver(&mut client, &mut server, 1_500), up);

    let certificates = client
        .peer_certificates()
        .unwrap()
        .iter()
        .map(|certificate| certificate.len())
        .sum::<usize>() as isize;
    let before = live();
    drop(client);
    (before - live(), certificates)
}

/// Each provider, with what a client that read everything may keep besides
/// the server's certificates: its keys, state and empty queues, not a record
/// buffer (18,437 B) nor the 4 KiB one a read is offered. ring's keys take
/// about 1 KB more than aws-lc-rs's.
fn providers() -> Vec<(&'static str, CryptoProvider, isize)> {
    vec![
        #[cfg(feature = "aws_lc_rs")]
        (
            "aws-lc-rs",
            rustls::crypto::aws_lc_rs::default_provider(),
            2_048,
        ),
        #[cfg(feature = "ring")]
        ("ring", rustls::crypto::ring::default_provider(), 3_072),
    ]
}

fn versions() -> Vec<&'static SupportedProtocolVersion> {
    vec![
        &rustls::version::TLS13,
        #[cfg(feature = "tls12")]
        &rustls::version::TLS12,
    ]
}

fn configs(
    provider: &Arc<CryptoProvider>,
    version: &'static SupportedProtocolVersion,
) -> (Arc<ClientConfig>, Arc<ServerConfig>) {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(
            &include_bytes!("../../test-ca/rsa-2048/ca.der")[..],
        ))
        .unwrap();
    let client = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[version])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[version])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![
                CertificateDer::from(&include_bytes!("../../test-ca/rsa-2048/end.der")[..]),
                CertificateDer::from(&include_bytes!("../../test-ca/rsa-2048/inter.der")[..]),
            ],
            PrivateKeyDer::from_pem_reader(
                &mut include_bytes!("../../test-ca/rsa-2048/end.key").as_slice(),
            )
            .unwrap(),
        )
        .unwrap();
    (Arc::new(client), Arc::new(server))
}

/// Moves everything `from` has to send into `to`, `piece` bytes per read,
/// processing after every read and reading out the plaintext as
/// tokio-rustls does. Returns that plaintext.
fn deliver(
    from: &mut impl DerefMut<Target = ConnectionCommon<impl SideData>>,
    to: &mut impl DerefMut<Target = ConnectionCommon<impl SideData>>,
    piece: usize,
) -> Vec<u8> {
    let mut wire = Vec::new();
    while from.wants_write() {
        from.write_tls(&mut wire).unwrap();
    }
    let mut received = Vec::new();
    for mut bytes in wire.chunks(piece) {
        while !bytes.is_empty() {
            to.read_tls(&mut bytes).unwrap();
            to.process_new_packets().unwrap();
            let mut chunk = [0u8; 4096];
            loop {
                match to.reader().read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => received.extend_from_slice(&chunk[..n]),
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
                    Err(err) => panic!("{err}"),
                }
            }
        }
    }
    received
}

thread_local! {
    static LIVE: Cell<isize> = const { Cell::new(0) };
}

/// Bytes this thread has allocated and not freed.
fn live() -> isize {
    LIVE.with(Cell::get)
}

fn count(bytes: isize) {
    let _ = LIVE.try_with(|live| live.set(live.get() + bytes));
}

struct Counting;

#[global_allocator]
static ALLOCATOR: Counting = Counting;

#[allow(unsafe_code)]
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            count(layout.size() as isize);
        }
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if !ptr.is_null() {
            count(layout.size() as isize);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        count(-(layout.size() as isize));
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new = unsafe { System.realloc(ptr, layout, new_size) };
        if !new.is_null() {
            count(new_size as isize - layout.size() as isize);
        }
        new
    }
}
