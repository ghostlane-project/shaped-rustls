//! The deframer buffer of a connection between records.
//!
//! A connection keeps the bytes it read from the socket in a deframer buffer
//! until they form whole records. A full record takes up to `MAX_WIRE_SIZE`
//! (18,437) bytes, which iOS rounds up to 32 KiB, and a phone holds hundreds of
//! idle connections. So once every buffered byte is processed the buffer is
//! released, and it grows again when the next record arrives.

#[macro_rules_attribute::apply(test_for_each_provider)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;
    use core::ops::DerefMut;
    use std::io::{self, Read, Write};

    use pki_types::pem::PemObject;
    use pki_types::{CertificateDer, PrivateKeyDer, ServerName};

    use crate::client::{ClientConfig, ClientConnection};
    use crate::conn::{ConnectionCommon, SideData};
    use crate::msgs::deframer::buffers::READ_SIZE;
    use crate::server::{ServerConfig, ServerConnection};
    use crate::sync::Arc;
    use crate::{RootCertStore, SupportedProtocolVersion, version};

    /// Plaintext bytes in the largest record a peer sends.
    const FULL_RECORD: usize = 16_384;

    #[test]
    fn idle_connection_holds_no_deframer_buffer() {
        for version in versions() {
            let (mut client, mut server) = handshake(version);
            assert_eq!(client.deframer_buffer.capacity(), 0, "{version:?}");
            assert_eq!(server.deframer_buffer.capacity(), 0, "{version:?}");

            // Application data both ways, records split across reads.
            let down = pattern(3 * FULL_RECORD + 100);
            server
                .writer()
                .write_all(&down)
                .unwrap();
            assert_eq!(
                deliver(&mut server, &mut client, &[5_000]),
                down,
                "{version:?}"
            );
            let up = pattern(FULL_RECORD + 7);
            client.writer().write_all(&up).unwrap();
            assert_eq!(
                deliver(&mut client, &mut server, &[3_000]),
                up,
                "{version:?}"
            );

            assert_eq!(client.deframer_buffer.capacity(), 0, "{version:?}");
            assert_eq!(server.deframer_buffer.capacity(), 0, "{version:?}");

            // A read that finds nothing, as tokio-rustls's pending read does,
            // is offered no more than the small buffer.
            let err = client
                .read_tls(&mut WouldBlock)
                .unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
            assert!(
                client.deframer_buffer.capacity() <= READ_SIZE,
                "{version:?}: {} bytes",
                client.deframer_buffer.capacity()
            );
        }
    }

    #[test]
    fn full_record_in_pieces_after_release() {
        for version in versions() {
            let (mut client, mut server) = handshake(version);

            for round in 0..3 {
                assert_eq!(client.deframer_buffer.capacity(), 0, "{version:?} {round}");

                let plaintext = pattern(FULL_RECORD);
                server
                    .writer()
                    .write_all(&plaintext)
                    .unwrap();
                let wire = send(&mut server);
                // One record of 16 KiB plus its overhead.
                assert!(wire.len() > FULL_RECORD + 5, "{version:?}: {}", wire.len());
                assert_eq!(
                    usize::from(u16::from_be_bytes([wire[3], wire[4]])) + 5,
                    wire.len()
                );

                // The header split, then pieces across the small first read.
                let pieces = [1, 4, 3, 4_093, 5_000, 1];
                let mut offset = 0;
                for piece in pieces {
                    let received = receive(&mut client, &wire[offset..offset + piece]);
                    assert!(received.is_empty(), "{version:?} {round}");
                    offset += piece;
                }
                assert!(client.deframer_buffer.capacity() >= wire.len());

                let received = receive(&mut client, &wire[offset..]);
                assert_eq!(received, plaintext, "{version:?} {round}");
            }
            assert_eq!(client.deframer_buffer.capacity(), 0, "{version:?}");
        }
    }

    fn versions() -> Vec<&'static SupportedProtocolVersion> {
        #[allow(unused_mut)]
        let mut versions = vec![&version::TLS13];
        #[cfg(feature = "tls12")]
        versions.push(&version::TLS12);
        versions
    }

    fn handshake(
        version: &'static SupportedProtocolVersion,
    ) -> (ClientConnection, ServerConnection) {
        let provider = Arc::new(super::provider::default_provider());
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(
                &include_bytes!("../../../test-ca/rsa-2048/ca.der")[..],
            ))
            .unwrap();
        let client_config = ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[version])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let server_config = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[version])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![
                    CertificateDer::from(&include_bytes!("../../../test-ca/rsa-2048/end.der")[..]),
                    CertificateDer::from(
                        &include_bytes!("../../../test-ca/rsa-2048/inter.der")[..],
                    ),
                ],
                PrivateKeyDer::from_pem_reader(
                    &mut include_bytes!("../../../test-ca/rsa-2048/end.key").as_slice(),
                )
                .unwrap(),
            )
            .unwrap();

        let mut client = ClientConnection::new(
            Arc::new(client_config),
            ServerName::try_from("localhost").unwrap(),
        )
        .unwrap();
        let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();
        while client.is_handshaking() || server.is_handshaking() {
            deliver(&mut client, &mut server, &[usize::MAX]);
            deliver(&mut server, &mut client, &[usize::MAX]);
        }
        // TLS 1.3 session tickets.
        deliver(&mut server, &mut client, &[usize::MAX]);
        (client, server)
    }

    /// Moves everything `from` has to send into `to` in `pieces` (the last
    /// one repeated), and returns the plaintext `to` received.
    fn deliver(
        from: &mut impl DerefMut<Target = ConnectionCommon<impl SideData>>,
        to: &mut impl DerefMut<Target = ConnectionCommon<impl SideData>>,
        pieces: &[usize],
    ) -> Vec<u8> {
        let wire = send(from);
        let mut received = Vec::new();
        let mut offset = 0;
        let mut pieces = pieces.iter().copied();
        let mut piece = 0;
        while offset < wire.len() {
            piece = pieces.next().unwrap_or(piece);
            let end = Ord::min(wire.len(), offset.saturating_add(piece));
            received.extend(receive(to, &wire[offset..end]));
            offset = end;
        }
        received
    }

    /// Everything `from` has to send.
    fn send(from: &mut impl DerefMut<Target = ConnectionCommon<impl SideData>>) -> Vec<u8> {
        let mut wire = Vec::new();
        while from.wants_write() {
            from.write_tls(&mut wire).unwrap();
        }
        wire
    }

    /// Reads `bytes` into `to` as a socket delivers them, processing after
    /// every read and reading out the plaintext, as tokio-rustls does.
    fn receive(
        to: &mut impl DerefMut<Target = ConnectionCommon<impl SideData>>,
        mut bytes: &[u8],
    ) -> Vec<u8> {
        let mut received = Vec::new();
        while !bytes.is_empty() {
            assert!(to.read_tls(&mut bytes).unwrap() > 0);
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
        received
    }

    fn pattern(len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| (i % 253) as u8)
            .collect()
    }

    /// A socket with nothing to read.
    struct WouldBlock;

    impl Read for WouldBlock {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::ErrorKind::WouldBlock.into())
        }
    }
}
