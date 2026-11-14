#[cfg(test)]
mod tests {
    use std::io;
    use std::sync::Arc;

    use rcgen::{CertifiedKey, generate_simple_self_signed};
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{
        CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime,
    };
    use rustls::{ClientConfig, DigitallySignedStruct, Error, ServerConfig};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    #[derive(Debug)]
    struct AcceptAnyServerCert;

    impl ServerCertVerifier for AcceptAnyServerCert {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            rustls::crypto::aws_lc_rs::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }

    fn endpoints() -> (TlsAcceptor, TlsConnector) {
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_chain = vec![CertificateDer::from(cert.der().to_vec())];
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));

        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .unwrap();

        let client_config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert))
            .with_no_client_auth();

        (
            TlsAcceptor::from(Arc::new(server_config)),
            TlsConnector::from(Arc::new(client_config)),
        )
    }

    fn pattern(len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| (i % 251) as u8)
            .collect()
    }

    #[tokio::test]
    async fn tokio_rustls_connector_uses_local_rustls_fork() -> io::Result<()> {
        let (acceptor, connector) = endpoints();
        let (client_io, server_io) = tokio::io::duplex(4096);

        let server = tokio::spawn(async move {
            let mut stream = acceptor
                .accept(server_io)
                .await
                .unwrap();
            let mut request = [0u8; 4];
            stream
                .read_exact(&mut request)
                .await
                .unwrap();
            assert_eq!(&request, b"ping");
            stream.write_all(b"pong").await.unwrap();
        });

        let mut client = connector
            .connect(ServerName::try_from("localhost").unwrap(), client_io)
            .await
            .unwrap();
        client.write_all(b"ping").await.unwrap();
        let mut response = [0u8; 4];
        client
            .read_exact(&mut response)
            .await
            .unwrap();
        assert_eq!(&response, b"pong");

        server.await.unwrap();
        Ok(())
    }

    /// Full-size records through a pipe narrower than one record: every
    /// record reaches rustls in many reads, and its deframer buffer empties
    /// and is released between records.
    #[tokio::test]
    async fn tokio_rustls_reads_full_records_split_across_reads() -> io::Result<()> {
        let (acceptor, connector) = endpoints();
        let (client_io, server_io) = tokio::io::duplex(1_000);
        let up = pattern(256 * 1024);
        let down = pattern(1024 * 1024);

        let server = tokio::spawn({
            let (up, down) = (up.clone(), down.clone());
            async move {
                let mut stream = acceptor
                    .accept(server_io)
                    .await
                    .unwrap();
                let mut received = vec![0u8; up.len()];
                stream
                    .read_exact(&mut received)
                    .await
                    .unwrap();
                assert!(received == up, "the server read other bytes than were sent");
                stream.write_all(&down).await.unwrap();
                stream.flush().await.unwrap();
            }
        });

        let mut client = connector
            .connect(ServerName::try_from("localhost").unwrap(), client_io)
            .await
            .unwrap();
        client.write_all(&up).await.unwrap();
        client.flush().await.unwrap();
        let mut received = vec![0u8; down.len()];
        client
            .read_exact(&mut received)
            .await
            .unwrap();
        assert!(
            received == down,
            "the client read other bytes than were sent"
        );

        server.await.unwrap();
        Ok(())
    }
}
