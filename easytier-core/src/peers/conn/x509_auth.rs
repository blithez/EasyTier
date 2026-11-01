//! Client admission credentials, independent of overlay network membership.
//! The certificate key signs the Noise transcript after message 2. The
//! transcript includes fresh ephemeral keys and authenticates this connection.
use std::sync::Arc;

use anyhow::{Context, ensure};
use rustls::{
    RootCertStore, SignatureScheme,
    pki_types::{CertificateDer, CertificateRevocationListDer, PrivateKeyDer, UnixTime, pem::PemObject},
    server::{WebPkiClientVerifier, danger::ClientCertVerifier},
    sign::CertifiedKey,
};

use crate::proto::{common::X509AuthConfig, peer_rpc::PeerConnNoiseMsg3Pb};

const CONTEXT: &[u8] = b"EasyTier X509 client admission v1\0";
pub(crate) const MAX_CHAIN_BYTES: usize = 48 * 1024;

fn signed_message(transcript: &[u8]) -> Vec<u8> {
    [CONTEXT, transcript].concat()
}

fn certificates(pem: &str) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let certs = CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()?;
    ensure!(!certs.is_empty(), "empty X.509 certificate chain");
    ensure!(certs.len() <= 8, "too many X.509 certificates");
    ensure!(certs.iter().map(|c| c.as_ref().len()).sum::<usize>() <= MAX_CHAIN_BYTES,
        "X.509 certificate chain is too large");
    Ok(certs)
}

fn identity(config: &X509AuthConfig) -> anyhow::Result<Option<CertifiedKey>> {
    match (&config.client_certificate_pem, &config.client_private_key_pem) {
        (None, None) => Ok(None),
        (Some(cert), Some(key)) => {
            let certs = certificates(cert)?;
            let key = PrivateKeyDer::from_pem_slice(key.as_bytes())
                .context("invalid X.509 client private key PEM")?;
            let provider = rustls::crypto::ring::default_provider();
            let identity = CertifiedKey::from_der(certs, key, &provider)
                .context("invalid X.509 identity or certificate/private key mismatch")?;
            identity.keys_match()?;
            Ok(Some(identity))
        }
        _ => anyhow::bail!("X.509 client certificate and private key must be configured together"),
    }
}

fn verifier(config: &X509AuthConfig) -> anyhow::Result<Arc<dyn ClientCertVerifier>> {
    let mut roots = RootCertStore::empty();
    for pem in &config.trusted_client_ca_pem {
        for cert in certificates(pem)? {
            roots.add(cert)?;
        }
    }
    ensure!(!roots.is_empty(), "X.509 client CA trust store is empty");
    let mut crls = Vec::new();
    for pem in &config.client_crl_pem {
        let parsed = CertificateRevocationListDer::pem_slice_iter(pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()?;
        ensure!(!parsed.is_empty(), "empty X.509 CRL PEM");
        crls.extend(parsed);
    }
    let builder = WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots), Arc::new(rustls::crypto::ring::default_provider()),
    );
    // Reject unknown revocation status and enforce CRL expiration.
    Ok(builder.with_crls(crls).enforce_revocation_expiration().build()?)
}

pub(crate) fn validate_config(config: &X509AuthConfig) -> anyhow::Result<()> {
    identity(config)?;
    if !config.trusted_client_ca_pem.is_empty() {
        verifier(config)?;
    } else {
        ensure!(config.client_crl_pem.is_empty(), "X.509 CRLs require trusted client CAs");
        ensure!(config.client_certificate_pem.is_some(), "empty X.509 authentication configuration");
    }
    Ok(())
}

pub(crate) fn sign(
    config: &X509AuthConfig,
    transcript: &[u8],
    msg: &mut PeerConnNoiseMsg3Pb,
) -> anyhow::Result<()> {
    let Some(identity) = identity(config)? else { return Ok(()); };
    let provider = rustls::crypto::ring::default_provider();
    let schemes = provider.signature_verification_algorithms.supported_schemes();
    let signer = identity.key.choose_scheme(&schemes)
        .context("unsupported X.509 client signing key")?;
    msg.client_signature_scheme = Some(u16::from(signer.scheme()) as u32);
    msg.client_certificate_signature = Some(signer.sign(&signed_message(transcript))?);
    msg.client_certificate_chain = identity.cert.iter().map(|c| c.as_ref().to_vec()).collect();
    Ok(())
}

pub(crate) fn verify(
    config: &X509AuthConfig,
    transcript: &[u8],
    msg: &PeerConnNoiseMsg3Pb,
) -> anyhow::Result<()> {
    verify_at(config, transcript, msg, UnixTime::now())
}

fn verify_at(
    config: &X509AuthConfig,
    transcript: &[u8],
    msg: &PeerConnNoiseMsg3Pb,
    now: UnixTime,
) -> anyhow::Result<()> {
    ensure!(!msg.client_certificate_chain.is_empty(), "X.509 client certificate required");
    ensure!(msg.client_certificate_chain.len() <= 8, "too many X.509 certificates");
    ensure!(msg.client_certificate_chain.iter().map(Vec::len).sum::<usize>() <= MAX_CHAIN_BYTES,
        "X.509 certificate chain is too large");
    let chain: Vec<_> = msg.client_certificate_chain.iter()
        .map(|c| CertificateDer::from(c.as_slice())).collect();
    verifier(config)?.verify_client_cert(&chain[0], &chain[1..], now)?;
    let scheme = msg.client_signature_scheme.context("X.509 client signature scheme required")?;
    let scheme = SignatureScheme::from(u16::try_from(scheme)?);
    let signature = msg.client_certificate_signature.as_deref()
        .context("X.509 client signature required")?;
    let provider = rustls::crypto::ring::default_provider();
    let algorithms = provider.signature_verification_algorithms.mapping.iter()
        .find(|(s, _)| *s == scheme).context("unsupported X.509 client signature scheme")?.1;
    let cert = webpki::EndEntityCert::try_from(&chain[0])?;
    let message = signed_message(transcript);
    ensure!(algorithms.iter().any(|algorithm|
        cert.verify_signature(*algorithm, &message, signature).is_ok()),
        "invalid X.509 client handshake signature");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    const CA: &str = include_str!("../../../tests/data/x509/ca.pem");
    const CERT: &str = include_str!("../../../tests/data/x509/client.pem");
    const KEY: &str = include_str!("../../../tests/data/x509/client.key.pem");
    const OTHER_CA: &str = include_str!("../../../tests/data/x509/other-ca.pem");
    const CRL: &str = include_str!("../../../tests/data/x509/revoked.crl.pem");

    fn config() -> X509AuthConfig {
        X509AuthConfig {
            trusted_client_ca_pem: vec![CA.to_owned()],
            client_certificate_pem: Some(CERT.to_owned()),
            client_private_key_pem: Some(KEY.to_owned()),
            ..Default::default()
        }
    }

    fn proof(config: &X509AuthConfig) -> PeerConnNoiseMsg3Pb {
        let mut proof = PeerConnNoiseMsg3Pb::default();
        sign(config, b"connection transcript", &mut proof).unwrap();
        proof
    }

    fn at(seconds: u64) -> UnixTime {
        UnixTime::since_unix_epoch(std::time::Duration::from_secs(seconds))
    }

    #[test]
    fn configuration_round_trips_and_redacts_private_keys() {
        use crate::config::toml::{ConfigLoader, TomlConfig};
        use crate::proto::common::SecureModeConfig;

        let config = config();
        let debug = format!("{config:?}");
        assert!(!debug.contains(KEY));
        assert!(debug.contains("<redacted>"));
        assert!(crate::config::normalize_secure_mode_config(SecureModeConfig {
            enabled: false,
            x509: Some(config.clone()),
            ..Default::default()
        }).is_err());
        let text = format!(
            "[secure_mode]\nenabled = true\n\n[secure_mode.x509]\ntrusted_client_ca_pem = ['''{CA}''']\nclient_certificate_pem = '''{CERT}'''\nclient_private_key_pem = '''{KEY}'''\n"
        );
        let loaded = TomlConfig::new_from_str(&text).unwrap();
        assert_eq!(loaded.get_secure_mode().unwrap().x509, Some(config.clone()));
        #[cfg(feature = "config-write")]
        {
            let redacted = loaded.dump_redacted();
            assert!(!redacted.contains(KEY.lines().nth(1).unwrap()));
            assert!(redacted.contains("<redacted>"));
            let round_trip = TomlConfig::new_from_str(&loaded.dump()).unwrap();
            assert_eq!(round_trip.get_secure_mode().unwrap().x509, Some(config));
        }
    }

    #[test]
    fn validates_chain_and_proof_of_possession() {
        let config = config();
        validate_config(&config).unwrap();
        verify_at(&config, b"connection transcript", &proof(&config), at(1_800_000_000)).unwrap();
    }

    #[test]
    fn rejects_replay_missing_certificate_and_tampered_signature() {
        let config = config();
        let mut proof = proof(&config);
        let now = at(1_800_000_000);
        assert!(verify_at(&config, b"another connection", &proof, now).is_err());
        proof.client_certificate_signature.as_mut().unwrap()[0] ^= 1;
        assert!(verify_at(&config, b"connection transcript", &proof, now).is_err());
        assert!(verify_at(&config, b"connection transcript", &PeerConnNoiseMsg3Pb::default(), now).is_err());
    }

    #[test]
    fn rejects_untrusted_expired_not_yet_valid_and_revoked_certificates() {
        let mut config = config();
        let proof = proof(&config);
        assert!(verify_at(&config, b"connection transcript", &proof, at(1)).is_err());
        assert!(verify_at(&config, b"connection transcript", &proof, at(2_200_000_000)).is_err());
        config.trusted_client_ca_pem = vec![OTHER_CA.to_owned()];
        assert!(verify_at(&config, b"connection transcript", &proof, at(1_800_000_000)).is_err());
        config.trusted_client_ca_pem = vec![CA.to_owned()];
        config.client_crl_pem = vec![CRL.to_owned()];
        assert!(verify_at(&config, b"connection transcript", &proof, at(1_800_000_000)).is_err());
    }

    #[test]
    fn rejects_server_only_usage_and_mismatched_private_key() {
        let mut config = config();
        config.client_certificate_pem = Some(include_str!("../../../tests/data/x509/server-only.pem").to_owned());
        assert!(validate_config(&config).is_err());
        config.client_private_key_pem = Some(include_str!("../../../tests/data/x509/server-only.key.pem").to_owned());
        let proof = proof(&config);
        assert!(verify_at(&config, b"connection transcript", &proof, at(1_800_000_000)).is_err());
    }

    #[test]
    fn rejects_partial_empty_and_malformed_configuration() {
        let mut config = config();
        config.client_private_key_pem = None;
        assert!(validate_config(&config).is_err());
        assert!(validate_config(&X509AuthConfig::default()).is_err());
        config.client_certificate_pem = None;
        config.trusted_client_ca_pem = vec!["not a PEM certificate".to_owned()];
        assert!(validate_config(&config).is_err());
    }
}
