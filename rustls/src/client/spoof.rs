use core::cell::LazyCell;
use core::ops::Deref;
use std::vec;
use std::vec::Vec;

use pki_types::ServerName;

use crate::client::EchGreaseConfig;
use crate::crypto::aws_lc_rs::hpke;
use crate::crypto::hpke::HpkePublicKey;
use crate::msgs::base::{Payload, PayloadU16};
use crate::msgs::enums::{Compression, ECPointFormat, ExtensionType, PSKKeyExchangeMode};
use crate::msgs::handshake::{
    CertificateStatusRequest, ClientExtension, ClientHelloPayload, ClientSessionTicket,
    ConvertProtocolNameList, KeyShareEntry, OcspCertificateStatusRequest, Random, SessionId,
    UnknownExtension,
};
use crate::{
    CertificateCompressionAlgorithm, CipherSuite, NamedGroup, ProtocolVersion, SignatureScheme,
};

use super::ClientConfig;

enum GreaseOrCipher {
    Grease,
    Cipher(CipherSuite),
}

const CHROME_CIPHERS: &[GreaseOrCipher] = &[
    GreaseOrCipher::Grease,
    GreaseOrCipher::Cipher(CipherSuite::TLS13_AES_128_GCM_SHA256),
    GreaseOrCipher::Cipher(CipherSuite::TLS13_AES_256_GCM_SHA384),
    GreaseOrCipher::Cipher(CipherSuite::TLS13_CHACHA20_POLY1305_SHA256),
    GreaseOrCipher::Cipher(CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
    GreaseOrCipher::Cipher(CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256),
    GreaseOrCipher::Cipher(CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384),
    GreaseOrCipher::Cipher(CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384),
    GreaseOrCipher::Cipher(CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256),
    GreaseOrCipher::Cipher(CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256),
    GreaseOrCipher::Cipher(CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA),
    GreaseOrCipher::Cipher(CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA),
    GreaseOrCipher::Cipher(CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256),
    GreaseOrCipher::Cipher(CipherSuite::TLS_RSA_WITH_AES_256_GCM_SHA384),
    GreaseOrCipher::Cipher(CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA),
    GreaseOrCipher::Cipher(CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA),
];

#[derive(Debug, Clone)]
enum GreaseOrProtocolVersion {
    Grease,
    ProtocolVersion(ProtocolVersion),
}

#[derive(Debug, Clone)]
enum GreaseOrNamedGroup {
    Grease(u16),
    NamedGroup(NamedGroup),
}

#[derive(Debug, Clone)]
enum GreaseOrCurve {
    Grease,
    NamedCurve(NamedGroup),
}

#[derive(Debug, Clone)]
enum SpoofExtension {
    Grease(u16, &'static [u8]),
    ServerName,
    RenegotiationInfo,
    SupportedGroups(&'static [GreaseOrNamedGroup]),
    SupportedVersions(&'static [GreaseOrProtocolVersion]),
    SignedCertificateTimestamp,
    KeyShare(&'static [GreaseOrCurve]),
    ApplicationSettings,
    ApplicationLayerProtocolNegotiation(&'static [&'static [u8]]),
    EncryptedClientHelloGrease(EchGreaseConfig),
}

enum ExtendedExtension {
    SpoofExtension(SpoofExtension),
    Extension(ClientExtension),
}

const CHROME_131_EXTENSIONS: LazyCell<Vec<ExtendedExtension>> = LazyCell::new(|| {
    vec![
        ExtendedExtension::SpoofExtension(SpoofExtension::Grease(2570, &[])),
        ExtendedExtension::SpoofExtension(SpoofExtension::ApplicationSettings),
        ExtendedExtension::Extension(ClientExtension::PresharedKeyModes(vec![
            PSKKeyExchangeMode::PSK_DHE_KE,
        ])),
        ExtendedExtension::SpoofExtension(SpoofExtension::ApplicationLayerProtocolNegotiation(&[
            b"h2",
            b"http/1.1",
        ])),
        ExtendedExtension::SpoofExtension(SpoofExtension::SupportedGroups(
            &CHROME_131_SUPPORTED_GROUPS,
        )),
        ExtendedExtension::SpoofExtension(SpoofExtension::KeyShare(&CHROME_131_KEY_SHARE)),
        ExtendedExtension::SpoofExtension(SpoofExtension::SupportedVersions(
            &CHROME_131_SUPPORTED_VERSIONS,
        )),
        ExtendedExtension::SpoofExtension(SpoofExtension::RenegotiationInfo),
        ExtendedExtension::Extension(ClientExtension::SessionTicket(ClientSessionTicket::Offer(
            Payload::Borrowed(&[]),
        ))),
        ExtendedExtension::SpoofExtension(SpoofExtension::SignedCertificateTimestamp),
        ExtendedExtension::SpoofExtension(SpoofExtension::ServerName),
        ExtendedExtension::Extension(ClientExtension::CertificateStatusRequest(
            CertificateStatusRequest::Ocsp(OcspCertificateStatusRequest {
                responder_ids: vec![],
                extensions: PayloadU16(vec![]),
            }),
        )),
        ExtendedExtension::Extension(ClientExtension::ExtendedMasterSecretRequest),
        ExtendedExtension::Extension(ClientExtension::SignatureAlgorithms(
            CHROME_131_SIGNATURE_ALGORITHMS.to_vec(),
        )),
        ExtendedExtension::SpoofExtension(SpoofExtension::EncryptedClientHelloGrease(
            EchGreaseConfig::new(
                hpke::DH_KEM_X25519_HKDF_SHA256_AES_128,
                HpkePublicKey(
                    [
                        0x67, 0x35, 0xCA, 0x50, 0x21, 0xFC, 0x4F, 0xE6, 0x29, 0x3B, 0x31, 0x2C,
                        0xB5, 0xE0, 0x97, 0xD8, 0xD0, 0x58, 0x97, 0xCF, 0x5C, 0x15, 0x12, 0x79,
                        0x4B, 0xEF, 0x1D, 0x98, 0x52, 0x74, 0xDC, 0x5E,
                    ]
                    .to_vec(),
                ),
            ),
        )),
        ExtendedExtension::Extension(ClientExtension::CertificateCompressionAlgorithms(vec![
            CertificateCompressionAlgorithm::Brotli,
        ])),
        ExtendedExtension::Extension(ClientExtension::EcPointFormats(vec![
            ECPointFormat::Uncompressed,
        ])),
        ExtendedExtension::SpoofExtension(SpoofExtension::Grease(56026, &[0])),
    ]
});

const CHROME_131_SIGNATURE_ALGORITHMS: &[SignatureScheme] = &[
    SignatureScheme::ECDSA_NISTP256_SHA256,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PKCS1_SHA256,
    SignatureScheme::ECDSA_NISTP384_SHA384,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PKCS1_SHA512,
];

const CHROME_131_SUPPORTED_VERSIONS: &[GreaseOrProtocolVersion] = &[
    GreaseOrProtocolVersion::Grease,
    GreaseOrProtocolVersion::ProtocolVersion(ProtocolVersion::TLSv1_3),
    GreaseOrProtocolVersion::ProtocolVersion(ProtocolVersion::TLSv1_2),
];

const CHROME_131_KEY_SHARE: &[GreaseOrCurve] = &[
    GreaseOrCurve::Grease,
    // GreaseOrCurve::Custom(0x11ec), // ! Post-quantum - 0x11ec - ML-KEM !
    GreaseOrCurve::NamedCurve(NamedGroup::X25519),
];

const CHROME_131_SUPPORTED_GROUPS: &[GreaseOrNamedGroup] = &[
    GreaseOrNamedGroup::Grease(35466),
    // GreaseOrNamedGroup::Custom(0x11ec), // ! Post-quantum - 0x11ec - ML-KEM !
    GreaseOrNamedGroup::NamedGroup(NamedGroup::X25519),
    GreaseOrNamedGroup::NamedGroup(NamedGroup::secp256r1),
    GreaseOrNamedGroup::NamedGroup(NamedGroup::secp384r1),
];

/// The spoof configuration of the ClientConfig
#[derive(Clone, Debug)]
pub struct Spoof(Fingerprint);

impl Spoof {
    pub(crate) fn new(fingerprint: Fingerprint) -> Self {
        Spoof(fingerprint)
    }

    pub(crate) fn spoof_ciphers(&self, ciphers: &mut Vec<CipherSuite>) {
        let fingerprint_ciphers = self.0.get_ciphers();
        *ciphers = fingerprint_ciphers
            .iter()
            .map(|v| match v {
                GreaseOrCipher::Grease => CipherSuite::Unknown(51914),
                GreaseOrCipher::Cipher(cipher) => cipher.clone(),
            })
            .collect();
    }

    pub(crate) fn spoof_extensions(
        &self,
        config: &ClientConfig,
        server_name: ServerName<'static>,
        random: Random,
        session_id: SessionId,
        ciphers: Vec<CipherSuite>,
        old_extensions: Vec<ClientExtension>,
    ) -> (ClientHelloPayload, Option<ClientExtension>) {
        let mut extensions = Vec::new();
        let mut ech_grease_config = None;

        let fingerprint_extensions = self.0.get_extensions();
        for ext in fingerprint_extensions.deref() {
            match ext {
                ExtendedExtension::SpoofExtension(ext) => match ext {
                    SpoofExtension::Grease(grease, val) => {
                        extensions.push(ClientExtension::Unknown(UnknownExtension {
                            typ: ExtensionType::Unknown(grease.clone()),
                            payload: Payload::Borrowed(val),
                        }));
                    }
                    SpoofExtension::ServerName => {
                        if let ServerName::DnsName(dns_name) = &server_name {
                            extensions.push(ClientExtension::make_sni(dns_name));
                        }
                    }
                    SpoofExtension::RenegotiationInfo => {
                        extensions.push(ClientExtension::Unknown(UnknownExtension {
                            typ: ExtensionType::RenegotiationInfo,
                            payload: Payload::Borrowed(&[0]),
                        }));
                    }
                    SpoofExtension::SupportedGroups(val) => {
                        let curves = val
                            .iter()
                            .map(|v| match v {
                                GreaseOrNamedGroup::Grease(val) => NamedGroup::Unknown(*val),
                                GreaseOrNamedGroup::NamedGroup(val) => val.clone(),
                            })
                            .collect();

                        extensions.push(ClientExtension::NamedGroups(curves));
                    }
                    SpoofExtension::SupportedVersions(val) => {
                        let versions = val
                            .iter()
                            .map(|v| match v {
                                GreaseOrProtocolVersion::Grease => ProtocolVersion::Unknown(14906),
                                GreaseOrProtocolVersion::ProtocolVersion(val) => val.clone(),
                            })
                            .collect();

                        extensions.push(ClientExtension::SupportedVersions(versions));
                    }
                    SpoofExtension::SignedCertificateTimestamp => {
                        extensions.push(ClientExtension::Unknown(UnknownExtension {
                            typ: ExtensionType::SCT,
                            payload: Payload::Borrowed(&[]),
                        }));
                    }
                    SpoofExtension::KeyShare(val) => {
                        let mut key_shares = old_extensions
                            .iter()
                            .find_map(|ext| {
                                if let ClientExtension::KeyShare(val) = ext {
                                    Some(val.clone())
                                } else {
                                    None
                                }
                            })
                            .expect("should have key share extension");

                        val.iter().for_each(|key| match *key {
                            GreaseOrCurve::Grease => {
                                key_shares
                                    .insert(0, KeyShareEntry::new(NamedGroup::Unknown(39578), [0]));
                            }
                            GreaseOrCurve::NamedCurve(curve) => {
                                if !key_shares
                                    .iter()
                                    .any(|key| key.group() == curve)
                                {
                                    panic!("key shares does not contain named curve");
                                }
                            }
                        });

                        extensions.push(ClientExtension::KeyShare(key_shares));
                    }
                    SpoofExtension::ApplicationSettings => {
                        extensions.push(ClientExtension::Unknown(UnknownExtension {
                            typ: 17513.into(),
                            payload: Payload::Borrowed(&[0, 3, 2, b'h', b'2']),
                        }));
                    }
                    SpoofExtension::ApplicationLayerProtocolNegotiation(val) => {
                        let protocols = Vec::from_slices(val);

                        extensions.push(ClientExtension::Protocols(protocols));
                    }
                    SpoofExtension::EncryptedClientHelloGrease(val) => {
                        ech_grease_config = Some(val.clone());
                    }
                },
                ExtendedExtension::Extension(ext) => extensions.push(ext.clone()),
            }
        }

        let mut hello_payload = ClientHelloPayload {
            client_version: ProtocolVersion::TLSv1_2,
            random,
            session_id,
            cipher_suites: ciphers,
            compression_methods: vec![Compression::Null],
            extensions,
        };
        let mut already_has_ech = None;

        if let Some(ech_grease_config) = ech_grease_config {
            let ext = ech_grease_config
                .grease_ext(
                    config.provider.secure_random,
                    server_name.clone(),
                    &hello_payload,
                )
                .unwrap();

            already_has_ech = Some(ext.clone());
            hello_payload
                .extensions
                .insert(hello_payload.extensions.len() - 1, ext);
        }

        (hello_payload, already_has_ech)
    }
}

/// The specific fingeprint beeing mimicked.
#[derive(Clone, Debug)]
pub enum Fingerprint {
    /// Chrome v131
    Chrome131,
}

impl Fingerprint {
    fn get_ciphers(&self) -> &[GreaseOrCipher] {
        match self {
            Fingerprint::Chrome131 => CHROME_CIPHERS,
        }
    }

    fn get_extensions(&self) -> LazyCell<Vec<ExtendedExtension>> {
        match self {
            Fingerprint::Chrome131 => CHROME_131_EXTENSIONS,
        }
    }
}
