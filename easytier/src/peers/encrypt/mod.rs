use crate::{
    common::{config::EncryptionAlgorithm, log},
    tunnel::{packet_def::ZCPacket, padding},
};
use std::sync::Arc;

#[cfg(feature = "wireguard")]
pub mod ring;

#[cfg(feature = "aes-gcm")]
pub mod aes_gcm;

#[cfg(feature = "openssl-crypto")]
pub mod openssl;

pub mod xor;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("packet is too short. len: {0}")]
    PacketTooShort(usize),
    #[error("decryption failed")]
    DecryptionFailed,
    #[error("encryption failed")]
    EncryptionFailed,
    #[error("invalid tag. tag: {0:?}")]
    InvalidTag(Vec<u8>),
}

pub trait Encryptor: Send + Sync + 'static {
    fn decrypt(&self, zc_packet: &mut ZCPacket) -> Result<(), Error>;
    fn encrypt(&self, zc_packet: &mut ZCPacket) -> Result<(), Error>;
    fn encrypt_with_nonce(
        &self,
        zc_packet: &mut ZCPacket,
        _nonce: Option<&[u8]>,
    ) -> Result<(), Error> {
        self.encrypt(zc_packet)
    }
}

pub struct NullCipher;

impl Encryptor for NullCipher {
    fn decrypt(&self, zc_packet: &mut ZCPacket) -> Result<(), Error> {
        let pm_header = zc_packet.peer_manager_header().unwrap();
        if pm_header.is_encrypted() {
            Err(Error::DecryptionFailed)
        } else {
            Ok(())
        }
    }

    fn encrypt(&self, _zc_packet: &mut ZCPacket) -> Result<(), Error> {
        Ok(())
    }
}

pub struct PaddedEncryptor {
    inner: Arc<dyn Encryptor>,
    padding_max: u32,
}

impl Encryptor for PaddedEncryptor {
    fn encrypt(&self, zc_packet: &mut ZCPacket) -> Result<(), Error> {
        padding::add_padding(zc_packet, self.padding_max);
        self.inner.encrypt(zc_packet)
    }

    fn decrypt(&self, zc_packet: &mut ZCPacket) -> Result<(), Error> {
        let was_encrypted = zc_packet
            .peer_manager_header()
            .map_or(false, |h| h.is_encrypted());
        self.inner.decrypt(zc_packet)?;
        if was_encrypted {
            padding::remove_padding(zc_packet)?;
        }
        Ok(())
    }

    fn encrypt_with_nonce(
        &self,
        zc_packet: &mut ZCPacket,
        nonce: Option<&[u8]>,
    ) -> Result<(), Error> {
        padding::add_padding(zc_packet, self.padding_max);
        self.inner.encrypt_with_nonce(zc_packet, nonce)
    }
}

/// Create an encryptor based on the algorithm name, with padding support.
pub fn create_encryptor(
    algorithm: &str,
    key_128: [u8; 16],
    #[allow(unused_variables)] key_256: [u8; 32],
    padding_max: u32,
) -> Arc<dyn Encryptor> {
    let algorithm = match EncryptionAlgorithm::try_from(algorithm) {
        Ok(algorithm) => algorithm,
        Err(_) => {
            let default = EncryptionAlgorithm::default();
            log::warn!(
                "Unknown encryption algorithm: {}, falling back to default {}",
                algorithm,
                default
            );
            default
        }
    };

    let inner: Arc<dyn Encryptor> = match algorithm {
        EncryptionAlgorithm::Xor => Arc::new(xor::XorCipher::new(&key_128)),

        #[cfg(any(feature = "aes-gcm", feature = "wireguard", feature = "openssl-crypto"))]
        EncryptionAlgorithm::AesGcm => {
            cfg_select! {
                feature = "openssl-crypto" => Arc::new(openssl::OpenSslCipher::new_aes128_gcm(key_128)),
                feature = "wireguard" => Arc::new(ring::RingCipher::new_aes128_gcm(key_128)),
                feature = "aes-gcm" => Arc::new(aes_gcm::AesGcmCipher::new_128(key_128)),
            }
        }

        #[cfg(any(feature = "aes-gcm", feature = "wireguard", feature = "openssl-crypto"))]
        EncryptionAlgorithm::Aes256Gcm => {
            cfg_select! {
                feature = "openssl-crypto" => Arc::new(openssl::OpenSslCipher::new_aes256_gcm(key_256)),
                feature = "wireguard" => Arc::new(ring::RingCipher::new_aes256_gcm(key_256)),
                feature = "aes-gcm" => Arc::new(aes_gcm::AesGcmCipher::new_256(key_256)),
            }
        }

        #[cfg(any(feature = "wireguard", feature = "openssl-crypto"))]
        EncryptionAlgorithm::ChaCha20 => {
            cfg_select! {
                feature = "openssl-crypto" => Arc::new(openssl::OpenSslCipher::new_chacha20(key_256)),
                feature = "wireguard" => Arc::new(ring::RingCipher::new_chacha20(key_256)),
            }
        }
    };

    if padding_max > 0 {
        Arc::new(PaddedEncryptor { inner, padding_max })
    } else {
        inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tunnel::packet_def::PacketType;

    #[test]
    fn padded_encryptor_roundtrip() {
        let encryptor = create_encryptor("aes-gcm", [1u8; 16], [1u8; 32], 128);
        let text = b"hello padded world";
        let mut pkt = ZCPacket::new_with_payload(text);
        pkt.fill_peer_manager_hdr(10, 20, PacketType::Data as u8);

        encryptor.encrypt(&mut pkt).unwrap();
        assert_ne!(pkt.payload(), text);
        assert!(pkt.peer_manager_header().unwrap().is_encrypted());

        encryptor.decrypt(&mut pkt).unwrap();
        assert_eq!(pkt.payload(), text);
        assert!(!pkt.peer_manager_header().unwrap().is_encrypted());
    }

    #[test]
    fn padded_encryptor_ciphertext_varies_due_to_padding() {
        let encryptor = create_encryptor("aes-gcm", [3u8; 16], [3u8; 32], 128);
        let text = b"same payload";

        let mut sizes = std::collections::HashSet::new();
        for _ in 0..50 {
            let mut pkt = ZCPacket::new_with_payload(text);
            pkt.fill_peer_manager_hdr(10, 20, PacketType::Data as u8);
            encryptor.encrypt(&mut pkt).unwrap();
            sizes.insert(pkt.payload().len());
        }
        // With padding_max=128, different encryptions should produce different sizes
        assert!(sizes.len() > 1, "ciphertext sizes should vary: {:?}", sizes);
    }

    #[test]
    fn padded_encryptor_zero_padding_passthrough() {
        let encryptor = create_encryptor("aes-gcm", [4u8; 16], [4u8; 32], 0);
        let text = b"no padding here";

        let mut pkt = ZCPacket::new_with_payload(text);
        pkt.fill_peer_manager_hdr(10, 20, PacketType::Data as u8);

        encryptor.encrypt(&mut pkt).unwrap();
        encryptor.decrypt(&mut pkt).unwrap();
        assert_eq!(pkt.payload(), text);
    }

    #[test]
    fn padded_encryptor_cross_instance_decrypt() {
        // Simulate two peers with the same key and padding_max
        let enc_a = create_encryptor("aes-gcm", [7u8; 16], [7u8; 32], 128);
        let enc_b = create_encryptor("aes-gcm", [7u8; 16], [7u8; 32], 128);

        let text = b"cross instance data";
        let nonce = [11u8; 12];

        let mut pkt = ZCPacket::new_with_payload(text);
        pkt.fill_peer_manager_hdr(10, 20, PacketType::Data as u8);

        // A encrypts with fixed nonce, B decrypts
        enc_a.encrypt_with_nonce(&mut pkt, Some(&nonce)).unwrap();
        enc_b.decrypt(&mut pkt).unwrap();
        assert_eq!(pkt.payload(), text);
    }

    #[test]
    fn padded_encryptor_mismatched_padding_max_fails() {
        // Peer A uses padding_max=128, Peer B uses padding_max=0 (no PaddedEncryptor)
        // B cannot decode A's padding after decrypt
        let enc_a = create_encryptor("aes-gcm", [8u8; 16], [8u8; 32], 128);
        let enc_b_raw = create_encryptor("aes-gcm", [8u8; 16], [8u8; 32], 0);

        let text = b"will B decode this?";
        let nonce = [12u8; 12];

        let mut pkt = ZCPacket::new_with_payload(text);
        pkt.fill_peer_manager_hdr(10, 20, PacketType::Data as u8);

        enc_a.encrypt_with_nonce(&mut pkt, Some(&nonce)).unwrap();
        // B decrypts successfully (AEAD is fine) but doesn't remove padding
        enc_b_raw.decrypt(&mut pkt).unwrap();
        // Payload now contains: [original_text][random_padding][len_suffix]
        // so it won't match original text
        assert_ne!(pkt.payload(), text);
    }
}
