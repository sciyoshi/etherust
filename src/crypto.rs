extern crate rand;
extern crate byteorder;
extern crate secp256k1;
extern crate crypto as rustcrypto;

use rand::{thread_rng, Rng};
use byteorder::{BigEndian, ByteOrder};
use rustcrypto::{aes, hmac};
use rustcrypto::symmetriccipher::SynchronousStreamCipher;
use rustcrypto::digest::Digest;
use rustcrypto::mac::Mac;
use rustcrypto::sha2;
//use rustcrypto::sha3::Sha3;

pub trait KeyDerivation {
	fn concat_kdf(&mut self, z: &[u8], s1: &[u8], len: usize) -> Vec<u8>;
}

impl<D> KeyDerivation for D where D: Digest {
	fn concat_kdf(&mut self, z: &[u8], s1: &[u8], len: usize) -> Vec<u8> {
		let mut counter = [0u8; 4];
		let mut hash = vec![0u8; self.output_bytes()];
		let mut result = vec![];

		for count in 0..((len + self.output_bytes() - 1) / self.output_bytes()) {
			BigEndian::write_u32(&mut counter, count as u32 + 1);

			self.reset();
			self.input(&counter);
			self.input(z);
			self.input(s1);
			self.result(&mut hash);

			result.extend_from_slice(&hash);
		}

		self.reset();
		result.truncate(len);

		result
	}
}

#[derive(Debug)]
pub struct EncryptionContext<'a> {
	pub curve: &'a secp256k1::Secp256k1,
	pub privkey: &'a secp256k1::key::SecretKey,
	pub pubkey: &'a secp256k1::key::PublicKey
}

impl<'a> EncryptionContext<'a> {
	pub fn encrypt(&self, msg: &[u8]) -> Vec<u8> {
		let (eprivkey, epubkey) = self.curve.generate_keypair(&mut thread_rng()).unwrap();

		let shared = secp256k1::ecdh::SharedSecret::new_raw(self.curve, self.pubkey, &eprivkey);

		let keylen = 16;

		let mut hasher = sha2::Sha256::new();

		let k = hasher.concat_kdf(&shared[..], &[] /* s1 */, 2 * keylen);

		let ke = &k[..keylen];
		let km = &k[keylen..];
		let mut kmhash = [0u8; 32];

		hasher.input(&km);
		hasher.result(&mut kmhash);
		hasher.reset();

		let enc = self.sym_encrypt(&ke, msg);

		let mut hmac = hmac::Hmac::new(hasher, &kmhash);

		hmac.input(&enc);
		/* hmac.input(s2) */

		let tag = hmac.result();

		let mut result = vec![0u8; 0];

		result.extend_from_slice(&epubkey.serialize_vec(self.curve, false));
		result.extend_from_slice(&enc);
		result.extend_from_slice(&tag.code());

		result
	}

	pub fn decrypt(&self, msg: &[u8]) -> Vec<u8> {
		let rlen = 65;
		let keylen = 16;
		let msglen = msg.len();
		let hashlen = 32;

		let epubkey = secp256k1::key::PublicKey::from_slice(self.curve, &msg[..rlen]).unwrap();

		let shared = secp256k1::ecdh::SharedSecret::new_raw(self.curve, &epubkey, self.privkey);

		let mut hasher = sha2::Sha256::new();

		let k = hasher.concat_kdf(&shared[..], &[] /* s1 */, 2 * keylen);

		let ke = &k[..keylen];
		let km = &k[keylen..];
		let mut kmhash = [0u8; 32];

		hasher.input(&km);
		hasher.result(&mut kmhash);
		hasher.reset();

		let mut hmac = hmac::Hmac::new(hasher, &kmhash);

		hmac.input(&msg[rlen..msglen - hashlen]);
		/* hmac.input(s2) */

		let tag = hmac.result();

		let msgtag = &msg[msglen - hashlen..];

		// todo: check equality in const time
		if tag.code() != msgtag {
			panic!("invalid msg tag")
		}

		self.sym_decrypt(&ke, &msg[rlen..msglen - hashlen])
	}


	fn sym_encrypt(&self, key: &[u8], msg: &[u8]) -> Vec<u8> {
		let mut iv = vec![0u8; 16];
		let mut ciphertext = vec![0u8; msg.len()];

		thread_rng().fill_bytes(&mut iv);

		let mut aes = aes::ctr(aes::KeySize::KeySize128, key, &iv);

		aes.process(msg, &mut ciphertext);

		let mut result: Vec<u8> = Vec::new();

		result.extend_from_slice(&iv);
		result.extend_from_slice(&ciphertext);

		result
	}

	fn sym_decrypt(&self, key: &[u8], ciphertext: &[u8]) -> Vec<u8> {
		let mut aes = aes::ctr(aes::KeySize::KeySize128, key, &ciphertext[..16]);

		let mut result = vec![0u8; ciphertext.len() - 16];

		aes.process(&ciphertext[16..], &mut result);

		result
	}
}
