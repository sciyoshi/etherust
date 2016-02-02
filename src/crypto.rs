extern crate byteorder;
extern crate crypto as rustcrypto;

use byteorder::{BigEndian, ByteOrder};
use rustcrypto::{aes, hmac};
use rustcrypto::digest::Digest;
use rustcrypto::sha3::Sha3;

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

#[macro_export]
macro_rules! hash {
	($hasher:expr; $($w:expr),+) => {
		{
			let ref mut hasher = $hasher;
			let mut result = vec![0u8; hasher.output_bits() / 8];

			$(
				hasher.input($w);
			)*

			hasher.result(&mut result);
			hasher.reset();

			result
		}
	};
}
