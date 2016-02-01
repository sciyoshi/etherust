extern crate byteorder;
extern crate crypto as rustcrypto;

use byteorder::{BigEndian, ByteOrder};
use rustcrypto::digest::Digest;
use rustcrypto::sha3::Sha3;

trait KeyDerivation {
	fn concat_kdf(&mut self, z: &[u8], s1: &[u8]) -> Vec<u8>;
}

impl<D> KeyDerivation for D where D: Digest {
	fn concat_kdf(&mut self, z: &[u8], s1: &[u8]) -> Vec<u8> {
		let mut counter = [0u8; 4];
		let mut result = Vec::new::<u8>();

		for count in 0..((result.len() + self.output_bytes() - 1) / self.output_bytes()) {
			BigEndian::write_u32(&mut counter, count + 1 as u32);


		}

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

pub fn concat_kdf<D: Digest>(hasher: &mut D, bytes: &[u8], s1: &[u8], kdlen: usize) -> Vec<u8> {
	let reps = (kdlen + 7) / hasher.block_size();
	let mut counter = [0u8; 4];
	let mut k: Vec<u8> = Vec::new();

	println!("haha {:}", hasher.haha());

	for count in 1..reps + 2 {
		BigEndian::write_u32(&mut counter, count as u32);
		k.extend_from_slice(&hash!(*hasher; &counter, bytes, s1));
	}

	k.truncate(kdlen);

	return k
}
