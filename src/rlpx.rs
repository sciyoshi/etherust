extern crate secp256k1;
extern crate crypto as rustcrypto;

use rand::{thread_rng, Rng};
use rustcrypto::digest::Digest;
use rustcrypto::sha3;
use crypto::EncryptionContext;

pub struct RlpxContext<'a> {
	pub context: &'a EncryptionContext<'a>,
	pub pubkey: secp256k1::key::PublicKey,
	pub randprivkey: secp256k1::key::SecretKey,
	pub randpubkey: secp256k1::key::PublicKey,
	pub nonce: Vec<u8>
}

impl<'a> RlpxContext<'a> {
	pub fn new(context: &'a EncryptionContext<'a>) -> Self {
		let (randprivkey, randpubkey) = context.curve.generate_keypair(&mut thread_rng()).unwrap();

		let mut nonce = vec![0; 32];

		thread_rng().fill_bytes(&mut nonce);

		RlpxContext {
			context: context,
			pubkey: secp256k1::key::PublicKey::from_secret_key(context.curve, context.privkey).unwrap(),
			randprivkey: randprivkey,
			randpubkey: randpubkey,
			nonce: nonce
		}
	}

	pub fn handshake(&self) -> Vec<u8> {
		let mut hasher = sha3::Sha3::keccak256();
		let token = 0u8;

		let shared = secp256k1::ecdh::SharedSecret::new_raw(self.context.curve, self.context.pubkey, self.context.privkey);

		let mut signed: [u8; 32] = [0; 32];

		for i in 0..32 {
			signed[i] = shared[i] ^ self.nonce[i];
		}

		let signature = self.context.curve.sign_recoverable(&secp256k1::Message::from_slice(&signed).unwrap(), &self.randprivkey).unwrap();

		let (sigrecid, sigserial) = signature.serialize_compact(self.context.curve);

		let mut msg = vec![0u8; 0];

		let mut randpubsha = [0u8; 32];

		hasher.input(&self.randpubkey.serialize_vec(self.context.curve, false)[1..]);
		hasher.result(&mut randpubsha);
		hasher.reset();

		msg.extend_from_slice(&sigserial);
		msg.push(sigrecid.to_i32() as u8);
		msg.extend_from_slice(&randpubsha);
		msg.extend_from_slice(&self.pubkey.serialize_vec(self.context.curve, false)[1..]);
		msg.extend_from_slice(&self.nonce);
		msg.push(token);

		println!("RANDPUBKEY\n========\n{:?}", &self.randpubkey.serialize_vec(self.context.curve, false)[1..]);
		println!("RANDPUBSHA\n========\n{:?}", &randpubsha);
		println!("SIGNED\n========\n{:?}", &signed);
		println!("SHARED\n========\n{:?}", &shared);
		println!("SIGSERIAL\n========\n{:?}", &sigserial[..]);
		println!("SIGRECID\n========\n{:?}", sigrecid.to_i32() as u8);
		println!("PUBKEY\n========\n{:?}", &self.pubkey.serialize_vec(self.context.curve, false)[1..]);
		println!("NONCE\n========\n{:?}", &self.nonce);

		self.context.encrypt(&msg)
	}
}
