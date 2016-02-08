extern crate secp256k1;
extern crate crypto as rustcrypto;

use rand::{thread_rng, Rng};
use rustcrypto::digest::Digest;
use rustcrypto::sha3;
use crypto::EncryptionContext;

#[derive(Debug)]
pub struct RlpxContext<'a> {
	pub context: &'a EncryptionContext<'a>,
	pub pubkey: secp256k1::key::PublicKey,
	pub randprivkey: secp256k1::key::SecretKey,
	pub randpubkey: secp256k1::key::PublicKey,
	pub nonce: Vec<u8>
}

pub struct RlpxSecrets<D: Digest> {
	pub aes_secret: Vec<u8>,
	pub mac: Vec<u8>,
	pub token: Vec<u8>,
	pub egress_mac: Box<D>,
	pub ingress_mac: Box<D>,
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

		self.context.encrypt(&msg)
	}

	pub fn auth_handshake_decode(&self, msg: &[u8]) -> RlpxSecrets<sha3::Sha3> {
		let mut hasher = sha3::Sha3::keccak256();
		let authresp = self.context.decrypt(msg);

		let mut key = vec![4u8];

		key.extend_from_slice(&authresp[..64]);

		let remoterandpubkey = secp256k1::key::PublicKey::from_slice(self.context.curve, &key).unwrap();

		let remotenonce = &authresp[64..96];
		let remotetoken = &authresp[96];

		let ecdhe_secret = secp256k1::ecdh::SharedSecret::new_raw(self.context.curve, &remoterandpubkey, &self.randprivkey);

		let mut shared_secret = [0u8; 32];
		let mut shared_tmp = [0u8; 32];

		let mut secrets = RlpxSecrets {
			aes_secret: vec![0u8; 32],
			mac: vec![0u8; 32],
			token: vec![0u8; 32],
			egress_mac: Box::new(sha3::Sha3::keccak256()),
			ingress_mac: Box::new(sha3::Sha3::keccak256())
		};

		hasher.input(&remotenonce);
		hasher.input(&self.nonce);
		hasher.result(&mut shared_tmp);
		hasher.reset();

		hasher.input(&ecdhe_secret[..]);
		hasher.input(&shared_tmp);
		hasher.result(&mut shared_secret);
		hasher.reset();

		hasher.input(&ecdhe_secret[..]);
		hasher.input(&shared_secret);
		hasher.result(&mut secrets.aes_secret);
		hasher.reset();

		hasher.input(&ecdhe_secret[..]);
		hasher.input(&secrets.aes_secret);
		hasher.result(&mut secrets.mac);
		hasher.reset();

		hasher.input(&shared_secret);
		hasher.result(&mut secrets.token);
		hasher.reset();

		println!("ecdhe_secret: {:?}", &ecdhe_secret[..]);
		println!("shared_secret: {:?}", &shared_secret);
		println!("aes_secret: {:?}", &secrets.aes_secret);
		println!("mac: {:?}", &secrets.mac);
		println!("token: {:?}", &secrets.token);

		secrets
	}
}
