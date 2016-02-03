extern crate secp256k1;
extern crate rand;
extern crate byteorder;
extern crate crypto;
extern crate etherust;

use std::io::prelude::*;
use std::time;
use std::thread;
use rand::Rng;
use std::net::TcpStream;
use byteorder::{BigEndian, ByteOrder};
use crypto::mac::Mac;
use crypto::digest::Digest;
use crypto::symmetriccipher::{Encryptor, Decryptor};
use crypto::{sha2, sha3, aes, mac, hmac};

use etherust::rlpx;
use etherust::crypto::{KeyDerivation, EncryptionContext};

fn main() {
	let mut rng = rand::OsRng::new().unwrap();
	let secp = secp256k1::Secp256k1::new();
	let mut hasher = sha3::Sha3::keccak256();

	let token = 0u8;

	//let rpub = b"\x04\xa9y\xfbWT\x95\xb8\xd6\xdbD\xf7P1}\x0fF\"\xbfL*\xa36]j\xf7\xc2\x843\x99h\xee\xf2\x9bi\xad\r\xcer\xa4\xd8\xdb^\xbbIh\xde\x0e;\xec\x91\x01\'\xf14w\x9f\xbc\xb0\xcbm31\x16<";
	//let rpub = b"\x04\xa7J6\xc3\xf9\xe9\x82>\xe7\x00\xd8XF\x90\x04@]7\xe2FY\xea\xc8\x13\xbac?\xbfo\x9e\xdf\x14;\xb3\x90^ \x94\xb7\xbb\xd2\xad\xb5s\xe7\xeds[\x87\xe8>+\x13\x86\xd32)\x9e+\x11\xb1\x91\x85T";
	let rpub = b"\x04E\xae\xfc\xd8\xb4iQR]\xf9\x1c\x9b\xb1@\x89\xb6\x99%2_\xc5\x8e\\mb\xd6\xdb\x85O\x9b\x93\x99\xd3\xc0\x9b\x96p5\x90n\x05\xe3\xca\xd6\x15\xca\x93\x05\xa6u\x8c\x90A|\xc9\xca\xe3\xc6\x87\xaf=n]A";
	let rpubkey = secp256k1::key::PublicKey::from_slice(&secp, rpub).unwrap();

	let (privkey, pubkey) = secp.generate_keypair(&mut rng).unwrap();

	let (randprivkey, randpubkey) = secp.generate_keypair(&mut rng).unwrap();

	let shared = secp256k1::ecdh::SharedSecret::new_raw(&secp, &rpubkey, &privkey);

	let mut nonce: [u8; 32] = [0; 32];

	let mut signed: [u8; 32] = [0; 32];

	rng.fill_bytes(&mut nonce);

	for i in 0..32 {
		signed[i] = shared[i] ^ nonce[i];
	}

	let signature = secp.sign_recoverable(&secp256k1::Message::from_slice(&signed).unwrap(), &randprivkey).unwrap();

	let (sigrecid, sigserial) = signature.serialize_compact(&secp);

	let mut msg = vec![0u8; 0];

	let mut randpubsha = [0u8; 32];

	hasher.input(&randpubkey.serialize_vec(&secp, false)[1..]);
	hasher.result(&mut randpubsha);
	hasher.reset();

	msg.extend_from_slice(&sigserial);
	msg.push(sigrecid.to_i32() as u8);
	msg.extend_from_slice(&randpubsha);
	msg.extend_from_slice(&pubkey.serialize_vec(&secp, false)[1..]);
	msg.extend_from_slice(&nonce);
	msg.push(token);

	println!("RANDPUBKEY\n========\n{:?}", &randpubkey.serialize_vec(&secp, false)[1..]);
	println!("RANDPUBSHA\n========\n{:?}", &randpubsha);
	println!("SIGNED\n========\n{:?}", &signed);
	println!("SHARED\n========\n{:?}", &shared);
	println!("SIGSERIAL\n========\n{:?}", &sigserial[..]);
	println!("SIGRECID\n========\n{:?}", sigrecid.to_i32() as u8);
	println!("PUBKEY\n========\n{:?}", &pubkey.serialize_vec(&secp, false)[1..]);
	println!("NONCE\n========\n{:?}", &nonce);

	let mut ctx = EncryptionContext {
		curve: &secp,
		privkey: &privkey,
		pubkey: &rpubkey
	};

	let encrypted = ctx.encrypt(&msg);

	let mut stream = TcpStream::connect("127.0.0.1:30303").unwrap();

	let mut read = [0u8; 210];

	let writeres = stream.write(&encrypted);

	let readres = stream.read(&mut read);

	println!("RES: {:?}", writeres);
	println!("RES: {:?}", readres);
	println!("READ: {:?}", &read[..]);

	let authresp = ctx.decrypt(&read[..]);

	let mut key = vec![4u8];

	key.extend_from_slice(&authresp[..64]);

	let remoterandpubkey = secp256k1::key::PublicKey::from_slice(&secp, &key).unwrap();

	let remotenonce = &authresp[64..96];
	let remotetoken = &authresp[96];

	println!("REMOTERANDPUBKEY: {:?}", &remoterandpubkey.serialize_vec(&secp, false));

	let ecdheSecret = secp256k1::ecdh::SharedSecret::new_raw(&secp, &remoterandpubkey, &randprivkey);
	let mut sharedSecret = [0u8; 32];

	let mut sharedTmp = [0u8; 32];

	println!("RNONCE\n========\n{:?}", &remotenonce);

	hasher.input(&remotenonce);
	hasher.input(&nonce);
	hasher.result(&mut sharedTmp);
	hasher.reset();

	println!("STMP\n========\n{:?}", &sharedTmp);

	hasher.input(&ecdheSecret[..]);
	hasher.input(&sharedTmp);
	hasher.result(&mut sharedSecret);
	hasher.reset();

	println!("ecdheSecret: {:?}", &ecdheSecret[..]);
	println!("sharedSecret: {:?}", &sharedSecret);
}
