extern crate mio;
extern crate rand;
extern crate mioco;
extern crate crypto as rustcrypto;
extern crate etherust;
extern crate secp256k1;

use std::io::prelude::*;
use std::io;
use rand::thread_rng;

use mioco::tcp::{TcpStream};

use etherust::rlpx::RlpxContext;
use etherust::crypto::EncryptionContext;

use rustcrypto::digest::Digest;
use rustcrypto::sha3;
use rustcrypto::{aes, aesni, hmac, blockmodes};
use rustcrypto::symmetriccipher::BlockEncryptor;
use rustcrypto::mac::Mac;


#[inline]
fn bytes_to_u24(arg: &[u8]) -> u32 {
	((arg[0] as u32) << 16) + ((arg[1] as u32) << 8) + (arg[2] as u32)
}

fn update_mac<D: Digest + Clone, E: BlockEncryptor>(mac: &mut D, block: &E, seed: &[u8]) -> Vec<u8> {
	let mut buf = vec![0u8; block.block_size()];
	let mut macout = vec![0u8; mac.output_bytes()];

	mac.clone().result(&mut macout);

	block.encrypt_block(&macout, &mut buf);

	for i in 0..buf.len() {
		buf[i] = buf[i] ^ seed[i];
	}

	mac.input(&buf);
	mac.clone().result(&mut macout);

	macout.truncate(16);

	macout
}

fn peer_handler(mut stream: TcpStream, secp: &secp256k1::Secp256k1, privkey: &secp256k1::key::SecretKey, rpubkey: &secp256k1::key::PublicKey) -> io::Result<()> {
	let ctx = EncryptionContext {
		curve: secp,
		privkey: privkey,
		pubkey: rpubkey
	};

	let rlpx = RlpxContext::new(&ctx);

	let auth_handshake = rlpx.handshake();

	try!(stream.write_all(&auth_handshake));

	let mut handshake_resp = vec![0; 210];

	try!(stream.read_exact(&mut handshake_resp));

	let mut secrets = rlpx.auth_handshake_decode(&handshake_resp, &auth_handshake);

	println!("mac: {:?}", secrets.mac);
	println!("aes: {:?}", secrets.aes_secret);

	let mut proto_handshake = vec![0; 32];

	try!(stream.read_exact(&mut proto_handshake));

	println!("read: {:?}", &proto_handshake);

	let macc = aesni::AesNiEncryptor::new(aes::KeySize::KeySize256, &secrets.mac);

	let head = &proto_handshake[..16];
	let head_mac = &proto_handshake[16..32];

	let outmac = update_mac(&mut *secrets.ingress_mac, &macc, &head);

	// check equality
	println!("outmac: {:?}, {:?}", outmac, head_mac);

	let mut aes = aes::ctr(aes::KeySize::KeySize256, &secrets.aes_secret, &[0u8; 16]);

	let mut result = vec![0u8; 16];

	aes.process(head, &mut result);

	println!("dec: {:?}", result);

	let fsize = bytes_to_u24(&result[..3]) as usize;

	let mut rsize = fsize;

	if fsize % 16 != 0 {
		rsize += 16 - fsize % 16;
	}

	let mut buf = vec![0u8; rsize + 16];

	try!(stream.read_exact(&mut buf));

	secrets.ingress_mac.input(&buf[..rsize]);

	let mut fmacseed = [0u8; 16];
	secrets.ingress_mac.clone().result(&mut fmacseed);

	println!("buf: {:?}", buf);

	let outmac = update_mac(&mut *secrets.ingress_mac, &macc, &fmacseed);

	println!("outmac: {:?}, {:?}", outmac, &buf[rsize..]);

	let mut result = vec![0u8; rsize];

	aes.process(&buf[..rsize], &mut result);

	println!("MSG: {:?}", &result);

	Ok(())
}

fn main() {
	let secp = secp256k1::Secp256k1::new();
	let privkey = secp256k1::key::SecretKey::new(&secp, &mut thread_rng());

	let rpub = b"\x04E\xae\xfc\xd8\xb4iQR]\xf9\x1c\x9b\xb1@\x89\xb6\x99%2_\xc5\x8e\\mb\xd6\xdb\x85O\x9b\x93\x99\xd3\xc0\x9b\x96p5\x90n\x05\xe3\xca\xd6\x15\xca\x93\x05\xa6u\x8c\x90A|\xc9\xca\xe3\xc6\x87\xaf=n]A";

	//let rpub = b"\x04\xa7J6\xc3\xf9\xe9\x82>\xe7\x00\xd8XF\x90\x04@]7\xe2FY\xea\xc8\x13\xbac?\xbfo\x9e\xdf\x14;\xb3\x90^ \x94\xb7\xbb\xd2\xad\xb5s\xe7\xeds[\x87\xe8>+\x13\x86\xd32)\x9e+\x11\xb1\x91\x85T";

	let rpubkey = secp256k1::key::PublicKey::from_slice(&secp, rpub).unwrap();

	//////////////////////////////////

	mioco::start(move || {
		mioco::spawn(move || {
			let stream = TcpStream::connect(&"127.0.0.1:30303".parse().unwrap()).unwrap();

			peer_handler(stream, &secp, &privkey, &rpubkey);

			Ok(())
		});

		Ok(())
	});
}
