extern crate mio;
extern crate rand;
extern crate mioco;
extern crate etherust;
extern crate secp256k1;

use std::collections::HashMap;
use std::io::prelude::*;
use std::io;
use rand::thread_rng;

use mioco::tcp::{TcpStream};

use etherust::rlpx::RlpxContext;
use etherust::crypto::EncryptionContext;

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

	rlpx.auth_handshake_decode(&handshake_resp);

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
