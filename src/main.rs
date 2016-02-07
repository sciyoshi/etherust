extern crate mio;
extern crate rand;
extern crate etherust;
extern crate secp256k1;

use std::collections::HashMap;
use std::io::prelude::*;
use rand::thread_rng;

use mio::{EventLoop, Handler, Token, EventSet, PollOpt};
use mio::tcp::{TcpStream};

use etherust::rlpx::RlpxContext;
use etherust::crypto::EncryptionContext;

#[derive(Debug)]
enum PeerState {
	Initializing,
	AuthHandshake
}

#[derive(Debug)]
struct Peer<'a> {
	pub stream: TcpStream,
	pub rlpx: RlpxContext<'a>,
	pub state: PeerState
}

impl<'a> Peer<'a> {
	pub fn new(ctx: &'a EncryptionContext, stream: TcpStream) -> Self {
		let rlpx = RlpxContext::new(ctx);

		Peer {
			stream: stream,
			rlpx: rlpx,
			state: PeerState::Initializing
		}
	}

	pub fn handle(&mut self, events: EventSet) {
		match self.state {
			PeerState::Initializing => {
				self.stream.write(&self.rlpx.handshake());
				self.state = PeerState::AuthHandshake;
			},
			PeerState::AuthHandshake => {
				let mut read = [0u8; 210];

				let readres = self.stream.read(&mut read);

				println!("READ: {:?}", readres);
			}
		}
	}
}

struct PeerHandler<'a> {
	pub counter: usize,
	pub peers: HashMap<Token, Peer<'a>>
}

impl<'a> PeerHandler<'a> {
	pub fn new() -> Self {
		PeerHandler {
			counter: 0,
			peers: HashMap::new()
		}
	}

	pub fn register_peer(&mut self, event_loop: &mut EventLoop<Self>, context: &'a EncryptionContext<'a>, stream: TcpStream) {
		let peer = Peer::new(context, stream);
		let token = Token(self.counter);

		self.counter += 1;

		event_loop.register(&peer.stream, token, EventSet::all(), PollOpt::edge()).unwrap();

		self.peers.insert(token, peer);
	}
}

impl<'a> Handler for PeerHandler<'a> {
	type Timeout = ();
	type Message = u32;

	fn ready(&mut self, event_loop: &mut EventLoop<PeerHandler>, token: Token, events: EventSet) {
		match self.peers.get_mut(&token) {
			Some(peer) => {
				println!("ready!, {:?}", events);
				peer.handle(events);
			},
			None => {
				panic!("received event for non-existent peer");
			}
		}
	}
}

fn main() {
	let secp = secp256k1::Secp256k1::new();
	let privkey = secp256k1::key::SecretKey::new(&secp, &mut thread_rng());

	let rpub = b"\x04E\xae\xfc\xd8\xb4iQR]\xf9\x1c\x9b\xb1@\x89\xb6\x99%2_\xc5\x8e\\mb\xd6\xdb\x85O\x9b\x93\x99\xd3\xc0\x9b\x96p5\x90n\x05\xe3\xca\xd6\x15\xca\x93\x05\xa6u\x8c\x90A|\xc9\xca\xe3\xc6\x87\xaf=n]A";

	//let rpub = b"\x04\xa7J6\xc3\xf9\xe9\x82>\xe7\x00\xd8XF\x90\x04@]7\xe2FY\xea\xc8\x13\xbac?\xbfo\x9e\xdf\x14;\xb3\x90^ \x94\xb7\xbb\xd2\xad\xb5s\xe7\xeds[\x87\xe8>+\x13\x86\xd32)\x9e+\x11\xb1\x91\x85T";

	let rpubkey = secp256k1::key::PublicKey::from_slice(&secp, rpub).unwrap();

	let ctx = EncryptionContext {
		curve: &secp,
		privkey: &privkey,
		pubkey: &rpubkey
	};

	//////////////////////////////////

	let mut event_loop = EventLoop::new().unwrap();

	let mut peer_handler = PeerHandler::new();

	let stream = TcpStream::connect(&"127.0.0.1:30303".parse().unwrap()).unwrap();

	peer_handler.register_peer(&mut event_loop, &ctx, stream);

	let _ = event_loop.run(&mut peer_handler);

	/*
	let ctx = EncryptionContext {
		curve: &secp,
		privkey: &privkey,
		pubkey: &rpubkey
	};

	let rlpx = RlpxContext::new(&ctx);

	let encrypted = rlpx.handshake();

	let mut read = [0u8; 210];

	let writeres = stream.write(&encrypted);

	let readres = stream.read(&mut read);

	println!("WROTE: {:?}", writeres);
	println!("READ: {:?}", readres);

	rlpx.auth_handshake_decode(&read);
	*/
}
