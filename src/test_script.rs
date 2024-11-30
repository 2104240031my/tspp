use crate::net::tspp::TsppCipherSuite;
use crate::net::tspp::TsppEngine;
use crate::net::tspp::TsppSocket;
use crate::net::tspp::TsppState;
use crate::net::tspp::TsppRole;
use crate::net::tspp::TsppVersion;
use cryptopkg::crypto::util::DigitalSignatureAlgorithm;

pub fn main() {

    let au_privkey: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
        0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60
    ];

    let au_pubkey: [u8; 32] = [
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
        0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a
    ];

    TsppEngine::insert_known_peer_auth_public_key(DigitalSignatureAlgorithm::Ed25519, &au_pubkey[..]);

    let mut alice: TsppSocket = TsppSocket::new(
        TsppVersion::Version1,
        TsppCipherSuite::X25519_Ed25519_AES_128_GCM_SHA3_256,
        TsppRole::ActiveOpener,
        &au_privkey[..]
    ).unwrap();

    let mut bob: TsppSocket = TsppSocket::new(
        TsppVersion::Version1,
        TsppCipherSuite::X25519_Ed25519_AES_128_GCM_SHA3_256,
        TsppRole::PassiveOpener,
        &au_privkey[..]
    ).unwrap();

    let mut buf: [u8; 1024] = [0; 1024];

    let (s, _): (usize, TsppState) = alice.hello_phase_send(&mut buf[..]).unwrap();

    printbytesln(&buf[..s]);
    println!("{}", s);

    let (_r, _): (usize, TsppState) = bob.hello_phase_recv(&buf[..]).unwrap();
    let (_s, _): (usize, TsppState) = bob.hello_phase_send(&mut buf[..]).unwrap();

    let (_r, _): (usize, TsppState) = alice.hello_phase_recv(&buf[..]).unwrap();

    let (s, _): (usize, TsppState) = bob.hello_phase_send(&mut buf[..]).unwrap();

    printbytesln(&buf[..s]);
    println!("{}", s);

    let (_r, _): (usize, TsppState) = alice.hello_phase_recv(&buf[..]).unwrap();

    let (s, _): (usize, TsppState) = alice.hello_phase_send(&mut buf[..]).unwrap();

    printbytesln(&buf[..s]);
    println!("{}", s);

    let (_r, _): (usize, TsppState) = bob.hello_phase_recv(&buf[..]).unwrap();

}

pub fn printbytes(bytes: &[u8]) {
    for i in 0..bytes.len() {
        print!("{:02x}", bytes[i]);
    }
}

pub fn printbytesln(bytes: &[u8]) {
    printbytes(bytes);
    println!();
}