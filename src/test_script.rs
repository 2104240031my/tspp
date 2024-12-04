use crate::net::tspp::TsppCipherSuite;
use crate::net::tspp::TsppEngine;
use crate::net::tspp::TsppSocket;
use crate::net::tspp::TsppHelloPhaseState;
use crate::net::tspp::TsppRole;
use crate::net::tspp::TsppVersion;
use crate::net::crypto::DigitalSignatureAlgorithm;
use crate::net::util::TsppProtectedTcpListener;
use crate::net::util::TsppProtectedTcpStream;
use std::thread;

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

    let (s, _) = alice.hello_phase_send(&mut buf[..]).unwrap();

    printbytesln(&buf[..s]);
    println!("{}", s);

    let (_r, _) = bob.hello_phase_recv(&mut buf[..]).unwrap();
    let (_s, _) = bob.hello_phase_send(&mut buf[..]).unwrap();

    let (_r, _) = alice.hello_phase_recv(&mut buf[..]).unwrap();

    let (s, _) = bob.hello_phase_send(&mut buf[..]).unwrap();

    printbytesln(&buf[..s]);
    println!("{}", s);

    let (_r, _) = alice.hello_phase_recv(&mut buf[..]).unwrap();

    let (s, state) = alice.hello_phase_send(&mut buf[..]).unwrap();

    printbytesln(&buf[..s]);
    println!("{}", s);

    println!("{}", state == TsppHelloPhaseState::Done);

    let (_r, state) = bob.hello_phase_recv(&mut buf[..]).unwrap();
    println!("{}", state == TsppHelloPhaseState::Done);

    let mut buf: [u8; 256] = [0; 256];
    let (_, w) = alice.send("Hello, this is Alice.".as_bytes(), &mut buf[..]).unwrap();

    printbytesln(&buf[..w]);
    println!("{}", w);

    let mut buf2: [u8; 256] = [0; 256];
    let (_, w) = bob.recv(&buf[..w], &mut buf2[..]).unwrap();

    printbytesln(&buf2[..w]);
    println!("{}", std::str::from_utf8(&buf2[..w]).unwrap());
    println!("{}", w);

    let mut buf: [u8; 256] = [0; 256];
    let (_, w) = bob.send("Hello, this is Bob.".as_bytes(), &mut buf[..]).unwrap();

    printbytesln(&buf[..w]);
    println!("{}", w);

    let mut buf2: [u8; 256] = [0; 256];
    let (_, w) = alice.recv(&buf[..w], &mut buf2[..]).unwrap();

    printbytesln(&buf2[..w]);
    println!("{}", std::str::from_utf8(&buf2[..w]).unwrap());
    println!("{}", w);



    let mut buf: [u8; 256] = [0; 256];
    let mut w = 0;
    let (_, w2) = alice.send("Alice's 2nd message.".as_bytes(), &mut buf[w..]).unwrap();
    w += w2;
    let (_, w3) = alice.send("Alice's 3rd message.".as_bytes(), &mut buf[w..]).unwrap();
    w += w3;
    let (_, w4) = alice.send("Alice's 4th message.".as_bytes(), &mut buf[w..]).unwrap();
    w += w4;
    let (_, w5) = alice.send("Alice's 5th message.".as_bytes(), &mut buf[w..]).unwrap();
    w += w5;

    printbytesln(&buf[..w]);
    println!("{}", w);

    let mut buf2: [u8; 256] = [0; 256];
    let (_, w) = bob.recv(&buf[..w], &mut buf2[..]).unwrap();

    printbytesln(&buf2[..w]);
    println!("{}", std::str::from_utf8(&buf2[..w]).unwrap());
    println!("{}", w);



    let mut buf: [u8; 256] = [0; 256];
    let w = alice.send_bye(&mut buf[..]).unwrap();

    printbytesln(&buf[..w]);
    println!("{}", w);

    let mut buf2: [u8; 256] = [0; 256];
    let (r, w) = bob.recv(&buf[..w], &mut buf2[..]).unwrap();

    println!("{}, {}", r, w);


    let mut buf: [u8; 256] = [0; 256];
    let w = bob.send_bye(&mut buf[..]).unwrap();

    printbytesln(&buf[..w]);
    println!("{}", w);

    let mut buf2: [u8; 256] = [0; 256];
    let (r, w) = alice.recv(&buf[..w], &mut buf2[..]).unwrap();

    println!("{}, {}", r, w);

    test_util();

}

fn test_util() {

    let au_privkey: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
        0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60
    ];

    thread::spawn(|| {

        let au_privkey: [u8; 32] = [
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
            0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60
        ];

        let bob_listner = TsppProtectedTcpListener::bind(
            "127.0.0.1:65535",
            TsppVersion::Version1,
            TsppCipherSuite::X25519_Ed25519_AES_128_GCM_SHA3_256,
            &au_privkey
        ).unwrap();

        let mut bob = bob_listner.accept().unwrap();

        let mut buf: [u8; 256] = [0; 256];
        let w = bob.read(&mut buf[..]).unwrap();
        printbytesln(&buf[..w]);
        println!("{}", std::str::from_utf8(&buf[..w]).unwrap());
        bob.write("Hello, this is Bob.".as_bytes()).unwrap();

    });

    let mut alice = TsppProtectedTcpStream::connect(
        "127.0.0.1:65535",
        TsppVersion::Version1,
        TsppCipherSuite::X25519_Ed25519_AES_128_GCM_SHA3_256,
        &au_privkey
    ).unwrap();

    alice.write("Hello, this is Alice.".as_bytes()).unwrap();
    let mut buf: [u8; 256] = [0; 256];
    let w = alice.read(&mut buf[..]).unwrap();
    printbytesln(&buf[..w]);
    println!("{}", std::str::from_utf8(&buf[..w]).unwrap());


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