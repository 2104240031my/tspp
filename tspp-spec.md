// TSPP: Transport-layer Stream Protection Protocol

enum FragmentType -> u8 {
    Hello             = 0x00,
    HelloDone         = 0x01,
    UserStream        = 0x02,
    Bye               = 0x03,
    KeyUpdate         = 0x04,
    HelloRetryRequest = 0x05,
    HelloRetry        = 0x06,
}

enum Version -> u32 {
    Null     = 0x00000000,
    Version1 = 0x00000001,
}

// KeyEx_PeerAuth_AEAD_HashFn
enum CipherSuite -> u64 {
    NULL_NULL_NULL_NULL                 = 0x0000000000000000,
    X25519_Ed25519_AES_128_GCM_SHA3_256 = 0x0000000000000001,
}

struct Fragment {
    frag_type: FragmentType,
    reserved: u8,
    length: u16, // # length of subsequent part
    ...
}

struct HelloFragment: Fragment {
    frag_type: FragmentType = FragmentType.Hello,
    reserved: u8,
    length: u16,
    version: Version,
    cipher_suite: CipherSuite,
    random: [u8; 64],
    ke_pubkey: [u8],   // # length can be derived from self.cipher_suite
    au_pubkey: [u8],   // # length can be derived from self.cipher_suite
    au_signature: [u8] // # length can be derived from self.cipher_suite
}

struct HelloDoneFragment: Fragment {
    frag_type: FragmentType = FragmentType.HelloDone,
    reserved: u8,
    length: u16,
    hello_phase_vrf_mac: [u8] // # length can be derived from known.cipher_suite
}

struct UserStreamFragment: Fragment {
    frag_type: FragmentType = FragmentType.UserStream,
    reserved: u8,
    length: u16,
    payload: [u8; self.length]
}

struct ByeFragment: Fragment {
    frag_type: FragmentType = FragmentType.Bye,
    reserved: u8,
    length: u16,
    bye_mac: [u8]
}

struct KeyUpdateFragment: Fragment {
    frag_type: FragmentType = FragmentType.KeyUpdate
    reserved: u8,
    length: u16 = 0,
}


[Initiator]                                          [Acceptor]

Hello ------------------>                                       // #
                                      <------------------ Hello // # Hello Phase
                                      <-------------- HelloDone // # encrypted
HelloDone -------------->                                       // #

// これ、もう1-RTT増やして、KeyShareで得たSecretも署名のInputに入れたほうがいいか？（InputにSecretを結合する必要がある => ke秘密鍵を持っていることの証明になる）
// それとも、ke秘密鍵を持っていることはHelloDone のMACで検証できるからいいか...？

// あるいは逆に、Secretを署名のInとすることは危険だったりするか...？（一方向性関数通してSubkeyとしてからにするか...？）



// SignとかKDFとかのinputって長さ情報もあったほうがいいんかな...

// # Ready to use UserStream fragment

UserStream <=======================================> UserStream

                               :
                               :

Bye -------------------->
                                      <-------------------- Bye

HelloFragment.au_signatureのinput dataは、

"TSPPv1 acceptor signature" || 0x80 || Hash(messages)

条件
- 下層のプロトコルが双方向通信可能なストリーム指向プロトコルであること。