# TSPP: Transport-layer Stream Protection Protocol

使用可能条件:
- 下層のプロトコルが双方向通信可能なストリーム指向プロトコルであること。

## Sequence
```
[ActiveOpener]                                   [PassiveOpener]

Hello ----------------------------->                             // #
                            <----------------------------- Hello // # Hello Phase
                            <------------------------- HelloDone // # encrypted
HelloDone ------------------------->                             // #

// # here, ready to use UserStream fragment

UserStream <========================================> UserStream

                               :
                               :

Bye ------------------------------>
                             <------------------------------ Bye
```

## Fragment
```
enum FragmentType -> u8 {
    Hello             = 0x00,
    HelloDone         = 0x01,
    UserStream        = 0x02,
    Bye               = 0x03,
    KeyUpdate         = 0x04,
    HelloRetryRequest = 0x05,
    HelloRetry        = 0x06,
}

struct Fragment {
    frag_type: FragmentType,
    reserved: u8,
    length: u16, // # length of payload (i.e. overall length - (header length + tag length))
    ...          // # subsequent fields
}

struct HelloFragment {
    // # common fields
    frag_type: FragmentType,
    reserved: u8,
    length: u16,

    // # type specific fields
    version: TsppVersion,
    cipher_suite: TsppCipherSuite,
    random: [u8; 64],
    ke_pubkey: [u8; KE_PUBKEY_LEN], // # length can be derived from self.cipher_suite
    au_pubkey: [u8; AU_PUBKEY_LEN], // # length can be derived from self.cipher_suite
    au_signature: [u8; AU_SIGN_LEN] // # length can be derived from self.cipher_suite
}

struct HelloDoneFragment {
    // # common fields
    frag_type: FragmentType,
    reserved: u8,
    length: u16,

    // # type specific fields
    hello_phase_vrf_mac: [u8; HASH_LEN] // # length can be derived from known.cipher_suite
}

struct UserStreamFragment {
    // # common fields
    frag_type: FragmentType,
    reserved: u8,
    length: u16,

    // # type specific fields
    payload: Vec<u8>,
    tag: [u8; AEAD_TAG_LEN]
}

struct ByeFragment {
    // # common fields
    frag_type: FragmentType = FragmentType.Bye,
    reserved: u8,
    length: u16,

    // # type specific fields
    bye_mac: [u8; MAC_LEN]
}

struct KeyUpdate {
    // # common fields
    frag_type: FragmentType,
    reserved: u8,
    length: u16,

    // # type specific fields
    key_upd_mac: [u8; MAC_LEN]
}
```

## Version ID
```
enum TsppVersion -> u8 {
    Null     = 0x00000000,
    Version1 = 0x00000001,
}
```

## Cipher Suite
```
// KeyEx_PeerAuth_AEAD_HashFn
enum TsppCipherSuite -> u8 {
    NULL_NULL_NULL_NULL                 = 0x0000000000000000,
    X25519_Ed25519_AES_128_GCM_SHA3_256 = 0x0000000000000001,
}
```



## memo

HelloFragment.au_signatureのinput dataは、

"TSPPv1 acceptor signature" || 0x80 || Hash(messages)