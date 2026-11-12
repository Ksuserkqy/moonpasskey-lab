///|
// Project synthetic fixtures, distinct from the W3C examples. Generated once
// outside the MoonBit core with Node.js 24.18.0 / OpenSSL 3.5.7. One ephemeral
// P-256 key signed authData || SHA256(original clientDataJSON), using ECDSA
// SHA-256 and DER output. OpenSSL independently verified all 44 signatures.
// Only public coordinates, messages and signatures are retained; no private
// key material is stored. Embedded signatures are fixed regression inputs.
struct AssertionSignedFixture {
  client : Bytes
  auth : Bytes
  signature : Bytes
}

///|
fn assertion_key_bytes() -> Bytes raise {
  w3c_hex(
    "a5010203262001215820367bf8b1c3707d4dec391a831471f17110d75a4101db99d0dc8a4653c65c6db92258203daf319a4397ec383d82eb7dc5cbc9dfcbf2c31ed25b02a245389af8e66c54e6",
    77,
  )
}

///|
fn assertion_key() -> @webauthn.ValidatedEs256PublicKey raise {
  crypto_imported(assertion_key_bytes())
}

///|
fn assertion_client(name : String) -> Bytes raise {
  let hex = match name {
    "base" =>
      "7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a22593268686247786c626d646c222c226f726967696e223a2268747470733a2f2f72702e74657374222c2263726f73734f726967696e223a66616c73657d"
    "cross_missing" =>
      "7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a22593268686247786c626d646c222c226f726967696e223a2268747470733a2f2f72702e74657374227d"
    "cross_true" =>
      "7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a22593268686247786c626d646c222c226f726967696e223a2268747470733a2f2f72702e74657374222c2263726f73734f726967696e223a747275657d"
    "top_true" =>
      "7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a22593268686247786c626d646c222c226f726967696e223a2268747470733a2f2f72702e74657374222c2263726f73734f726967696e223a747275652c22746f704f726967696e223a2268747470733a2f2f746f702e74657374227d"
    "reordered" =>
      "7b20226f726967696e22203a202268747470733a2f2f72702e74657374222c202263726f73734f726967696e223a66616c73652c20226368616c6c656e6765223a22593268686247786c626d646c222c202274797065223a22776562617574686e2e67657422207d"
    "origin_alt" =>
      "7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a22593268686247786c626d646c222c226f726967696e223a2268747470733a2f2f6c6f67696e2e72702e74657374222c2263726f73734f726967696e223a66616c73657d"
    "bom" =>
      "efbbbf7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a22593268686247786c626d646c222c226f726967696e223a2268747470733a2f2f72702e74657374222c2263726f73734f726967696e223a66616c73657d"
    _ => fail("unknown synthetic client fixture")
  }
  w3c_hex(hex, hex.length() / 2)
}

///|
fn assertion_fixture(
  flags~ : Byte = b'\x01',
  count~ : UInt32 = 0U,
  client~ : String = "base",
) -> AssertionSignedFixture raise {
  let (auth_hex, signature_hex) = match (flags.to_int(), count, client) {
    (1, 0U, "base") =>
      (
        "fb0ceb606e074ff0b3bfd62b9c3ce299307561e11c19dafc0fc91accb99c51ee0100000000",
        "304402207676e70ac9e333aa20b692a819f13b3958df76a0ac415cd5ca4ce0646e01bbc60220418a89295d962356bb6fd806e9099460c6085fbb560306ebb7e61face4133cfa",
      )
    (1, 3U, "base") =>
      (
        "fb0ceb606e074ff0b3bfd62b9c3ce299307561e11c19dafc0fc91accb99c51ee0100000003",
        "3045022100aae977d305d726493c2ce5dc2152ec78ecc30549f819287e33a44c46f7ee0ec80220108969b5d2b2a9e38c521ecbe9f9b2dad11170111f8860913d5aeefdca2f1f20",
      )
    (1, 5U, "base") =>
      (
        "fb0ceb606e074ff0b3bfd62b9c3ce299307561e11c19dafc0fc91accb99c51ee0100000005",
        "30450220250504e6cfd720f94c801086787b18922e2c47780996fa4921f4f0893ddb4fd60221008a645ec475e6d8f246ae1e85fb28d495649e7d1c4362c7312eb490e265c2096e",
      )
    (1, 8U, "base") =>
      (
        "fb0ceb606e074ff0b3bfd62b9c3ce299307561e11c19dafc0fc91accb99c51ee0100000008",
        "3046022100a357cc2e0468e0281d58815a087ad478204f19962259be594ee0e2662b1108460221009f77e7c045ab4772fd5ea683021fcd7de35f8a8acfc877c0b18215e3063afb08",
      )
    (1, 4294967295U, "base") =>
      (
        "fb0ceb606e074ff0b3bfd62b9c3ce299307561e11c19dafc0fc91accb99c51ee01ffffffff",
        "304402204b67d60ec91b0d39532f88f6da3ce833ce81d139ed741643a601560f14f4ce6e02205ded601c5a49f65c8d188ef887f800c612e377361bfb7dca5bd2b0e6a7cf5e98",
      )
    (5, 0U, "base") =>
      (
        "fb0ceb606e074ff0b3bfd62b9c3ce299307561e11c19dafc0fc91accb99c51ee0500000000",
        "304502202b841f35a8a263e3bf5633909836ed8d2b2843782cb7e72f3ba09366bc9e2edd022100f266e4e9c677855146e236783d4f4d891c92f2c0ab7b63f1383a842cdfbf0884",
      )
    (5, 3U, "base") =>
      (
        "fb0ceb606e074ff0b3bfd62b9c3ce299307561e11c19dafc0fc91accb99c51ee0500000003",
        "3045022100c072a9f15dab9af748eaa04d70e0e68ae4b795ee9ba5a543fad0247b48d0dd4e02203a0595dd26a1c0744bfada65b9d4dbe78f38940c052c2b239471bc3f07a55e70",
      )
    (5, 5U, "base") =>
      (
        "fb0ceb606e074ff0b3bfd62b9c3ce299307561e11c19dafc0fc91accb99c51ee0500000005",
        "3046022100fb11e85d3ddc2cd26e083761d05d8a8b0fc1b439a3dfe5752f35e5a525082ea60221009c6bd8d74b371ae279fee7d36e0c2ef180182391c5446c380537dbdbd61f6f96",
      )
    (5, 8U, "base") =>
      (
        "fb0ceb606e074ff0b3bfd62b9c3ce299307561e11c19dafc0fc91accb99c51ee0500000008",
        "3045022064da218fcecc58ce8ef3f43eaeb24b861a89a1ea727b3da09bda2578d7fcc44302210088dfe9fc7e483d0d74df2f53ca7af0c5a9609ac5dc6c8b92c8a76b7cfe58a082",
      )
    (5, 4294967295U, "base") =>
      (
        "fb0ceb606e074ff0b3bfd62b9c3ce299307561e11c19dafc0fc91accb99c51ee05ffffffff",
        "3045022100a42c01ead2f1433b3ccdaecfb57c4a5810d180ffc613d60f1b9ae4d721b4f08502200370451930d96bbbbe6255b37151f571060a135e565303799a812b63a6e4d32a",
      )
    (9, 0U, "base") =>
      (
        "fb0ceb606e074ff0b3bfd62b9c3ce299307561e11c19dafc0fc91accb99c51ee0900000000",
        "3045022100b11d5852d6bc0584dfe32a85ae60a02878c742dd2ce2ab64b0c753a4881fbf8b0220584942ef1586fcf6378f39b76ffe6926d2647c0a65c7c8ddd5e7bccaa909bfb2",
      )
    (9, 3U, "base") =>
      (
        "fb0ceb606e074ff0b3bfd62b9c3ce299307561e11c19dafc0fc91accb99c51ee0900000003",
        "3045022100d47d976a3092cf929d2461d2ca9a62947315e02a135556ec9951691686f224da0220474b2ba9e0c68d27768273ae61b64aac82ce04f8d1e00c5e39489bb9fa26419c",
      )
    (9, 5U, "base") =>
      (
        "fb0ceb606e074ff0b3bfd62b9c3ce299307561e11c19dafc0fc91accb99c51ee0900000005",
        "30450220418a0966c4c4731e035fcef18d9ad96b4f622c970164c976f034a236d06663f2022100cb68f4e980ecaeb61163b742733562ce08b8a3fbc7689c3d51b69f937e88902d",
      )
    (9, 8U, "base") =>
      (
        "fb0ceb606e074ff0b3bfd62b9c3ce299307561e11c19dafc0fc91accb99c51ee0900000008",
        "304502206389d0f5fa373de4b5f7605562fd7000eb82e8b556fe0b90f5ff27f97b1a36e802210080974a626af3c226f51aad4b57c954f60bda42a87d3c1fb9b35cac16bea404dc",
      )
    (9, 4294967295U, "base") =>
      (
        "fb0ceb606e074ff0b3bfd62b9c3ce299307561e11c19dafc0fc91accb99c51ee09ffffffff",
        "3045022100cef43b2dd2d1536e7ea78b3ee4cddeae0019aaee4330706b4d1dc45327ccb5d10220358f31ac14dcd874e68b92068540601dd7360641b315a5be0d8ba6dc3f3513b3",
      )
    (13, 0U, "base") =>
      (
        "fb0ceb606e074ff0b3bfd62b9c3ce299307561e11c19dafc0fc91accb99c51ee0d00000000",
        "3044022014f646231ab9bb77fe6ffadda2f8e41a239ab276b446dcaa88af1a67c00461e30220500eeb19a50d63debb72eb332ff27f628e52c2ba0015df31db6ecc4d093bb1f9",
      )
    (13, 3U, "base") =>
      (
        "fb0ceb606e074ff0b3bfd62b9c3ce299307561e11c19dafc0fc91accb99c51ee0d00000003",
        "3045022032562c9dae7c7a7ae34edd491269a129d5657154d9ee277ab3410dfcc6734b7d022100affc83ca66df090fcc870ca561857ea9c91cb4c9166c89b63a5c9dbd99ea1a11",
      )
    (13, 5U, "base") =>
      (
        "fb0ceb606e074ff0b3bfd62b9c3ce299307561e11c19dafc0fc91accb99c51ee0d00000005",
        "304402207513fa31db46665f9bce0d53ce31a8cb5fe36dcb05592ff2daf7d02d4bf8ba5c0220428bee1c9f150149df357ca219e00de00ed8a15bc07662dce5ef752cafdb85d4",
      )
    (13, 8U, "base") =>
      (
        "fb0ceb606e074ff0b3bfd62b9c3ce299307561e11c19dafc0fc91accb99c51ee0d00000008",
        "304402204372dbd0b24f775e4a7dae1254123b6c0c6e95f02894c47f200994f488374a9802205c0bf4b9ec50708d1c74e0ea76b8a910b0c5d88f363315fecc51271e9eb0f19e",
      )
    (13, 4294967295U, "base") =>
      (
        "fb0ceb606e074ff0b3bfd62b9c3ce299307561e11c19dafc0fc91accb99c51ee0dffffffff",
        "3046022100c976b2e0593f4aa71c0faa6371f348226c1d5ee389eb9fbe6a12295cef785ea6022100e360137845dad26b599bb9247e9440fb6f8289fe265ad91d0da9753119c31477",
      )
    (25, 0U, "base") =>
      (
        "fb0ceb606e074ff0b3bfd62b9c3ce299307561e11c19dafc0fc91accb99c51ee1900000000",
        "304502201f0449d97199d7ab8abff4806871f4137095811e9b255bdc02181061691b896d02210088f6752583fc086db149469188bf61131abd5bfbf4e16951e110387b4643ab5d",
      )
    (25, 3U, "base") =>
      (
        "fb0ceb606e074ff0b3bfd62b9c3ce299307561e11c19dafc0fc91accb99c51ee1900000003",
        "3046022100dedc1335a3b7f16e9d7b91c06c10869005f185526a0b10e4ffa32dcb73a2e724022100d6de07cffb97634f0835137f751b34aa3523b501989aac6c2ab3fea7eba62f64",
      )
    (25, 5U, "base") =>
      (
        "fb0ceb606e074ff0b3bfd62b9c3ce299307561e11c19dafc0fc91accb99c51ee1900000005",
        "3046022100c334ac149f099561ef5c9133457fca59806580c71f17d75b7c69328843040409022100bf09f95a1ff0e379962b24bd6853619878ed3df6068c33a2f0803df6d750f764",
      )
    (25, 8U, "base") =>
      (
        "fb0ceb606e074ff0b3bfd62b9c3ce299307561e11c19dafc0fc91accb99c51ee1900000008",
        "304502200e133943fca07d1c5adc23552da85ce8b02c44d932493e394d7e1d259a6c3d98022100fbe9cd10e9bd2f350211daf235c092013ec945fc714d4ae6be9b2925747aaaf2",
      )
    (25, 4294967295U, "base") =>
      (
        "fb0ceb606e074ff0b3bfd62b9c3ce299307561e11c19dafc0fc91accb99c51ee19ffffffff",
        "3046022100acd4a9ddf58282c9378e9f5aa5dd82820b18b77e9ce5c8ed03d12006ca7ddde1022100ccf48c54d4d910cd2dbf9bf4bdec28433c477fa0be67365f6983e7ca3c58a64e",
      )
    (29, 0U, "base") =>
      (
        "fb0ceb606e074ff0b3bfd62b9c3ce299307561e11c19dafc0fc91accb99c51ee1d00000000",
        "3045022100c2ff59572b943a61a086d866eab2c561bfc47c9597d125654684908c9f1d416002206f164e060813363be0b7537f0972ade293ac940d2731c51b603ef21a875f4d23",
      )
    (29, 3U, "base") =>
      (
        "fb0ceb606e074ff0b3bfd62b9c3ce299307561e11c19dafc0fc91accb99c51ee1d00000003",
        "3045022100e04755fc1a15039ef2f7d9617407943bddd63af7184caf07a09a963987fbb09e02201dbe46804e9447a974c7fb5ab397ff53b504e304e05c4427845a506d03f4cdd6",
      )
    (29, 5U, "base") =>
      (
        "fb0ceb606e074ff0b3bfd62b9c3ce299307561e11c19dafc0fc91accb99c51ee1d00000005",
        "3045022036394f62cec1acaeb0888768867155146dc25eb367af3ff18939e6b445bba4d8022100cd03977d5658f7206ae0c4fe925648823681df088e7fa5385268fb071e1a0871",
      )
    (29, 8U, "base") =>
      (
        "fb0ceb606e074ff0b3bfd62b9c3ce299307561e11c19dafc0fc91accb99c51ee1d00000008",
        "3044022074a6b77d9460dcfab52f1c8a0d81d92698325cedee07805a25f92e696183519402202a53452400d47fe461f9d7f75696861a1cd222cfbcb537867862219ce587d176",
      )
    (29, 4294967295U, "base") =>
      (
        "fb0ceb606e074ff0b3bfd62b9c3ce299307561e11c19dafc0fc91accb99c51ee1dffffffff",
        "3045022100855966c28009201c3058fa50a7c92306b699a0e738cfa310dfae5882dc0539f4022066ddd6c0b15349a3108314a852d30965d1d381802c629f6fe472f06108eac596",
      )
    (0, 0U, "base") =>
      (
        "fb0ceb606e074ff0b3bfd62b9c3ce299307561e11c19dafc0fc91accb99c51ee0000000000",
        "3046022100adbf93d7e736b24c9259a1ccb2a2a00d756b7115ee742b221b6a1355a0a3553902210099498afb66b93b78bb69bd72d8bc4a060f1fd7b0d0e5b808e6933fc3c6cfca28",
      )
    (4, 0U, "base") =>
      (
        "fb0ceb606e074ff0b3bfd62b9c3ce299307561e11c19dafc0fc91accb99c51ee0400000000",
        "304502202c48317b8777dabd5293d4121f1705a9dafeb6141fa3b0df55bb0814903a781f022100d6e64439caa8bd1325b64cb9edb826a127fc7428573dc06eb1fedfdd2964e0b0",
      )
    (3, 0U, "base") =>
      (
        "fb0ceb606e074ff0b3bfd62b9c3ce299307561e11c19dafc0fc91accb99c51ee0300000000",
        "3046022100f5583f7de7d79564e45636b20345e88fa279d37460025d9d0744d9e059cc27ee022100d7fae68eaa00713eec61de0ea68e84dbf71f686c624628b8c13559e25e1d7caa",
      )
    (33, 0U, "base") =>
      (
        "fb0ceb606e074ff0b3bfd62b9c3ce299307561e11c19dafc0fc91accb99c51ee2100000000",
        "3044022021c9b0fecf8d71ffad8ee6d714f9a0f9c8d537bd997ed661a265937742ceff2d022028d907e905e188e0c89bef72808cc661e4bdbf58e693c4f029ba34fa7326a1f5",
      )
    (17, 0U, "base") =>
      (
        "fb0ceb606e074ff0b3bfd62b9c3ce299307561e11c19dafc0fc91accb99c51ee1100000000",
        "3045022100d499235d55f2958078b6644957377f13539befb8298e60a7bfaa204ad117fca10220675f0c79a51a0513a841ba2bfdd6f6561527fdd374504d8daae49bc71cdbc142",
      )
    (65, 0U, "base") =>
      (
        "fb0ceb606e074ff0b3bfd62b9c3ce299307561e11c19dafc0fc91accb99c51ee410000000000000000000000000000000000000000000a63726564656e7469616ca5010203262001215820367bf8b1c3707d4dec391a831471f17110d75a4101db99d0dc8a4653c65c6db92258203daf319a4397ec383d82eb7dc5cbc9dfcbf2c31ed25b02a245389af8e66c54e6",
        "3045022100e07c1604dfdfa0841e5d44d0c30e7cf7928f63423c38db98d8c7f931548a4d3702206ea42edc01bce6dfc161404942961e1a935dbbefda67e9e0e832fad74a5735e0",
      )
    (129, 0U, "base") =>
      (
        "fb0ceb606e074ff0b3bfd62b9c3ce299307561e11c19dafc0fc91accb99c51ee8100000000a16178f5",
        "30460221008515a50f64e0b5d6cacabf59d18fcfe67e70032f10a3a2f0adb58edba8329495022100a4455f47009cab515c53fa1321d4c42bb077ffa29bd1eed918cca8f6f7c1774c",
      )
    (133, 0U, "base") =>
      (
        "fb0ceb606e074ff0b3bfd62b9c3ce299307561e11c19dafc0fc91accb99c51ee8500000000a16178f5",
        "3046022100a001b4d8822f46ba81ea0a51605fa4e80bfd04ddffe152590fcfa4e654b1b0c3022100b87e9b74d4f4c338a8120fff53aa75f792f2b362c6a2a4f0dcce081cf4f55d36",
      )
    (1, 0U, "cross_missing") =>
      (
        "fb0ceb606e074ff0b3bfd62b9c3ce299307561e11c19dafc0fc91accb99c51ee0100000000",
        "304402203b731d4dd0358b603ed4e95b779a0831225ff871fa136a5b9a0d69672fdd910c02203437953ada84b35210a2f764c2c62ab4201e3a0f9b990efac87b85f867145a29",
      )
    (1, 0U, "cross_true") =>
      (
        "fb0ceb606e074ff0b3bfd62b9c3ce299307561e11c19dafc0fc91accb99c51ee0100000000",
        "30460221008272401789ada2579651342bfa75a1100c862f3f05fc231542603eaf532370ff022100a314f7a098f448c03b90def9b177aca77da560807477ddae3acc8671ebe08487",
      )
    (1, 0U, "top_true") =>
      (
        "fb0ceb606e074ff0b3bfd62b9c3ce299307561e11c19dafc0fc91accb99c51ee0100000000",
        "304402205af66c52d301a98025f033d04f5003bbcd38f952fc9baeacb4b546e11e5a48c902204b03b9f653cfde940e104f1150ebfd9cd1435957e8d34e90fae6213366fa8528",
      )
    (1, 0U, "reordered") =>
      (
        "fb0ceb606e074ff0b3bfd62b9c3ce299307561e11c19dafc0fc91accb99c51ee0100000000",
        "3045022100db02690d310b87df0cc41d1f459c9aa740e10b5a21f36c177d69d0fe7a7c9d2b0220135b75b70e2e4d5aef6a2176cb187e9757c575961d7b58f5fd886eebe875d4b4",
      )
    (1, 0U, "origin_alt") =>
      (
        "fb0ceb606e074ff0b3bfd62b9c3ce299307561e11c19dafc0fc91accb99c51ee0100000000",
        "304502207a3ee527851effbee1e8f6dc1e3467e8874a91240bb886a8097c7f7554af07de022100b3440b27a015cff52e48ca356e2bf593a59eb42b815ba455127ab03169eb6d9d",
      )
    (1, 0U, "bom") =>
      (
        "fb0ceb606e074ff0b3bfd62b9c3ce299307561e11c19dafc0fc91accb99c51ee0100000000",
        "30450221009ab8a33fe3ac962351ea4e89317c033b23b461489d3af89490bda4a6fb14a1aa02201317e0d6f17b6f6e4d422d768268006a98374e79ecbfc78cbbfcaad92e460724",
      )
    _ => fail("unsigned synthetic fixture combination")
  }
  {
    client: assertion_client(client),
    auth: w3c_hex(auth_hex, auth_hex.length() / 2),
    signature: w3c_hex(signature_hex, signature_hex.length() / 2),
  }
}

///|
fn assertion_request(
  fixture : AssertionSignedFixture,
) -> @webauthn.AssertionVerificationRequest {
  {
    client_data_json: fixture.client,
    authenticator_data: fixture.auth,
    signature: fixture.signature,
    credential_id: b"credential",
    user_handle: Some(b"account"),
    expected_challenge: b"challenge",
    user_identification: @webauthn.Identified,
  }
}

///|
fn assertion_record(
  count~ : UInt32 = 0U,
  be~ : Bool? = None,
) -> @webauthn.AssertionCredentialRecord raise {
  {
    credential_id: b"credential",
    user_handle: b"account",
    public_key: assertion_key(),
    sign_count: count,
    backup_eligible: be,
  }
}

///|
fn assertion_policy() -> @webauthn.AssertionVerificationPolicy {
  @webauthn.AssertionVerificationPolicy::new("rp.test", ["https://rp.test"])
}

///|
fn assertion_ok(
  request : @webauthn.AssertionVerificationRequest,
  credential : @webauthn.AssertionCredentialRecord,
  policy : @webauthn.AssertionVerificationPolicy,
) -> @webauthn.AssertionVerificationResult raise {
  match @webauthn.verify_webauthn_es256_assertion(request, credential, policy) {
    Ok(result) => result
    Err(error) => fail("unexpected assertion failure \{error.to_repr()}")
  }
}

///|
fn assertion_error(
  request : @webauthn.AssertionVerificationRequest,
  credential : @webauthn.AssertionCredentialRecord,
  policy : @webauthn.AssertionVerificationPolicy,
  kind : @webauthn.AssertionVerificationErrorKind,
  context : String,
  offset~ : Int32? = None,
) -> Unit raise {
  match @webauthn.verify_webauthn_es256_assertion(request, credential, policy) {
    Err(error) => {
      assert_eq(error.kind, kind)
      assert_eq(error.context, context)
      assert_eq(error.offset, offset)
    }
    Ok(_) => fail("expected assertion error with no state update")
  }
}

///|
test "assertion all 44 fixed synthetic signatures verify exact fixture bytes" {
  let key = assertion_key()
  let fixtures : Array[AssertionSignedFixture] = []
  for flags in [b'\x01', b'\x05', b'\x09', b'\x0d', b'\x19', b'\x1d'] {
    for count in [0U, 3U, 5U, 8U, 4294967295U] {
      fixtures.push(assertion_fixture(flags~, count~))
    }
  }
  // Some fixtures intentionally violate assertion policy. This primitive
  // check establishes that their later rejection is independent of signature.
  for
    flags in [
      b'\x00', b'\x04', b'\x03', b'\x21', b'\x11', b'\x41', b'\x81', b'\x85',
    ] {
    fixtures.push(assertion_fixture(flags~))
  }
  for
    client in [
      "cross_missing", "cross_true", "top_true", "reordered", "origin_alt", "bom",
    ] {
    fixtures.push(assertion_fixture(client~))
  }
  assert_eq(fixtures.length(), 44)
  for fixture in fixtures {
    assert_eq(
      @webauthn.verify_webauthn_es256_assertion_signature(
        key,
        fixture.auth,
        fixture.client,
        fixture.signature,
      ),
      Ok(true),
    )
  }
}
