"""Ed25519 tests: RFC 8032 vectors plus fixtures generated with libsodium."""

import unittest

from app import ed25519

VECTORS = [
    # RFC 8032 section 7.1, TEST 2
    ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
     "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
     "72",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
     "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
    # RFC 8032 section 7.1, TEST 3
    ("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
     "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
     "af82",
     "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
     "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
    # libsodium fixture: empty message
    ("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
     "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8",
     "",
     "9ca53579530654d5c3df77089ef45eda613e2fedf670e96bedac4639504e5845"
     "ef4b95d5793077233dd16817b2532e9c5525872a73a4ad74b759369a9e05c102"),
    # libsodium fixture: canonical vote line format
    ("1dbcb4aeebd0e4d6ca98bc96af19683162482c3e3a37e0f237dce18214412121",
     "96313ed446c988dada1dfd3e095b86db9ff6277bc9ccaca392c8b79e9c375259",
     "6c6f636b2d61756469742e76310a766f74650a61756469743a736d6f6b650a766965773a330a626c6f636b3a616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261626162616261620a",
     "796015f45bcc600a6ca9d368ea15528137fc526c78df72998584b9271f1f0349"
     "1a23953ae737ce37b821e9cd509be9146d97713be585ad995e83969ec8500e06"),
    # libsodium fixture: non-ASCII UTF-8 message
    ("4755399ccb91598312ac30abb8f92c8494e7ea7e7cf8bbb4fd595ebe70b867bb",
     "e6731f3344edd4d96d55ad32be063fb3288a9159dd809ff1eba43336d0fded74",
     "e68f90e6a1882fe8af81e6988e2fe68a95e7a5a820e280942063616e6f6e6963"
     "616c205554462d3820e29c93",
     "e2360ea0154f597e34b92404866c0cb0b40baa6d5f9f47353e94c77ef08bf415"
     "43111765d7e1516b093b9c018714b9c78711909825e12b50c3d7b82ce242dd0a"),
    # libsodium fixture: 256-byte message
    ("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
     "76a1592044a6e4f511265bca73a604d90b0529d1df602be30a19a9257660d1f5",
     "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
     "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
     "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"
     "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"
     "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
     "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
     "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
     "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
     "7af20cb061d228589239f42bd5fef31d789e8f446ac8c7a2ec33c2820038b319"
     "496e593df7b00332afcdf6ca3b5d8c95e978de40bd4e5658eee2696d871cfa01"),
]


class TestVectors(unittest.TestCase):
    def test_vectors(self):
        for seed_hex, pk_hex, msg_hex, sig_hex in VECTORS:
            seed = bytes.fromhex(seed_hex)
            public = bytes.fromhex(pk_hex)
            message = bytes.fromhex(msg_hex)
            signature = bytes.fromhex(sig_hex)
            self.assertEqual(ed25519.publickey(seed), public)
            self.assertEqual(ed25519.sign(seed, message), signature)
            self.assertTrue(ed25519.verify(public, signature, message))

    def test_rejects_tampered_inputs(self):
        seed = bytes(range(32))
        public = ed25519.publickey(seed)
        message = b"canonical utf-8 fields"
        signature = ed25519.sign(seed, message)
        self.assertFalse(ed25519.verify(public, signature, message + b"x"))
        bad = bytearray(signature)
        bad[10] ^= 1
        self.assertFalse(ed25519.verify(public, bytes(bad), message))
        other = ed25519.publickey(bytes(range(32, 64)))
        self.assertFalse(ed25519.verify(other, signature, message))

    def test_rejects_malformed_values(self):
        public = ed25519.publickey(bytes(range(32)))
        signature = ed25519.sign(bytes(range(32)), b"m")
        self.assertFalse(ed25519.verify(b"short", signature, b"m"))
        self.assertFalse(ed25519.verify(public, b"short", b"m"))
        self.assertFalse(ed25519.verify(b"\xff" * 32, signature, b"m"))
        # S >= group order is rejected
        bad_s = signature[:32] + (2**253).to_bytes(32, "little")
        self.assertFalse(ed25519.verify(public, bad_s, b"m"))


if __name__ == "__main__":
    unittest.main()
