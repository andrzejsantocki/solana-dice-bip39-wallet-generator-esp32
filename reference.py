"""Reference implementation + official test vectors for wallet_core verification.
BIP39: official trezor vectors.json (english, 256-bit ENT, implicit passphrase "TREZOR").
SLIP-0010: official spec vectors; Solana: pynacl <-> cryptography cross-check.
Outputs tests/reference_vectors.json consumed by the host C++ test harness.
"""
import hashlib, hmac, json, unicodedata
import nacl.signing
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

WORDS = [w.strip() for w in open("lib/bip39/english.txt") if w.strip()]
assert len(WORDS) == 2048 and len(set(WORDS)) == 2048

BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def base58(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = BASE58[r] + out
    pad = 0
    for b in data:
        if b == 0: pad += 1
        else: break
    return "1" * pad + (out or "")

def sha256(b): return hashlib.sha256(b).digest()
def hmac512(key, data): return hmac.new(key, data, hashlib.sha512).digest()
def nfkd(s): return unicodedata.normalize("NFKD", s)

def mnemonic_from_entropy(ent: bytes) -> str:
    assert len(ent) == 32
    cs = sha256(ent)[0]
    bits = "".join(f"{b:08b}" for b in ent) + f"{cs:08b}"
    return " ".join(WORDS[int(bits[i:i+11], 2)] for i in range(0, 264, 11))

def seed_from_mnemonic(mnemonic: str, passphrase: str = "") -> bytes:
    salt = ("mnemonic" + nfkd(passphrase)).encode()
    return hashlib.pbkdf2_hmac("sha512", nfkd(mnemonic).encode(), salt, 2048, 64)

def slip10_master(seed: bytes):
    I = hmac512(b"ed25519 seed", seed)
    return I[:32], I[32:]

def slip10_child(kL, cc, index):  # hardened only
    I = hmac512(cc, b"\x00" + kL + (index | 0x80000000).to_bytes(4, "big"))
    return I[:32], I[32:]

def solana_keypair(seed: bytes):  # m/44'/501'/0'/0'
    kL, cc = slip10_master(seed)
    for idx in (44, 501, 0, 0):
        kL, cc = slip10_child(kL, cc, idx)
    return kL

def pub_pynacl(s32): return bytes(nacl.signing.SigningKey(s32).verify_key)
def pub_crypto(s32):
    k = Ed25519PrivateKey.from_private_bytes(s32)
    return k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

results = {"bip39": [], "slip10": [], "solana": [], "nfkd": []}

# ---- BIP39: official vectors (english, 256-bit, passphrase "TREZOR") ----
tv = json.load(open("tests/vectors.json"))["english"]
tv256 = [x for x in tv if len(x[0]) == 64]
print("256-bit vectors:", len(tv256))
for ent_hex, mnem_expected, seed_expected, _xprv in tv256:
    ent = bytes.fromhex(ent_hex)
    mn = mnemonic_from_entropy(ent)
    sd = seed_from_mnemonic(mn, "TREZOR")
    assert mn == mnem_expected, (ent_hex, mn, mnem_expected)
    assert sd.hex() == seed_expected, (ent_hex, sd.hex(), seed_expected)
    results["bip39"].append({"entropy": ent_hex, "passphrase": "TREZOR",
                             "mnemonic": mn, "seed": sd.hex()})
print("BIP39 OK:", len(tv256))

# ---- SLIP-0010 official ed25519 vectors (seed 000102...0f; pubkeys carry 0x00 prefix) ----
seed = bytes(range(16))
kL, cc = slip10_master(seed)
slip10_expected = [
    ("m",       "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7",
                "90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb",
                "00a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed"),
    ("m/0'",    "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3",
                "8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69",
                "008c8a13df77a28f3445213a0f432fde644acaa215fc72dcdf300d5efaa85d350c"),
    ("m/0'/1'", "b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2",
                "a320425f77d1b5c2505a6b1b27382b37368ee640e3557c315416801243552f14",
                "001932a5270f335bed617d5b935c80aedb1a35bd9fc1e31acafd5372c30f5c1187"),
]
step = {"m": 0, "m/0'": 1}
for name, priv_e, chain_e, pub_e in slip10_expected:
    assert kL.hex() == priv_e, (name, kL.hex(), priv_e)
    assert cc.hex() == chain_e, (name, cc.hex(), chain_e)
    pub = pub_pynacl(kL)
    assert b"\x00" + pub == bytes.fromhex(pub_e), (name, pub.hex(), pub_e)
    results["slip10"].append({"path": name, "private": kL.hex(),
                              "chaincode": cc.hex(), "public": pub.hex()})
    if name in step:
        kL, cc = slip10_child(kL, cc, step[name])
print("SLIP-0010 OK:", len(slip10_expected))

# ---- Solana m/44'/501'/0'/0' ----
for b in results["bip39"]:
    sd = seed_from_mnemonic(b["mnemonic"], b["passphrase"])
    kL_s = solana_keypair(sd)
    p1, p2 = pub_pynacl(kL_s), pub_crypto(kL_s)
    assert p1 == p2
    results["solana"].append({"mnemonic": b["mnemonic"], "passphrase": b["passphrase"],
                              "private": kL_s.hex(), "public": p1.hex(),
                              "address": base58(p1)})
print("SOLANA OK:", len(results["solana"]))

# ---- NFKD: NFD vs NFC passphrase forms -> same seed ----
pp1, pp2 = "Spa\u0308tlese", "Sp\u00e4tlese"
sd1 = seed_from_mnemonic(results["bip39"][0]["mnemonic"], pp1)
sd2 = seed_from_mnemonic(results["bip39"][0]["mnemonic"], pp2)
assert sd1 == sd2
results["nfkd"].append({"passphrase_nfd": pp1, "passphrase_nfc": pp2, "seed": sd1.hex()})
print("NFKD OK")

json.dump(results, open("tests/reference_vectors.json", "w"), indent=1)
print("ALL REFERENCE VECTORS PASSED -> tests/reference_vectors.json")
