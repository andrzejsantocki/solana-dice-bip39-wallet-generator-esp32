"""Generate tests/host_test/vectors.inc from tests/reference_vectors.json."""
import json

v = json.load(open("tests/reference_vectors.json"))
out = []
out.append("// Auto-generated from tests/reference_vectors.json. Do not edit.")
out.append("#pragma once")
out.append("#include <stdint.h>")
out.append("")

out.append("typedef struct { const char* entropy; const char* passphrase; "
           "const char* mnemonic; const char* seed; } Bip39Vector;")
out.append("static const Bip39Vector BIP39_VECTORS[] = {")
for b in v["bip39"]:
    out.append(f'  {{"{b["entropy"]}", "{b["passphrase"]}", "{b["mnemonic"]}", "{b["seed"]}"}},')
out.append("};")
out.append("")

out.append("typedef struct { const char* path; const char* priv; "
           "const char* chaincode; const char* pub; } Slip10Vector;")
out.append("static const Slip10Vector SLIP10_VECTORS[] = {")
for s in v["slip10"]:
    out.append(f'  {{"{s["path"]}", "{s["private"]}", "{s["chaincode"]}", "{s["public"]}"}},')
out.append("};")
out.append("")

out.append("typedef struct { const char* mnemonic; const char* passphrase; "
           "const char* priv; const char* pub; const char* address; } SolanaVector;")
out.append("static const SolanaVector SOLANA_VECTORS[] = {")
for s in v["solana"]:
    out.append(f'  {{"{s["mnemonic"]}", "{s["passphrase"]}", "{s["private"]}", "{s["public"]}", "{s["address"]}"}},')
out.append("};")
out.append("")

out.append("typedef struct { const char* nfd; const char* nfc; const char* seed; } NfkdVector;")
out.append("static const NfkdVector NFKD_VECTORS[] = {")
for n in v["nfkd"]:
    out.append(f'  {{"{n["passphrase_nfd"]}", "{n["passphrase_nfc"]}", "{n["seed"]}"}},')
out.append("};")
out.append("")
out.append("#define BIP39_VECTOR_COUNT %d" % len(v["bip39"]))
out.append("#define SLIP10_VECTOR_COUNT %d" % len(v["slip10"]))
out.append("#define SOLANA_VECTOR_COUNT %d" % len(v["solana"]))
out.append("#define NFKD_VECTOR_COUNT %d" % len(v["nfkd"]))

open("tests/host_test/vectors.inc", "w").write("\n".join(out))
print("vectors.inc written:", len(v["bip39"]), len(v["slip10"]),
      len(v["solana"]), len(v["nfkd"]))
