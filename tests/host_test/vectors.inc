// Auto-generated from tests/reference_vectors.json. Do not edit.
#pragma once
#include <stdint.h>

typedef struct { const char* entropy; const char* passphrase; const char* mnemonic; const char* seed; } Bip39Vector;
static const Bip39Vector BIP39_VECTORS[] = {
  {"0000000000000000000000000000000000000000000000000000000000000000", "TREZOR", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art", "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8"},
  {"7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f", "TREZOR", "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title", "bc09fca1804f7e69da93c2f2028eb238c227f2e9dda30cd63699232578480a4021b146ad717fbb7e451ce9eb835f43620bf5c514db0f8add49f5d121449d3e87"},
  {"8080808080808080808080808080808080808080808080808080808080808080", "TREZOR", "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless", "c0c519bd0e91a2ed54357d9d1ebef6f5af218a153624cf4f2da911a0ed8f7a09e2ef61af0aca007096df430022f7a2b6fb91661a9589097069720d015e4e982f"},
  {"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "TREZOR", "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote", "dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e1613912f0a5b694407be899ffd31ed3992c456cdf60f5d4564b8ba3f05a69890ad"},
  {"68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c", "TREZOR", "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length", "64c87cde7e12ecf6704ab95bb1408bef047c22db4cc7491c4271d170a1b213d20b385bc1588d9c7b38f1b39d415665b8a9030c9ec653d75e65f847d8fc1fc440"},
  {"9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863", "TREZOR", "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside", "72be8e052fc4919d2adf28d5306b5474b0069df35b02303de8c1729c9538dbb6fc2d731d5f832193cd9fb6aeecbc469594a70e3dd50811b5067f3b88b28c3e8d"},
  {"066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad", "TREZOR", "all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform", "26e975ec644423f4a4c4f4215ef09b4bd7ef924e85d1d17c4cf3f136c2863cf6df0a475045652c57eb5fb41513ca2a2d67722b77e954b4b3fc11f7590449191d"},
  {"f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f", "TREZOR", "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold", "01f5bced59dec48e362f2c45b5de68b9fd6c92c6634f44d6d40aab69056506f0e35524a518034ddc1192e1dacd32c1ed3eaa3c3b131c88ed8e7e54c49a5d0998"},
};

typedef struct { const char* path; const char* priv; const char* chaincode; const char* pub; } Slip10Vector;
static const Slip10Vector SLIP10_VECTORS[] = {
  {"m", "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7", "90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb", "a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed"},
  {"m/0'", "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3", "8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69", "8c8a13df77a28f3445213a0f432fde644acaa215fc72dcdf300d5efaa85d350c"},
  {"m/0'/1'", "b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2", "a320425f77d1b5c2505a6b1b27382b37368ee640e3557c315416801243552f14", "1932a5270f335bed617d5b935c80aedb1a35bd9fc1e31acafd5372c30f5c1187"},
};

typedef struct { const char* mnemonic; const char* passphrase; const char* priv; const char* pub; const char* address; } SolanaVector;
static const SolanaVector SOLANA_VECTORS[] = {
  {"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art", "TREZOR", "17b680929853edbbca11eea404ca7f8ff89516dfad1340d517fbb2ebca32382f", "dc81c0485db6150612280dd09cd44622fa65b2ee8aed8f97f0e0bffe8c8c5a54", "FqmSsV7HEX93rzs3pTGAdxhSuvdk1bay6VQQaTPBGuUo"},
  {"legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title", "TREZOR", "6af42a73ad56498592ea7e63d3d58f0e391b6d70c50671b7c22be55dd34b0483", "82317e65801095bf5904f17e2cdef7f05f383c67f9bb1ceab816da00b87633f8", "9mDmr7YZRVci4uNM2qfZvFBkQg8uUuVntmi41DUzasFm"},
  {"letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless", "TREZOR", "0a3b638699f251e35c3eb83d4804dad260080ead003b0e0ccbee3b4d888c1167", "ef0ef8c01a2507bc2452de156600cfbf03e6c4a5fd6861d91292d4ebacb2d8d7", "H6BgVCR9YdccWYdkGR8JNjkAHsK8NPuUEKTQucQopBTt"},
  {"zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote", "TREZOR", "3490ee2da175cb60427a177008bbdf8bcdf822940a3dd7befc45ef199e45c8f7", "77616dc3b87784628bfec7e1a4d866d72bfa7ba853b7d248dd3b0fb82acb961a", "931gb2j6cV5UcK2ZpGF4rt63FCQVq6HHwEYRf8KrPzaV"},
  {"hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length", "TREZOR", "fcf7169c80586fa370dd5a1a53a60aad73711e6ed0cacef7252dd967f6eb177d", "f980efc6b4f152171c3a985e18b6a2720da79bbd8ab7941809c35a444cca517f", "HnxYqfM23feUgMGRfjJR18CLYtvjJRnKCn3Ay2sZ9MDx"},
  {"panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside", "TREZOR", "ebe91f7d30a92243f1212708ff98b19e99b7b0a7ce413ea82554c1e424989412", "3f4058f37db50376a64b4c898418c900d17e77b04798bfc2418e03332fd37ed6", "5FubTqLfdvTmM4se3Xxz3CuaJa4ByRarVn8y1jXjrkAy"},
  {"all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform", "TREZOR", "4a71407a14a87dc30185ae9332d43bd2b1d4d6fe5f336691cfdc1ae5a65526d8", "46f6a53ad9e4affc7c9d230c729fde6d51b5d06f2fb870b566dd11f2cd1e370f", "5n1g4276sag2EfXjxwqRXKBeAxPR8wXfB24LS44L4Laa"},
  {"void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold", "TREZOR", "716c0263d55b633bbff1ff7a51c73158427cbb2979d1fc5a95acf05be8bb8242", "66b098b31e118052c203aaaaef0f7c6026323b4929c9683d1200bc0aec25d4c1", "7urmYYLsvfULp9UDRRVSSxwGCLgKHQuTe1qqQsX2ek1W"},
};

typedef struct { const char* nfd; const char* nfc; const char* seed; } NfkdVector;
static const NfkdVector NFKD_VECTORS[] = {
  {"Spätlese", "Spätlese", "211d35a1a826249aeb55710090dd449ae43da42ada62c2f304a74e1bad225d4bfc1f9f805e1613cf3b04986b34855e3581f4321ce2b8e33a5dc6cc2b5f678368"},
};

typedef struct { const char* transcript; const char* entropy; const char* raw_entropy; const char* fingerprint; const char* mnemonic; const char* address; } VnVector;
static const VnVector VN_VECTOR = {"6116322261665154111225515266654245312643322311413353164514153653526116231214346323326366615625622443665263121343125632644642322655365454322541112626451445453516616536313424166352516365522325515341133212511641522645235542566263466345412213155252116612113152364252655424421164344461666114631222542423421451165112244424124143434665664223215651631154552151215162415255151465553326632342663431145511525323123324563565165361231165233526326635431164311326326456451116251355242133132626135456222241263466232614142243322162433133654653113253115436345514523164155666662341635361635364346352246466255345133245563444625462613566531263222112451446526644422661142265415214246555345654542644326354623416323335122246", "bcf5b0705cb936740347e7562d4dbdb52a1daffcaac168b9810a07f78e3fb523", "04b9a5055f25831e04efde5440442f7823a1b4a57fa396a916e5ad8aaca62261", "45ba6e3ac693a5e7067d45094b1cd46ebe8c97be18584835fb0628dc30f1f8b8", "rude pulse bright ride nature deliver artist woman file heavy hunt heart peace subject verify flag hamster slot dream avocado jump cabin stand ginger", "7QSCMMh1jNiAW8Cqt81A8Wj5PK283k1iJGPu5SMwKV3a"};

#define BIP39_VECTOR_COUNT 8
#define SLIP10_VECTOR_COUNT 3
#define SOLANA_VECTOR_COUNT 8
#define NFKD_VECTOR_COUNT 1