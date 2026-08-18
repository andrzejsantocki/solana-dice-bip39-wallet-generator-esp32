#!/bin/bash
set -e
cd "$(dirname "$0")/.."
ROOT=$(pwd)
INC="-Ilib/wallet_core -Ilib/bip39 -Ilib/ed25519 -Ilib/utf8proc -Itests/host_test"
mkdir -p .tmp/obj

# Portable toolchain detection: local w64devkit (author Windows machine) or
# system gcc/g++ (CI ubuntu runner).
if [ -x "$ROOT/.tmp/w64devkit/w64devkit/bin/gcc" ]; then
  export PATH="$ROOT/.tmp/w64devkit/w64devkit/bin:$PATH"
  GCC="$ROOT/.tmp/w64devkit/w64devkit/bin/gcc"
  GXX="$ROOT/.tmp/w64devkit/w64devkit/bin/g++"
  EXE=".exe"
else
  GCC="${GCC:-gcc}"
  GXX="${GXX:-g++}"
  EXE=""
fi

# Optional sanitizer flags (CI sets SANFLAGS="-fsanitize=address,undefined").
SANFLAGS="${SANFLAGS:-}"

$GCC $SANFLAGS -O2 -c lib/ed25519/add_scalar.c -o .tmp/obj/add_scalar.o
$GCC $SANFLAGS -O2 -c lib/ed25519/fe.c        -o .tmp/obj/fe.o
$GCC $SANFLAGS -O2 -c lib/ed25519/ge.c        -o .tmp/obj/ge.o
$GCC $SANFLAGS -O2 -c lib/ed25519/keypair.c   -o .tmp/obj/keypair.o
$GCC $SANFLAGS -O2 -c lib/ed25519/sc.c        -o .tmp/obj/sc.o
$GCC $SANFLAGS -O2 -c lib/ed25519/seed.c      -o .tmp/obj/seed.o
$GCC $SANFLAGS -O2 -c lib/ed25519/sha512.c    -o .tmp/obj/ed_sha512.o
$GCC $SANFLAGS -O2 -c lib/ed25519/sign.c      -o .tmp/obj/sign.o
$GCC $SANFLAGS -O2 -DUTF8PROC_STATIC -c lib/utf8proc/utf8proc.c -o .tmp/obj/utf8proc.o
$GCC $SANFLAGS -O2 -c tests/host_test/sha256.c -o .tmp/obj/sha256.o

$GXX $SANFLAGS -O2 -std=c++17 -DUTF8PROC_STATIC $INC -c lib/wallet_core/wallet_core.cpp -o .tmp/obj/wallet_core.o
$GXX $SANFLAGS -O2 -std=c++17 $INC -c tests/host_test/wc_platform_host.cpp -o .tmp/obj/wc_platform_host.o
$GXX $SANFLAGS -O2 -std=c++17 $INC -c tests/host_test/main.cpp -o .tmp/obj/main.o

$GXX $SANFLAGS -o "tests/host_test/host_test$EXE" .tmp/obj/*.o
echo "BUILD OK -> tests/host_test/host_test$EXE"
