#!/bin/sh
# Local toolchain only. No installs, package managers, containers or networking.
set -eu
umask 077
export LC_ALL=C SOURCE_DATE_EPOCH=0
compiler=${CC:-cc}
if ! command -v "$compiler" >/dev/null 2>&1; then
  printf '%s\n' 'No local C compiler; build not performed.' >&2
  exit 1
fi
task_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
build_dir=$(mktemp -d "${TMPDIR:-/tmp}/cloudsentinel-connect-peer-build-XXXXXXXX")
trap 'rm -rf -- "$build_dir"' EXIT HUP INT TERM
compile() {
  "$compiler" -std=c11 -O2 -Wall -Wextra -Werror -Wpedantic -Wformat=2 \
    -Wconversion -Wshadow -Wstrict-prototypes -fno-ident -fPIE \
    -fstack-protector-strong -fstack-clash-protection -D_FORTIFY_SOURCE=2 \
    "-ffile-prefix-map=$task_root=." -static-pie \
    -Wl,--build-id=none,-z,noexecstack,-z,relro,-z,now "$1" -o "$2"
}
compile "$task_root/native/connect-peer.c" "$build_dir/connect-peer"
compile "$task_root/native/connect-peer-test.c" "$build_dir/native-unit"
# The unit executable replaces all socket-related syscalls; no live probes.
"$build_dir/native-unit" > "$build_dir/native-tests.log"
chmod 0500 "$build_dir/connect-peer"
(cd "$build_dir" && sha256sum connect-peer > binary.sha256)
sha256sum "$task_root/native/connect-peer.c" > "$build_dir/source.sha256"
"$compiler" --version > "$build_dir/toolchain.txt"
printf '%s\n' 'c11 O2 Wall Wextra Werror Wpedantic Wformat=2 Wconversion Wshadow Wstrict-prototypes fno-ident fPIE fstack-protector-strong fstack-clash-protection FORTIFY_SOURCE=2 ffile-prefix-map static-pie build-id=none noexecstack relro now SOURCE_DATE_EPOCH=0' > "$build_dir/flags.txt"
trap - EXIT HUP INT TERM
printf '%s\n' "$build_dir"
