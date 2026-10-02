# Building the EKA1 (7.0s / S80v2) version on Linux

This is how `ssladaptor.dll` for the Nokia 9300 was built without Windows, with
[GnuPoc](https://github.com/mstorsjo/gnupoc-package) and the S60 2nd Edition FP1 SDK.

## What you need

- `S60_SDK_2_1_NET.zip` (S60 2nd Edition FP1 SDK, Symbian 7.0s)
- `gcc-539-2aeh-source.tar.bz2` (Symbian GCC 2.9-psion-98r2)
- gnupoc-package (`git clone https://github.com/mstorsjo/gnupoc-package`)
- packages: `build-essential flex bison libncurses-dev zlib1g-dev cabextract perl`
- bearssl-symbian checked out next to this repository as `../bearssl`

## Toolchain

```sh
cd gnupoc-package/tools
# a modern host GCC needs these flags to build the 1998-era compiler
CC="gcc -std=gnu89 -fcommon -w -fpermissive" CFLAGS="-g" \
  ./install_gcc_539 gcc-539-2aeh-source.tar.bz2 ~/sym/gcc539
```

If it stops at `collect2` with "undefined reference to sys_siglist" (removed from glibc),
patch the source it unpacked and continue in `obj`:

```sh
sed -i 's/sys_siglist\[\([^]]*\)\]/strsignal(\1)/g' src/gcc/collect2.c
cd obj && make all-gcc && make install-binutils install-gas install-ld install-gcc
cd .. && cp arm-specs ~/sym/gcc539/lib/gcc-lib/arm-epoc-pe/2.9-psion-98r2/specs
```

Native EKA1 tools (petran, rcomp, ...): `./install_eka1_tools ~/sym/gcc539`
(bmconv needs `(foundPath > 0)` changed to `(foundPath != 0)` in `bmconv-1.1.0-2/src/pbmcomp.cpp`).

## SDK

```sh
cd gnupoc-package/sdks
./install_gnupoc_s60_21 S60_SDK_2_1_NET.zip ~/sym/s60_21
./install_wrapper ~/sym/wrap        # then set EKA1TOOLS=~/sym/gcc539/bin in ~/sym/wrap/gnupoc-common.sh
```

The SDK's perl scripts use `defined(%hash)` / `defined(@array)`, which modern perl rejects.
Replace them with `%hash` / `@array` in `epoc32/tools/*.pm, *.pl` (e.g. `e32plat.pm` line 273
becomes `if (%{$Plat{$ASSP}}) {`).

## Build

```sh
export EPOCROOT=~/sym/s60_21/ PATH=~/sym/wrap:$PATH
cd ../bearssl/group && bldmake bldfiles && abld build armi urel
cd -  # this repository
cd group && bldmake bldfiles && abld build armi urel ssladaptor
# -> $EPOCROOT/epoc32/release/armi/urel/ssladaptor.dll  (copy to C:\System\Libs on the phone)
```

With logging to `C:\Logs\SSL\SSLLog.txt` (only written if that folder exists):
add `MACRO SSL_LOG` to `group/ssladaptor.mmp`, then `abld reallyclean armi urel ssladaptor`
and build again.

EKA1 DLLs may not have writable static data ("Dll has initialised data" from petran):
the stub certificate is `const`, and bearssl's `x509_minimal_full.c` must not use a
`static` array of pointers.

## What this fork changes (EKA1, found with the log on a Nokia 9300)

- **Java SNI**: the MIDP `HttpsConnection` never sets `KSoSSLDomainName`. When no host name
  is set, the handshake is deferred until the first `Send`; the host name is taken from
  the HTTP request's `Host:` header and used for SNI. Optional fallback:
  `C:\System\Data\ssl_sni.txt` with lines `<IPv4> <host name>`.
- **Recv/RecvOneOrMore** replace the descriptor's contents (like `RSocket`). Before, a
  reused full buffer (Java reads 512 bytes at a time) got 0 bytes, reported as `KErrEof`
  ("Unexpected end of stream").
- **close_notify** is reported as `KErrEof` instead of error -1.
- A second `Send` during the deferred handshake is queued; closing cancels the raw
  socket I/O so no request completes on a deleted object.
- `SSL_LOG` build option: plain-file logging, incl. the peer address and every `SetOpt`.
