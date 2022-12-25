# ropgadget-rs

[![CI Build](https://github.com/hugsy/ropgadget-rs/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/hugsy/ropgadget-rs/actions/workflows/build.yml)

## Why another ROP gadget finder?

RopGadget-rs is an attempt to learn Rust as a weekend project, to try and get a really fast & easily portable ropgadget finder even (especially!) for large binaries (ntoskrnl, chrome, etc.). As a result it is barely functional, and the code is probably ugly and inefficient.

You've been warned, don't blame me...

Currently supports:

|      | ELF | PE | Mach  |
|:-----:|:---:|:--:|:----:|
| x86   | ✅ | ✅ | ❌   |
| x64   | ✅ | ✅ | ✅   |
| arm   | ✅ | ✅ | ❌   |
| arm64 | ✅ | ✅ | ❌   |


## ropgadget-rs

```text
❯ .\ropgadget-rs.exe --help
Another (bad) ROP gadget finder

Usage: rp-rs.exe [OPTIONS] <FILE>

Arguments:
  <FILE>
          The file to parse

Options:
  -t, --number-of-threads <THREAD_NUM>
          The number of threads to use

          [default: 2]

  -o, --output-file <OUTPUT>
          Write gadget to file (optional)

  -v, --verbose...
          The verbosity level

  -u, --unique
          Unique gadgets

      --architecture <ARCHITECTURE>
          Force the architecture to given value

          [possible values: x86, x64, arm, arm64]

      --format <FORMAT>
          Force the OS to given value

          [possible values: pe, elf, mach]

  -i, --image-base <IMAGE_BASE>
          Specify an image base

          [default: 0]

      --no-color
          Disable colors

      --max-insn-per-gadget <MAX_INSN_PER_GADGET>
          The maximum number of instructions in a gadget

          [default: 6]

      --max-size <MAX_SIZE>
          The maximum size of the gadget

          [default: 32]

      --rop-types <ROP_TYPES>
          The type of gadgets to focus on (default - return only)

          [possible values: jump, call, ret, int, iret, privileged]

      --profile-type <PROFILE_TYPE>
          The profile type (default - fast)

          [default: fast]

          Possible values:
          - fast:     Strategy Fast
          - complete: Strategy Complete

  -h, --help
          Print help information (use `-h` for a summary)

  -V, --version
          Print version information
```


## Build

If you don't have `cargo`:

 - On Linux/MacOS
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

 - On Windows
```bash
Invoke-WebRequest https://win.rustup.rs/x86_64 -UseBasicParsing -OutFile "rustup-init.exe"
Invoke-Expression rustup-init.exe
```

Then build:

```bash
git clone https://github.com/hugsy/ropgadget-rs
cd ropgadget-rs
cargo build
```

And run:

```bash
cargo run -- --help
```


## Install

Via `cargo`:

```bash
$ cargo install --bins --git https://github.com/hugsy/ropgadget-rs.git
```

## Perfs

Well yeah, it's pretty fast (thanks Rust) but I'll try to improve here and there as I learn to write better Rust.

For a lame benchmark: here on an old i5-4300M (build in `--release` mode) with 2 threads (default)

 * `ntoskrnl.exe` (Windows 10 RS6 - 10.0.19041.329) - 10,921,280 bytes

```bash
PS C:\Users\hugsy>  .\ropgadget-rs.exe -o rop.txt -vv .\ntoskrnl-rs6.exe
[INFO] - Checking file '.\ntoskrnl-rs6.exe'
[INFO] - Creating new Session(file=.\ntoskrnl-rs6.exe, Info(Arch=x86-64, OS=PE))
[INFO] - Looking for gadgets in 15 sections (with 2 threads)...'
[INFO] - Dumping 336787 gadgets to 'rop.txt'...
[INFO] - Done!
[INFO] - Execution: 336787 gadgets found in 13.5224138s
```

 * `msedge.dll` (Chromium Edge - 83.0.478.64) - 145,665,416 bytes

```bash
PS C:\Users\hugsy> .\ropgadget-rs.exe -o rop.txt -vv .\msedge.dll
[INFO] - Checking file '.\msedge.dll'
[INFO] - Creating new Session(file=.\msedge.dll, Info(Arch=x86-64, OS=PE))
[INFO] - Looking for gadgets in 1 sections (with 2 threads)...'
[INFO] - Dumping 5713703 gadgets to 'rop.txt'...
[INFO] - Done!
[INFO] - Execution: 5713703 gadgets found in 132.2237842s
```

YMMV but most small files (like Unix binaries) will execute in way under 1 second.

```text
$ ./ropgadget-rs -vv -o /dev/null /bin/ls
[INFO] - Checking file '/bin/ls'
[INFO] - Creating new Session(file=/bin/ls, Info(Arch=x86-64, OS=ELF))
[INFO] - Looking for gadgets in 5 sections (with 2 threads)...'
[INFO] - Dumping 3544 gadgets to '/dev/null'...
[INFO] - Done!
[INFO] - Execution: 3544 gadgets found in 151.5587ms
```


## Better projects

Unless you're ok with experiencing my bugs, you should probably check out one of those projects:
 - [rp++](https://github.com/0vercl0k/rp)
 - [ropper](https://github.com/sashs/ropper)
 - [RopGadget](https://github.com/JonathanSalwan/ROPgadget)

