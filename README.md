<p align="center">
  <img src="https://i.imgur.com/zjcxyVf.png" alt="logo" width="250px"/>
</p>

# `ropgadget-rs`

<p align="center">
    <a href="https://discord.gg/hSbqxxBgRX"><img alt="Discord" src="https://img.shields.io/badge/Discord-BlahCats-yellow"></a>
    <a href="https://github.com/hugsy/ropgadget-rs/actions/workflows/build.yml"><img src="https://github.com/hugsy/ropgadget-rs/actions/workflows/build.yml/badge.svg?branch=main"/></a>
</p>


RopGadget-rs started as a weekend project to learn [Rust](https://www.rust-lang.org/). But as usual it also started from the need to get really fast & easily portable ropgadget finder capable of handling quickly any binary (especially very large ones such as mshtml, ntoskrnl, chrome, etc.).

> [!NOTE]
> This library is a side project to learn Rust. If you want better tools, see the ones mentioned at the bottom of the page. 

Currently supports:

|       |  ELF   |  PE   |    MachO  |
| :---: | :----: |:-----:|:---------:|
|  x86  |   ✅   |   ✅   |   ✅   |
|  x64  |   ✅   |   ✅   |   ✅   |
|  arm  |   ✅   |   ✅   |   ❌   |
| arm64 |   ✅   |   ✅   |   ❌   |


## `ropgadget-rs`

Since 0.4, RopGadget-Rs was re-designed to be built as a library so it can be integrated to other projects.
But a lightweight standalone binary that features all what the library offers, can also be built.

## Build

(Optionally) If you don't have `cargo`:

 - On Linux/MacOS
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

 - On Windows
```ps1
Invoke-WebRequest https://win.rustup.rs/x86_64 -UseBasicParsing -OutFile "rustup-init.exe"
Invoke-Expression rustup-init.exe
```

Then build:
```bash
git clone https://github.com/hugsy/ropgadget-rs
cd ropgadget-rs
cargo build --release --lib
```

You might also want to build the ropgadget-rs binary so it can be easily used from the command line:
```bash
cargo build --release --example rp-rs
```


And run:
```bash
cargo run -- --help
```


## Install

Via `cargo`

```bash
cargo install --bins --git https://github.com/hugsy/ropgadget-rs.git
```

## Performance

The tool performs decently but could largely be optimized (and will be, over time).
Here are some performance obtained on an old i5-4300M (build in `--release` mode) with 2 threads (default)

 * `ntoskrnl.exe` (Windows 10 RS6 - 10.0.19041.329) - 10,921,280 bytes

```console
>  ./ropgadget-rs.exe -o rop.txt -vv ./ntoskrnl-rs6.exe
[INFO] - Checking file './ntoskrnl-rs6.exe'
[INFO] - Creating new Session(file=./ntoskrnl-rs6.exe, Info(Arch=x86-64, OS=PE))
[INFO] - Looking for gadgets in 15 sections (with 2 threads)...'
[INFO] - Dumping 336787 gadgets to 'rop.txt'...
[INFO] - Done!
[INFO] - Execution: 336787 gadgets found in 13.5224138s
```

 * `msedge.dll` (Chromium Edge - 83.0.478.64) - 145,665,416 bytes

```console
> ./ropgadget-rs -o rop.txt -vv ./msedge.dll
[INFO] - Checking file './msedge.dll'
[INFO] - Creating new Session(file=./msedge.dll, Info(Arch=x86-64, OS=PE))
[INFO] - Looking for gadgets in 1 sections (with 2 threads)...'
[INFO] - Dumping 5713703 gadgets to 'rop.txt'...
[INFO] - Done!
[INFO] - Execution: 5713703 gadgets found in 132.2237842s
```

YMMV but most small files (like Unix binaries) will execute in way under 1 second.

```console
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

