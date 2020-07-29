# ropgadget-rs

![Github Actions CI](https://github.com/hugsy/rp-rs/workflows/Github%20Actions%20CI/badge.svg)

## Why another ROP gadget finder?

RopGadget-rs is an attempt to learn Rust as a weekend project, to try and get a really fast & easily portable ropgadget finder even (especially!) for large binaries (ntoskrnl, chrome, etc.). As a result it is barely functional, and the code is probably ugly and inefficient.

You've been warned, don't blame me...

## rp-rs

```bash
PS C:\Users\hugsy❯ .\rp-rs.exe --help
rp-rs 0.1
hugsy
Another (bad) ROP gadget finder

USAGE:
    rp-rs.exe [FLAGS] [OPTIONS] <FILE>

ARGS:
    <FILE>    The input file to check

FLAGS:
    -h, --help        Prints help information
        --no-color    Don't colorize the output (only applies for stdout)
    -u, --unique      Show unique gadget only
    -v                Increase verbosity (repeatable from 1 to 4)
    -V, --version     Prints version information

OPTIONS:
        --architecture <arch>                   Target architecture
        --imagebase <image_base>                Use VALUE as image base
    -l, --max-gadget-len <max_gadget_length>    Maximum size of a gadget [default: 16]
        --os <os>                               Target OS
    -o, --output-file <output_file>             Write all gadgets into file
    -t, --nb-threads <thread_num>               The number of threads for processing the binary [default: 2]
```


## Build

If you don't have `cargo`:

```bash
$ curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Then build:

```bash
$ git clone https://github.com/hugsy/rp-rs
$ cd rp-rs
$ cargo build
```

And run:

```bash
$ cargo run -- --help
```


## Perfs

Well yeah, it's pretty fast (thanks Rust) but I'll try to improve here and there as I learn to write better Rust.

For a lame benchmark: here on an old i5-4300M (build in `--release` mode) with 2 threads (default)

 * `ntoskrnl.exe` (Windows 10 RS6 - 10.0.19041.329) - 10,921,280 bytes

```bash
PS C:\Users\hugsy>  .\rp-rs.exe -o rop.txt -vv .\ntoskrnl-rs6.exe
[INFO] - Checking file '.\ntoskrnl-rs6.exe'
[INFO] - Creating new Session(file=.\ntoskrnl-rs6.exe, Info(Arch=x86-64, OS=PE))
[INFO] - Looking for gadgets in 15 sections (with 2 threads)...'
[INFO] - Dumping 336787 gadgets to 'rop.txt'...
[INFO] - Done!
[INFO] - Execution: 336787 gadgets found in 13.5224138s
```

 * `msedge.dll` (Chromium Edge - 83.0.478.64) - 145,665,416 bytes

```bash
PS C:\Users\hugsy> .\rp-rs.exe -o rop.txt -vv .\msedge.dll
[INFO] - Checking file '.\msedge.dll'
[INFO] - Creating new Session(file=.\msedge.dll, Info(Arch=x86-64, OS=PE))
[INFO] - Looking for gadgets in 1 sections (with 2 threads)...'
[INFO] - Dumping 5713703 gadgets to 'rop.txt'...
[INFO] - Done!
[INFO] - Execution: 5713703 gadgets found in 132.2237842s
```

YMMV but most small files (like Unix binaries) will execute in way under 1 second.

```bash
wsl@ph0ny:/mnt/d/Code/rp-rs/target/release$ ./rp-rs -vv -o /dev/null /bin/ls
[INFO] - Checking file '/bin/ls'
[INFO] - Creating new Session(file=/bin/ls, Info(Arch=x86-64, OS=ELF))
[INFO] - Looking for gadgets in 5 sections (with 2 threads)...'
[INFO] - Dumping 3544 gadgets to '/dev/null'...
[INFO] - Done!
[INFO] - Execution: 3544 gadgets found in 151.5587ms
```


## Improvements to come

 * Add sequence of instructions (`call/jmp`, `ret imm`)
 * Handle multiple binaries
 * Generate complete ROP sequence (`execve`, `Virtual{Alloc,Protect}`, that kind)
 * MachO support (maybe)
 * ARM/ARM64 support (maybe)


## Other projects

Unless you're ok with experiencing my bugs, you should probably check out one of those projects:
 - [rp++](https://github.com/0vercl0k/rp)
 - [RopGadget](https://github.com/JonathanSalwan/ROPgadget)
 - [ropper](https://github.com/sashs/ropper)
