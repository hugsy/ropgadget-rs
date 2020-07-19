# ropgadget-rs

## Why another ROP gadget finder?

RopGadget-rs is a project because I had some time to kill, wanted a really fast & easily portable ropgadget finder even (especially!) for large binaries (ntoskrnl, chrome, etc.), and also to learn rust-lang. As a result it is barely functional, and the code is probably ugly and inefficient.

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
    -h, --help       Prints help information
    -u, --unique     Unique only
    -V, --version    Prints version information

OPTIONS:
        --arch <arch>                Target architecture [default: x64]
        --os <os>                    Target OS [default: win]
    -o, --output-file <outfile>      Write all gadgets into file
    -t, --nb-threads <thread_num>    The number of threads for processing the binary [default: 2]
    -v <verbosity>...                Increase verbosity (repeatable)
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

Well yeah, it's pretty fast (thanks Rust) but I'll try to improve here and there.

For a lame benchmark: here on an old i5-4300M

 * `ntoskrnl.exe` (Windows 10 RS6 - 10.0.19041.329) - 10,921,280 bytes
```bash
PS C:\Users\hugsy> cargo run -- --nb-threads 4 D:\Temp\ntoskrnl-rs6.exe
Checking file 'D:\Temp\ntoskrnl-rs6.exe'
looking for executables s in PE: 'D:\Temp\ntoskrnl-rs6.exe'
[...]
[INIT] 2360 gadget(s) found
A total of 50488 gadgets were found
Execution time: 22.503228s
```

 * `msedge.dll` (Chromium Edge - 83.0.478.64) - 145,665,416 bytes
```bash
PS C:\Users\hugsy> cargo run -- --nb-threads 4 D:\Temp\msedge.dll
Checking file 'D:\Temp\msedge.dll'
looking for executables s in PE: 'D:\Temp\msedge.dll`
[...]
[.text] 679074 gadget(s) found
A total of 679074 gadgets were found
Execution time: 364.6681895s
```

YMMV


## Other projects

Unless you're ok with experiencing my bugs, you should probably check out one of those projects:
 - [rp++](https://github.com/0vercl0k/rp)
 - [RopGadget](https://github.com/JonathanSalwan/ROPgadget)
 - [ropper](https://github.com/sashs/ropper)
