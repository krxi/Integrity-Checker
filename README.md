# Integrity-Checker

A small Windows user-mode tool that detects runtime patching of a target process by hashing its `.text` (code) section and re-checking it every second.

This is a learning project for anti-tamper / anti-cheat concepts. It is defensive in nature: it only **reads** a target process's memory and does not modify, inject into, or bypass anything.

## How it works

1. Finds the target process (`game.exe`) with `CreateToolhelp32Snapshot` / `Process32First/Next`.
2. Gets the module base address via a module snapshot.
3. Opens the process and reads the PE headers from its memory (DOS header → NT headers → section headers).
4. Locates the `.text` section and computes a baseline CRC32 of it.
5. Every second, reads `.text` again and compares the hash with the baseline.
6. If the hash differs, it shows an alert and terminates the target process.

## Build

Tested with MSYS2 UCRT64 (requires zlib):

```
gcc main.c -o main.exe -lz
```

## Usage

1. Start the target program (by default `game.exe`; change the `file` variable in `main.c`).
2. Run `main.exe`. It prints the base address, size, and baseline hash, then keeps monitoring.

Use it only on programs you own or have permission to test (for example, your own test application).

## Limitations

This is an educational prototype, not a production anti-cheat:

- Runs in user mode with the same privileges as an attacker, so it can be killed, hooked, or bypassed (e.g., by hooking `ReadProcessMemory`).
- Only covers the `.text` section. IAT hooks, data tampering, and code in other sections or modules are not checked.
- CRC32 is not collision-resistant; a cryptographic hash (e.g., SHA-256) would be better.
- Polling every second can miss short-lived patches.
- Limited error handling.

## Ideas for improvement

- Cryptographic hashing and per-page checks to locate which region changed
- Checking other sections, imported modules, and the IAT
- Better error handling and a configurable target/interval
- Running the checker inside the protected process or as a separate, hardened component

## What I learned

PE file structure, the Windows process/module APIs, reading remote process memory, and the basic limits of user-mode integrity checking.

## References

- PE format walkthrough: https://0xrick.github.io/win-internals/pe2/
