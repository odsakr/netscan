# NetScan

NetScan - a lightweight command-line TCP/UDP local network scanner for
Windows Vista through 11 (x86/x64), without Npcap/WinPcap and without
administrator privileges.

Written in C, cross-compiled with mingw-w64 from Linux with static linking —
no administrator rights, no third-party drivers (Npcap/WinPcap), and no
extra `.dll` files needed on the target machine.

Full documentation: [HELP.txt](HELP.txt)

## Features at a glance

- Multi-threaded TCP and UDP scanning, in parallel or sequentially
- A genuinely asynchronous `fast` mode (hundreds/thousands of concurrent
  checks per thread via async connect + select, no fake multi-threading)
- Live-host discovery via ICMP **and** ARP at once (`--discover`) — finds
  devices even when ICMP is disabled on them
- Protocol-specific UDP probes (DNS/NTP/SNMP) instead of an empty packet,
  since most services silently ignore malformed probes
- Low-cost device fingerprinting, one request per host rather than per port
  (`--info`): MAC + vendor from an OUI database, OS guess from TTL, device
  type from open-port patterns, NetBIOS, mDNS, LLMNR, SNMP sysDescr
- Deeper hostname resolution (`--deep-resolve`): reverse DNS and an
  unauthenticated SMB2/NTLMSSP handshake (works both in a workgroup and
  in an AD domain)
- Flexible output: append mode with timestamps, simultaneous sort-by-IP
  and sort-by-port result files

## Quick start

```
netscan_x64.exe --ip 192.168.1.1-192.168.1.254 --ports 22,80,443,445,3389 ^
                 --proto all --mode fast --threads 50 --batch 32 ^
                 --discover --info --out result.txt
```

Prebuilt binaries (x64 and x86) are in [`releases/`](releases/).
Build it yourself:

```
x86_64-w64-mingw32-gcc -O2 -D_WIN32_WINNT=0x0600 scanner.c -o netscan_x64.exe \
    -lws2_32 -liphlpapi -lwininet -static -static-libgcc

i686-w64-mingw32-gcc -O2 -D_WIN32_WINNT=0x0600 scanner.c -o netscan_x86.exe \
    -lws2_32 -liphlpapi -lwininet -static -static-libgcc
```

## Why not just use nmap?

Nmap is great, but this project scratches a specific itch: no scan progress
display, and it's fairly heavy for quick everyday checks. NetScan aims to be
small, fast to reach for, and self-sufficient — no bundled driver, no admin
prompt, just an .exe you can drop anywhere.

## Requirements & compatibility

- Windows Vista, 7, 8, 8.1, 10, 11 — separate x86 and x64 builds
- No administrator rights required for scanning or for `--info`/`--deep-resolve`
- No third-party drivers required or installed
- Statically linked — no extra DLLs needed on the target machine
- A true raw-socket SYN scan (like masscan) is not possible without
  Npcap/WinPcap — Windows has blocked arbitrary raw TCP header injection
  at the kernel level since XP SP2. `--mode fast` is therefore a
  high-concurrency async connect() scan, not a literal SYN flood.

## TODO

See the TODO section at the end of [HELP.txt](HELP.txt) — it covers the
planned WMI-based diagnostics layer (exact OS version/build, CPU cores,
RAM, logged-in user) and remote configuration via DCOM/WinRM.

## License

Not decided yet.
