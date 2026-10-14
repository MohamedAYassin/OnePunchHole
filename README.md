# OnePunchHole

**Direct UDP connection between two machines behind NAT.** No rendezvous server, no TURN relay, no libraries — one `.cpp` and one build command.

![C++20](https://img.shields.io/badge/C%2B%2B-20-00599C?logo=cplusplus\&logoColor=white)

![platform](<https://img.shields.io/badge/platform-Windows%20%7C%20Linux-0078D6?logo=windows\&logoColor=white>)

![dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)

![relay](https://img.shields.io/badge/relay-none-blue)

![build](<https://img.shields.io/badge/build-one%20command-success>)
![license](https://img.shields.io/badge/license-MIT-blue)

---

> ### ⚠️ Proof of concept
>
> **This is a PoC, not a product.** It exists to show that two machines behind NAT can find each other and talk directly, in one file, with no server in the middle. That is the entire claim — and note it is only *half* a solution: to make it usable without manual copy-paste, you also need a signalling server (see below).
>
> There is **no warranty of any kind**, express or implied. It is not hardened, not audited, not encrypted, not authenticated. By running it you accept that you are doing so **entirely at your own risk** and that you are **solely responsible** for anything that follows — including but not limited to: the traffic you send, the port mappings it writes to your router, the firewall state it creates, any network policy or terms of service you break, and any data that leaks because the link has no confidentiality.
>
> **No liability is accepted** for damage, data loss, banned accounts, blocked ports, disciplinary action, or anything else arising from its use or misuse. Do whatever you want with it — fork it, gut it, sell it, ignore it — but understand that you are the operator, and the consequences are yours.
>
> If you need any of the following, **this is the wrong tool**: confidentiality, authentication, reliability, IPv6, automatic peer discovery without manual endpoint swapping, or support for users behind a carrier-grade NAT. Use a real overlay or a real relay.

---

`OnePunchHole` asks Google's public STUN servers what your `ip:port` looks like from the outside. You and your peer paste those endpoints at each other, both sides punch a hole through their own NAT, and you talk directly. Nothing in the middle ever sees your traffic.

## Build

| Platform | Command                                                                        |
| :------- | :----------------------------------------------------------------------------- |
| Windows  | `g++ -O2 -std=c++20 -static -o OnePunchHole.exe OnePunchHole.cpp -lws2_32`   |
| Linux    | `g++ -O2 -std=c++20 -pthread -static -o OnePunchHole OnePunchHole_linux.cpp` |

`-static` gets you one self-contained file. On Linux, `-pthread` is required.

## Use

```bash
./OnePunchHole stun  [port] [hosts...]            # print your public endpoint, then exit
./OnePunchHole check [port] [hosts...]            # can your NAT be punched?
./OnePunchHole punch [ip:port] [port] [hosts...]  # punch through, then chat
```

Two people, two different networks:

1. **Both** run `./OnePunchHole punch 50000`. The bare port binds a **fixed local port**, so your NAT mapping stays put and is predictable. Use the same number on both sides.
2. Each side prints a `reflex` endpoint. **Swap them.**
3. Paste your peer's endpoint at the prompt. Both sides print `HOLE PUNCHED` and you can type. `quit` exits, and the other side is told.

> This manual "swap them" step is the part a **signalling server** would automate — see [To actually complete this](#to-actually-complete-this-you-need-a-signalling-server).

Skip the prompt by passing the peer up front:

```bash
./OnePunchHole punch 203.0.113.7:41222 50000
```

## How it works

- **STUN (RFC 5389)** — a binding request to `stun.l.google.com:3478` reveals the endpoint your NAT assigned you. The packet is built by hand; no third-party library.
- **One socket, start to finish** — discovery, printing and punching share a single socket, so the reflex you print *is* the port you punch from. Nothing gets reopened, nothing drifts.
- **Punching** — both sides fire `PUNCH n` every 250 ms. The first packet each way opens both NATs; after that it settles to `KEEP n` once a second.
- **UPnP IGD / NAT-PMP** — given a fixed port, `OnePunchHole` also asks your router for an endpoint-independent mapping. That fixes symmetric NAT with no relay involved.
- **Disconnects are visible** — a clean `quit` sends `BYE`, so the peer knows instantly. A crash or a dropped link is caught after 5 s of silence.

## When it won't work

### What the code tries, in order

Punching is not one attempt — it's a chain. Each rung is tried only if the one before it fails, and the whole chain runs on **one** socket so the port never drifts.

| Order | What it does                                                                 | Succeeds when                                                                                                                                                      |
| :---- | :--------------------------------------------------------------------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1     | **Bind the fixed port** (`udp_sock`)                                 | The port you asked for is free. If taken, it warns and falls back to a random port — **which breaks the plan, because the peer can no longer predict you.** |
| 2     | **UPnP IGD** (`upnp_map`) — SSDP discovery, then `AddPortMapping` | The router speaks UPnP and hasn't disabled it. Requests a permanent lease.                                                                                         |
| 3     | **NAT-PMP** (`natpmp_map`) — probes 4 common gateways on UDP 5351   | UPnP failed or is off, but the router is a NAT-PMP device (most Apple and many consumer routers).                                                                  |
| 4     | **STUN discovery** (`stun_query` → `discover`)                    | Outbound UDP to port 3478 reaches a STUN server, which reports the endpoint your NAT assigned you. Tries all five servers in rotation.                             |
| 5     | **Punching** — `PUNCH n` every 250 ms                               | Both sides are sending at the same time and the NATs are endpoint-independent.                                                                                     |
| 6     | **Keepalive** — `KEEP n` every 1 s                                  | Only reached once connected; this is what holds the mapping open and what the 5 s disconnect timeout watches.                                                      |

### Where it stops

| Situation                                                               | Result                                                                                                                               |
| :---------------------------------------------------------------------- | :----------------------------------------------------------------------------------------------------------------------------------- |
| Both peers share one public IP (same router, or same carrier-grade NAT) | **Cannot work.** Both get the same reflex endpoint; there is no distinct mapping for each side to open.                        |
| Symmetric NAT, and steps 2–3 both failed                               | **Cannot work.** Each destination gets a different external port, so the endpoint you publish is already stale. Needs a relay. |
| Fixed port already in use                                               | Degrades to a random port and the peer's endpoint is unpredictable.                                                                  |
| No outbound UDP to 3478, or DNS blocked                                 | `STUN failed - no mapping`. Nothing else can run.                                                                                  |
| Antivirus or a host firewall blocks the binary                          | Never gets off the ground.                                                                                                           |
| Router reboots, or drops the mapping mid-session                        | Punches, then `peer disconnected (no packets)` after 5 s.                                                                          |

### The fallbacks we already use

These are built in and automatic — you do not configure them:

- **PORT_UNAVAILABLE → random port.** If the fixed port is taken, the code says so and continues on an OS-assigned port, rather than failing outright.
- **UPnP → NAT-PMP.** Two different port-mapping protocols are attempted because routers commonly ship with one on and the other off. Whichever answers first wins; if both fail, the punch is tried anyway without a mapping.
- **STUN server rotation.** All five Google servers are tried in turn, and a `resolve` failure on one host is not fatal.
- **Punching without any mapping.** Steps 2–3 are optimisations, not prerequisites. Plenty of home routers need nothing but plain punching.
- **Disconnect detection.** A clean quit sends `BYE` (instant), and a crash or dead link is caught by the 5 s silence timeout.

### If none of that is enough

The code cannot go further on its own. Beyond it:

1. **Port-forward manually.** If you control the router, forward the fixed UDP port to your machine by hand. This is exactly what UPnP/NAT-PMP would have done, minus the automation — it fixes symmetric NAT completely.
2. **Get on the same LAN.** If both peers can reach one network, skip NAT entirely.
3. **Use a real relay.** A TURN server (`coturn`) or a mesh VPN like WireGuard or Tailscale will connect peers that can never punch. That is a different program, deliberately — this one's whole point is having no server.
4. **Accept that it's the wrong tool.** For anything you actually depend on, use something with encryption, authentication and a fallback path designed in. This PoC has none of those on purpose.

### To actually complete this: you need a signalling server

**This is the missing piece, and it is the honest caveat on the whole PoC.** Hole punching is only half the problem. The other half is exchanging endpoints before the punch can start — and this program does that by **hand**.

Right now the flow is: both peers run the tool, read their reflex endpoint off the terminal, and **copy-paste it to each other out of band** (Discord, SMS, a phone call). That works with two people who are already talking. It does not scale, it does not survive one side needing to reconnect, and it cannot support more than two peers.

A signalling server is the standard answer. It is a small always-on service that both peers connect to at startup, which simply:

1. accepts each peer's registration and learns its public endpoint (it can even learn it from the connection itself, so the peer doesn't need to run STUN at all),
2. relays each peer's endpoint to the other,
3. then steps out of the way once the direct path is open.

**Crucially, it stays out of the data path.** Signalling is tiny control traffic — a few hundred bytes at startup. The actual conversation still goes peer-to-peer, which is the whole point: the server learns your endpoints but never sees your messages. Adding one does not turn this into a relay.

What you would need to build to close the gap:

- A tiny TCP or WebSocket server holding a map of `peer_id -> last known endpoint`, plus a room/join concept for pairing two peers.
- A registration step in `main` — connect, announce yourself, receive the peer's endpoint, then fall through into the existing punch loop unchanged. The punching code needs **no modification**; it only needs `peer` populated from the socket instead of from `argv` or `stdin`.
- Optionally, a keepalive to the server so it always has a fresh endpoint to hand out.

Until that exists, treat `OnePunchHole` as a **bisection of the problem** — it proves the hard half. If you decide to build the signalling server, that is a genuinely different piece of software, and it should authenticate peers properly, because an unauthenticated signalling server hands out endpoints to anyone who asks.

The built-in `BYE` and 5 s timeout already assume a peer that may vanish without warning, which is exactly the failure mode signalling has to handle — so the client side is ready for it.

## Requirements

- The two peers must be behind **different public IPs**. Two machines on one router, or behind a shared carrier-grade NAT, can't punch — there's no per-peer mapping to open.
- Your NAT must be **endpoint-independent** (most home routers). A symmetric NAT needs the UPnP/NAT-PMP mapping, or a TURN relay.
- Outbound UDP to port 3478 must be allowed — that's the default on Windows and Debian.

## Troubleshooting

| Symptom                             | What it means                                     |
| :---------------------------------- | :------------------------------------------------ |
| `STUN query failed`               | No outbound UDP to 3478, or DNS is blocked.       |
| `STUN failed - no mapping`        | STUN is unreachable from this network.            |
| Never prints `HOLE PUNCHED`       | Symmetric NAT, or both peers share one public IP. |
| Punches, then `peer disconnected` | The peer quit, crashed, or the path died.         |

Run `./OnePunchHole check` first — it tells you whether punching can work at all, before you go to the trouble of swapping endpoints.

## Notes

- IPv4 only.
- **No encryption or authentication.** Anyone who learns the 4-tuple can inject packets. Use it on networks you trust, or wrap it.
- The Windows build often trips antivirus. The filename, the UPnP port-mapping and the stdin-to-remote relay pattern all read as RAT-like to heuristics. It's a false positive — exclude the folder.

## Files

| File                       |                                                      |
| :------------------------- | :--------------------------------------------------- |
| `OnePunchHole.cpp`       | Windows build — Winsock, 312 lines                  |
| `OnePunchHole_linux.cpp` | Linux build — POSIX sockets, 317 lines              |
| `ANALYSIS.md`            | Line-by-line memory and correctness review           |
| `up.original.cpp`        | The pre-cleanup original (kept as `up`), 381 lines |
| `LICENSE`                | MIT                                                  |

Both builds speak the same wire protocol, so a Windows peer and a Linux peer punch to each other unchanged.

## License

**MIT.** Do whatever you want with it — use it, modify it, ship it, sell it, relicense it. The only condition is that the copyright notice stays in the source.

The licence also carries the **no-warranty / no-liability** clause, which is the legal form of the [PoC warning above](#-proof-of-concept): the software is provided "as is", and the author is not liable for anything it does. See [`LICENSE`](LICENSE) for the exact text.
