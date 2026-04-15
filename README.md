# Auto-OVPN-Fetcher-V2 - Multi-Source OVPN Config Fetcher

Fetches free OpenVPN configs from four sources and saves them as `.ovpn` files ready to use with `openvpn`.

All sources use **datacenter exit nodes** — none provide residential IPs. For residential-leaning nodes use the companion [`ovpn`](https://github.com/Krainium/Auto-OVPN-Fetcher) tool which pulls from VPNGate (volunteer home connections included).

---

## Sources

| # | Name | Method | Auth to connect |
|---|------|--------|-----------------|
| 1 | **VPNBook** | Real REST | username `vpnbook`, weekly rotating password |
| 2 | **VPNJantit** | Config ZIP | Free account (7-day TTL) at vpnjantit.com |
| 3 | **FreeOpenVPN** | GitHub mirror | Varies per config (embedded or none) |
| 4 | **IPSpeed** | GitHub mirror | Varies per config (embedded or none) |

---
## Run directly
```
go run ovpn2.go
```

## Build

```sh
go build -o ovpn2

```
Requires Go 1.21+. No external dependencies.

---

## Run

```sh
./ovpn2
```

Interactive menu — enter a number and press Enter.

---

## Menu options

```
[1]  VPNBook       — fetches all servers × 4 protocols (TCP/443, TCP/80, UDP/53, UDP/25000)
[2]  VPNJantit     — scrapes 18 country pages, downloads config ZIPs, extracts .ovpn files
[3]  FreeOpenVPN   — pulls FOV_ configs from Zoult GitHub mirror across 20 countries
[4]  IPSpeed       — pulls IPS_ configs from Zoult GitHub mirror across 20 countries
[5]  All sources   — runs all four in sequence, accumulates everything in memory

[6]  List current results        — print the table of loaded configs
[7]  Save current results        — save all loaded configs to a directory
[8]  Save split by source        — save configs into per-source subfolders
[9]  Filter by country keyword   — search loaded configs by country name
[0]  Quit
```

---

## Connecting

Install OpenVPN Connect for your platform:

- **Windows / Linux / macOS / iOS / Android / Chrome OS** — [OpenVPN Connect](https://openvpn.net/client/)
  - Windows: once installed, double-click any `.ovpn` file and it will be automatically imported
  - iOS / Android: tap the `.ovpn` file and open it with OpenVPN Connect
  - Linux (CLI): `sudo apt install openvpn` / `sudo pacman -S openvpn`

**All sources — same command (Linux/macOS CLI):**
```sh
sudo openvpn --config path/to/config.ovpn
```

VPNBook configs have the username and password embedded directly inside the `.ovpn` file using the OpenVPN inline credentials block (`<auth-user-pass>`), so no separate auth file is needed.

The VPNBook password rotates weekly. If your config stops authenticating, re-run option `[1]` or `[5]` to fetch fresh configs with the current password embedded, or check https://www.vpnbook.com/freevpn manually.

**VPNJantit accounts:**

VPNJantit configs require a free account to authenticate. Create one (valid 7 days, renewable) at:
https://www.vpnjantit.com/create-free-account

---

## Notes

- VPNBook servers are scraped live from the website; the known list is also compiled in as a fallback.
- VPNJantit configs include a ZIP with both TCP and UDP variants where available.
- The Zoult mirror (`github.com/Zoult/.ovpn`) is a community-maintained snapshot — configs may be older.
- None of these services provide residential IPs; all are datacenter exit points.

