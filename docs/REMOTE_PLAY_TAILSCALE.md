# Remote Play over Tailscale

This guide lets friends on other PCs play on your emulator over Tailscale. One PC, the host, runs the server. Each friend runs the one-click launcher in remote mode and connects to the host inside the tailnet. Every PC needs a full PH v1.0.0.24 client with the emulator folder inside its game root, the same layout the one-click launcher always needs.

Not yet confirmed on a real two-PC run: the lobby and matches over Tailscale, and a host playing on its own server PC. Record what you see.

## 1. Install Tailscale on every PC

Install Tailscale on the host and on every friend's PC, and join all of them to one tailnet.

## 2. Find the host's address

On the host:

```powershell
tailscale ip -4
```

It prints one address in `100.64.0.0/10`. This guide uses `100.64.1.2` as an example only. Use your own output everywhere the example appears.

The address stays the same for that device. If it ever changes, set `AF_PUBLIC_HOST` again (step 4) and send friends the new address.

## 3. Open the host firewall to the tailnet only

Friends need these ports on the host:

| Port | Protocol | Service |
|---|---|---|
| 9060 | TCP | VERSION |
| 8000 | TCP | AUTH |
| 9010 | TCP | DIR |
| 65005 | TCP | ROLE |
| 65006 | TCP | ZONE |
| 65008-65011 | UDP | match bridge, one port per room |

The UDP range runs from `AF_DS_PUBLIC_PORT_BASE` (65008) to `AF_DS_PUBLIC_PORT_BASE` + `AF_DS_MAX_INSTANCES` (4) - 1. If you change either setting, change the rule to match.

In PowerShell as Administrator on the host, add two rules that accept Tailscale addresses only:

```powershell
New-NetFirewallRule -DisplayName "AFPH friends TCP" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 9060,8000,9010,65005,65006 -RemoteAddress 100.64.0.0/10
New-NetFirewallRule -DisplayName "AFPH friends UDP" -Direction Inbound -Action Allow -Protocol UDP -LocalPort 65008-65011 -RemoteAddress 100.64.0.0/10
```

Do not open any other port:

- 65007 is a diagnostic port that is never sent to clients.
- 7777 and up (UDP) is the local match server. Friends reach it only through the bridge on 65008-65011.
- 8080 is the account page. It listens on 127.0.0.1 only.

Tailscale already connects the PCs, so never port-forward these ports on your router.

The first time the server runs, Windows may ask to allow `python.exe` and then create an inbound rule for it on every port and every address. Open Windows Defender Firewall with Advanced Security, find the inbound rules for `python.exe`, and delete them or set their remote address to `100.64.0.0/10`.

## 4. Start the server on the host

Open PowerShell as Administrator in the emulator folder. Set `AF_PUBLIC_HOST` in that same window: a value set in a normal window does not reach the elevated launcher. Set `AF_ACCOUNT_DB` to a path outside the emulator folder, so account data never ends up in a copy or commit of that folder.

```powershell
$env:AF_PUBLIC_HOST="100.64.1.2"
$env:AF_ACCOUNT_DB="D:\AFPH-data\assaultfire_accounts.sqlite3"
.\START_ASSAULT_FIRE.ps1
```

The launcher maps the game's server names on the host to `100.64.1.2` too, so the host's own game uses the same address as friends. A good start shows:

```text
[OK] Windows hosts mappings already point to 100.64.1.2.
[PREFLIGHT] game launch gate         : UNLOCKED
```

A host that does not play runs the server without the launcher, after the README's manual setup, in the same Administrator window:

```powershell
.\.venv\Scripts\python.exe .\server\assaultfire_server_v143b.py --server-only
```

## 5. Send the public key and its hash

On the host, read the SHA256 of the public key file:

```powershell
Get-FileHash <game root>\TCLS\config\APClient.dat -Algorithm SHA256
```

A host that runs `--server-only` without a game client uses `generated\APClient.dat` in the emulator folder, the public key that pairs with `server\PRIVATE.PEM`.

Send each friend that `APClient.dat` file and the 64-character `Hash` value.

**Never copy PRIVATE.PEM** to anyone. It is the server's private key. A friend's PC needs `APClient.dat` only.

## 6. Create each friend's account

The account page listens on 127.0.0.1 only, so friends cannot register from their own PC. On the host, open the register page (normally `http://127.0.0.1:8080/register`, or the `[WEB] Registration` URL in the server window) and create a username and password for each friend. Send each friend their login privately.

## 7. Connect from a friend's PC

The friend copies the host's file to `<game root>\TCLS\config\APClient.dat`, replacing the one there. Then they open PowerShell as Administrator in the emulator folder and run, with the host's address and hash:

```powershell
.\START_ASSAULT_FIRE.ps1 -RemoteHost 100.64.1.2 -ApClientSha256 <hash>
```

The launcher maps the game's server names to the host, checks that the file's SHA256 equals the hash, and starts no server on that PC. Success looks like this:

```text
[PREFLIGHT] PASS - remote client checks succeeded; supported game launch helpers are UNLOCKED.
[OK] Remote launch gate is UNLOCKED. No local server runs on this PC. The game connects to the host at 100.64.1.2.
```

The client then opens, and they log in with the account the host made for them.

## 8. Stay inside the tailnet

Connect each friend's PC to the host's own `100.x` address directly inside the tailnet, not through a subnet router or exit node. The server binds each login ticket to one client address, and a subnet router that rewrites addresses can break that.

Game traffic uses old, weak encryption. Keep it inside the tailnet and never expose these ports to the internet.

## 9. Troubleshooting by stage

The client reaches the host in this order: VERSION, AUTH, DIR, ROLE, ZONE, then the match. Find the last `[STAGE] Connected` line from the friend's `100.x` address in the host's server window (or `server\af_server_live.log`), then check the next stage below. [Launcher Errors](LAUNCHER_ERRORS.md) explains each popup in more detail.

| Stage | What you see | Usual cause |
|---|---|---|
| Launcher | `-RemoteHost must be an IPv4 address` or `-ApClientSha256 is required with -RemoteHost` | The address or hash is missing or mistyped. |
| Launcher | `APClient.dat SHA256 does not match the host's (--apclient-sha256)` | Wrong hash, or the friend's `APClient.dat` is not the host's file. Copy the file again and recheck the hash. |
| VERSION | The client cannot connect. No `[VERSION] Connected` from the friend on the host. | TCP firewall rule missing, Tailscale off on either PC, or the friend's hosts mapping still points to 127.0.0.1 (run the launcher with `-RemoteHost`). |
| AUTH | `[VERSION] Connected` but no `[AUTH] Connected`, or an RSA error on the host | Port 8000 missing from the TCP rule, or the host's key changed after the hash was sent. Send the new file and hash. |
| DIR | `[AUTH] Connected` but no `[DIR] Connected`, or `Get Game Server Info fail!` | Port 9010 missing from the TCP rule. |
| ROLE | `[DIR] Connected` but no `[ROLE] Connected`, or `Network is disconnected:Connection Closed!` | `AF_PUBLIC_HOST` not set in the host's Administrator window, so the server sends 127.0.0.1. Port 65005 missing. Running through a subnet router. |
| ZONE | `[ROLE] Connected` but no `[ZONE] Connected` | Port 65006 missing, or `AF_PUBLIC_HOST` not set. |
| Match | A room starts but the match never connects | UDP rule for 65008-65011 missing, or `AF_PUBLIC_HOST` not set. |
