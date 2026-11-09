# EDITH-permission-firewall
Enhanced Digital Identity,Trust &amp; Heuristics - A live permission decision engine for apps and user data


# E.D.I.T.H. — The Permission Firewall
**Enhanced Digital Identity, Trust & Heuristics** · NITSHACKS 9.0 · Software Track · Problem Statement 2

Most permission systems ask once, at install time, and never look again.
E.D.I.T.H. sits **between apps and user data** and judges every request and every upload in real time.

Android and iOS show what apps did. Enterprise tools list risky apps. E.D.I.T.H. **decides live**:
allow, deny, or give a *downgraded* answer (approximate location, dummy contacts), and gives every app
a **context-aware, explainable trust score**.

## How it works
```
App request ──► DATA BROKER ──► Context engine ──► Trust score ──► ALLOW / DOWNGRADE / DENY
                    │                                   │
                    └──── hash-chained audit log ◄──────┘
```
Penalty = `base × permission risk × context` (background use, destination, volume, intent).

## Features implemented in this prototype
| Feature | What it does |
|---|---|
| **Data Broker** | Apps never access data directly; every request goes through the broker |
| **Graceful responses** | Suspicious app gets approximate location / dummy contacts / decoy files and learns nothing real |
| **Adaptive baseline** | Per-app moving average + deviation; spikes flagged by z-score. Baseline is *not* updated during a spike, so an attacker cannot “teach” it |
| **Risk-weighted permissions** | LOCATION 2, FILES 2, CONTACTS 3, CAMERA 3, MIC 3 |
| **Background vs. foreground** | Idle-app access to sensitive data costs extra trust |
| **Data destination tracking** | The broker performs uploads itself, so the logged destination is real, not self-reported. Unknown destination after a sensitive read, and unusual volume, lower trust |
| **Intent check** | Each app declares its purpose; using a permission outside it is a mismatch |
| **Tripwire (canary) data** | A decoy file nobody needs; touching it is an instant critical alert |
| **Explainable score** | Every score change is printed with its reasons and amounts |
| **Recommendations + actions** | Revoke out-of-purpose permissions, block destinations, restrict, approve, suspend |
| **Auto policy** | Trust below 50 automatically downgrades responses and recommends restriction |
| **Tamper-evident audit log** | Each entry stores the hash of the previous one; editing any entry breaks the chain (demo included) |
| **HTML dashboard** | `dashboard.html`: scores, trust-over-time chart, alerts, audit log |

## Roadmap (designed, not built yet)
Auto-expiring permissions · one-time / time-limited grants · risky-combination map · user-defined policy rules · live usage indicator.

## Build & run
Needs only a C++17 compiler (no libraries).
```
g++ -std=c++17 -O2 edith.cpp -o edith
./edith --demo          # automatic scripted demo (about 40 s)
./edith                 # interactive menu
./edith --demo --fast --nocolor   # instant, plain text
```
On Windows with MinGW: `g++ -std=c++17 -O2 edith.cpp -o edith.exe`, then `edith.exe --demo`.
The demo (and menu option 9) writes `dashboard.html`; open it in any browser.

## Demo scenario (matches the problem statement)
1. Three apps (PhotoEdit, FitTrack, NoteSync) behave normally; all trusted.
2. NoteSync turns rogue: requests extra permissions (mic, location), ~5x access rate, runs in the background, reads contacts outside its purpose, touches the tripwire and uploads to an unknown server.
3. Trust drops 100 → 70 → 40 → 10 with reasons shown; responses switch to dummy contacts; alerts fire.
4. E.D.I.T.H. recommends: revoke CONTACTS, block the destination, restrict the app. User applies it.
5. NoteSync is contained and stops losing trust. The audit log verifies; a simulated edit is detected.

## Honest limitations
- This is a **simulation**: apps are simulated, and the “network” and “data” are modelled inside the broker.
- On a real device the same signals would come from the OS / a network proxy (as in iOS App Privacy Report); the prototype's broker plays that role.
- E.D.I.T.H. judges what *leaves* the device (where, when, how much), not what a remote server does with it.
- The audit log uses a 64-bit FNV-1a hash for the prototype; a real deployment would use SHA-256 and signed entries.
- Thresholds and weights are hand-tuned for the demo.
