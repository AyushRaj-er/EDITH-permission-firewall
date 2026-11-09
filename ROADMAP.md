# E.D.I.T.H. Roadmap: Planned Features

The hackathon prototype (`edith.cpp`) implements the core Permission Firewall: Data Broker, graceful
responses, adaptive baseline, risk-weighted permissions, background/foreground and destination signals,
intent check, tripwire data, explainable scores, recommendations, hash-chained audit log and an HTML dashboard.

The features below were **designed but not built** because of the 24-hour time limit.
Each one fits the existing architecture (Data Broker → context engine → trust score → decision).

## Summary

| # | Feature | Priority | Effort | Where it plugs in |
|---|---|---|---|---|
| 1 | Auto-expiring permissions | High | Low | `App` struct + `endTick()` |
| 2 | One-time and time-limited grants | High | Low | `handleRequest()` + approve action |
| 3 | User-defined policy rules | High | Medium | rules list checked in `endTick()` |
| 4 | Risky-combination map | Medium | Medium | `recommendations()` + dashboard |
| 5 | Live usage indicator | Medium | Low | dashboard / terminal output |
| 6 | Publisher reputation | Medium | Low | initial trust in `initApps()` |
| 7 | Per-app activity timeline | Medium | Low | dashboard |
| 8 | Slow-leak and total-volume tracking | Medium | Medium | `handleSend()` |
| 9 | Persistent storage (SQLite) | Medium | Medium | log, alerts, baselines |
| 10 | SHA-256 signed audit log | Medium | Low | `fnv()` replacement |
| 11 | Real data sources (OS / proxy) | Long term | High | replaces the simulator |
| 12 | Learned scoring weights | Long term | High | scoring constants |

## 1. Auto-expiring permissions
**Problem:** permissions granted once stay forever, even if the app stops needing them.
**Idea:** track when each granted permission was last used legitimately. If it is unused for N ticks, move it to
"expired" and ask the user again on next use. Android already auto-resets unused permissions; E.D.I.T.H. adds
trust-aware timing (a low-trust app expires sooner).
**How:** add `lastUsedTick[NRES]` to `App`; in `endTick()` expire permissions where `T - lastUsedTick > limit`
(limit shorter when trust is lower); log the expiry in the audit chain.
**Done when:** an unused CAMERA grant disappears from the dashboard after the limit and is logged.

## 2. One-time and time-limited grants
**Problem:** "Allow" is permanent. Users want "only this time" or "for 1 hour".
**Idea:** approving an app offers three grant types: always, until a time, or once.
**How:** replace `bool granted[]` with a grant struct `{type, expiresAtTick, usesLeft}`; `handleRequest()` checks
and decrements it. Works together with feature 1.
**Done when:** a "once" grant allows exactly one request, then the next request is denied and logged.

## 3. User-defined policy rules
**Problem:** the only automatic rule is "trust below 50 → downgrade responses".
**Idea:** a small rules table such as
- `IF trust < 50 THEN restrict + notify`
- `IF app touches tripwire THEN suspend immediately`
- `IF upload to unknown destination AND trust < 80 THEN deny`

**How:** a `Rule {condition, action}` list evaluated once per tick; conditions read score, status and recent
alerts; actions reuse the existing restrict, suspend and block functions. Every automatic action is written to the audit log.
**Done when:** rules can be added from the menu and fire without a click.

## 4. Risky-combination map
**Problem:** location + contacts + microphone in one app is far riskier than each permission alone.
**Idea:** an apps × resources grid, with dangerous combinations highlighted and added to the recommendations.
**How:** define a list of risky sets (e.g. {LOCATION, CONTACTS, MIC}); in `recommendations()` flag any app whose
granted set contains one and whose declared purpose does not justify it; render the grid in `dashboard.html`.
**Done when:** the dashboard shows the grid and flags the app with a plain-English reason.

## 5. Live usage indicator
**Problem:** users cannot see sensor use as it happens.
**Idea:** like the green/orange dots on phones: a live indicator that lights up whenever an app uses camera, microphone or location.
**How:** terminal: print a coloured tag in the live feed; dashboard: a status row refreshed from the log.
**Done when:** each camera, microphone or location access is visibly marked in real time.

## 6. Publisher reputation
**Idea:** each app has a "verified publisher" flag or reputation score that sets its starting trust. Unknown publishers start in Watch.
**How:** add `reputation` to `App`; use it for initial `score` and for how fast trust recovers.

## 7. Per-app activity timeline
**Idea:** a 24-hour timeline per app showing accesses, uploads and alerts, easier to read than a log table.
**How:** group `logv` by app and time bucket in `exportHtml()`; draw bars on a canvas.

## 8. Slow-leak and total-volume tracking
**Problem:** a rogue app can leak small amounts over a long time to avoid volume spikes.
**Idea:** track cumulative data sent per app per destination over a sliding window and compare it with the baseline.
**How:** add `sentKbWindow` per destination; flag when the total exceeds a multiple of the learned normal.

## 9. Persistent storage
**Idea:** keep apps, baselines, alerts and the audit chain in SQLite so state survives restarts.
**How:** write on every event; load on start; verify the chain at startup.

## 10. SHA-256 signed audit log
**Problem:** the prototype uses a 64-bit FNV-1a hash, which detects accidental edits but is not cryptographically secure.
**Idea:** SHA-256 chaining plus a periodic signature (e.g. HMAC with a key held outside the app).
**How:** swap `fnv()` for a SHA-256 implementation; sign every Nth entry.

## 11. Real data sources
**Problem:** the prototype simulates apps, data and network inside the broker.
**Idea:** feed the same engine from real signals:
- **Android:** app-ops / permission usage logs and per-app network stats.
- **Desktop:** a local proxy that sees outgoing connections per process.
- **Enterprise:** OAuth app and audit logs from cloud suites.

**How:** keep `handleRequest()` and `handleSend()` as the interface; write adapters that convert real events into those calls.
**Limit:** E.D.I.T.H. can judge what leaves a device (where, when, how much), not what a remote server does with the data.

## 12. Learned scoring weights
**Idea:** the penalty weights are hand-tuned. With real data, tune them (or learn them) to reduce false alarms, and report precision and recall.
**How:** collect labelled normal and malicious traces from the simulator and real logs; evaluate before changing any weight.

## Known limitations of the current prototype
- Simulation only: no real apps, devices or network traffic.
- Thresholds and weights are hand-tuned for the demo.
- State is in memory; it is lost when the program exits.
- Audit log hash is not cryptographically strong (see item 10).
