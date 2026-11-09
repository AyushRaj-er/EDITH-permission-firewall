// =====================================================================
//  E.D.I.T.H. - Enhanced Digital Identity, Trust & Heuristics
//  "The Permission Firewall"  -  NITSHACKS 9.0 prototype (C++17)
//
//  Simulates 3 apps that access user data. EVERY request and every
//  outgoing upload goes through the Data Broker, which decides to
//  ALLOW, DENY or DOWNGRADE it and updates a context-aware trust score.
//
//  Build:  g++ -std=c++17 -O2 edith.cpp -o edith
//  Run  :  ./edith            (interactive menu)
//          ./edith --demo     (automatic demo for the video)
//          ./edith --demo --fast --nocolor   (no delays / no colours)
//  Output: dashboard.html is written by menu option 9 / at end of demo.
// =====================================================================
#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <random>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
#ifdef _WIN32
#include <windows.h>
#endif
using namespace std;

// ----------------------------- resources -----------------------------
enum Res { LOCATION, CONTACTS, CAMERA, MIC, FILES, NRES };
static const char* RN[NRES] = {"LOCATION", "CONTACTS", "CAMERA", "MICROPHONE", "FILES"};
// Risk weight per permission (feature: risk-weighted permissions)
static const int RISK[NRES] = {2, 3, 3, 3, 2};

// ----------------------------- terminal ------------------------------
static string R, G, Y, B, D, X;  // red, green, yellow, bold, dim, reset
static bool FAST = false;
static void setColors(bool on) {
    if (!on) { R = G = Y = B = D = X = ""; return; }
    R = "\033[31;1m"; G = "\033[32;1m"; Y = "\033[33;1m";
    B = "\033[1m"; D = "\033[2m"; X = "\033[0m";
}
static void pauseMs(int ms) { if (!FAST) Sleep(ms); }

// ----------------------------- data model ----------------------------
struct Reason { string text; int amount = 0; int count = 0; };
struct Alert { int tick; string app; string severity; string text; };
struct LogEntry {
    int idx; int tick; string app; string event; string detail;
    string prevHash; string hash;
};

struct App {
    string name, purposeText;
    bool purpose[NRES] = {false};   // what the app DECLARED it needs (intent check)
    bool granted[NRES] = {false};   // what the user granted
    set<string> known;              // known-good destinations (learned / declared)
    set<string> blocked;            // destinations blocked by the user
    set<string> unknownSeen;        // unknown destinations it tried
    set<int> outsidePurpose;        // resources used outside declared purpose
    double score = 100;
    bool restricted = false, suspended = false, rogue = false;
    // adaptive baseline (exponential moving average + variance)
    double mean = 2, var = 1, kbMean = 10;
    int ticksSeen = 0, tickCount = 0;
    int lastReadRes = -1, lastReadTick = -100;
    bool belowPolicy = false, tripAlerted = false;
    vector<Reason> pending;
    vector<double> history;
};

static vector<App> apps;
static vector<Alert> alerts;
static vector<LogEntry> logv;
static int T = 0;                     // simulation clock (ticks)
static mt19937 rng(42);               // fixed seed -> repeatable demo
static string tamperBackup; static int tamperIdx = -1;

// ----------------------------- audit log -----------------------------
// Hash-chained log: each entry stores the hash of the previous one, so
// editing any past entry breaks every hash after it.
// (FNV-1a 64-bit used for the prototype; SHA-256 in production.)
static string fnv(const string& s) {
    uint64_t h = 1469598103934665603ULL;
    for (unsigned char c : s) { h ^= c; h *= 1099511628211ULL; }
    stringstream ss; ss << hex << setw(16) << setfill('0') << h; return ss.str();
}
static string entryHash(const LogEntry& e) {
    return fnv(e.prevHash + "|" + to_string(e.idx) + "|" + to_string(e.tick) + "|" +
               e.app + "|" + e.event + "|" + e.detail);
}
static void logEvent(const string& app, const string& event, const string& detail) {
    LogEntry e; e.idx = (int)logv.size(); e.tick = T; e.app = app; e.event = event; e.detail = detail;
    e.prevHash = logv.empty() ? string(16, '0') : logv.back().hash;
    e.hash = entryHash(e);
    logv.push_back(e);
}
// returns -1 if chain is intact, otherwise index of first broken entry
static int verifyChain() {
    string prev(16, '0');
    for (auto& e : logv) {
        if (e.prevHash != prev || e.hash != entryHash(e)) return e.idx;
        prev = e.hash;
    }
    return -1;
}

// ----------------------------- helpers -------------------------------
static string statusOf(const App& a) {
    if (a.suspended) return "SUSPENDED";
    if (a.restricted) return "RESTRICTED";
    if (a.score >= 80) return "TRUSTED";
    if (a.score >= 50) return "WATCH";
    return "SUSPICIOUS";
}
static string statusColor(const string& s) {
    if (s == "TRUSTED") return G;
    if (s == "WATCH") return Y;
    return R;
}
static string f1(double v) { stringstream s; s << fixed << setprecision(1) << v; return s.str(); }
static string f0(double v) { stringstream s; s << fixed << setprecision(0) << v; return s.str(); }

static void raiseAlert(App& a, const string& sev, const string& text, bool verbose) {
    alerts.push_back({T, a.name, sev, text});
    logEvent(a.name, "ALERT", sev + ": " + text);
    if (verbose) cout << "  " << (sev == "CRITICAL" ? R : Y) << "[ALERT-" << sev << "] " << X << a.name << ": " << text << "\n";
}

// queue a penalty; it is applied (and explained) at the end of the tick
static void addPenalty(App& a, const string& text, int amount) {
    for (auto& r : a.pending) if (r.text == text) { r.amount += amount; r.count++; return; }
    a.pending.push_back({text, amount, 1});
}

static void printDecision(const App& a, const string& dec, Res res, bool fg, const string& note) {
    string c = dec == "ALLOW" ? G : (dec == "DOWNGRADE" ? Y : R);
    cout << "  " << D << "t" << setw(3) << T << X << "  " << setw(9) << left << a.name << right << " "
         << setw(10) << left << RN[res] << right << (fg ? " fg " : " bg ") << c << setw(9) << left << dec << right << X
         << " " << D << note << X << "\n";
}

// ------------------------- THE DATA BROKER ---------------------------
// Apps never touch data directly. They call handleRequest() and the
// broker returns ALLOW / DOWNGRADE / DENY.
static string handleRequest(App& a, Res res, bool fg, bool canary, bool verbose) {
    a.tickCount++;
    int r = RISK[res];
    string dec = "ALLOW", note;

    if (a.suspended) {
        dec = "DENY"; note = "app suspended";
    } else if (canary) {
        // TRIPWIRE: decoy file planted by E.D.I.T.H. - no real feature needs it
        dec = "DOWNGRADE"; note = "decoy served - TRIPWIRE touched";
        if (!a.restricted) addPenalty(a, "TRIPWIRE: touched decoy file 'passwords_backup.txt'", 30);
        if (!a.tripAlerted) { a.tripAlerted = true; raiseAlert(a, "CRITICAL", "touched tripwire decoy file (no legitimate reason to read it)", verbose); }
    } else if (a.restricted && (!a.granted[res] || !a.purpose[res] || !fg)) {
        dec = "DENY"; note = fg ? "blocked by restriction" : "background access blocked by restriction";
    } else if (!a.granted[res]) {
        dec = "DENY"; note = "not granted: new permission request, pending user approval";
        addPenalty(a, string("new permission request for ") + RN[res] + " (risk " + to_string(r) + ")", 4 * r);
    } else {
        if (!a.purpose[res]) {
            a.outsidePurpose.insert(res);
            addPenalty(a, string("intent mismatch: declared '") + a.purposeText + "' but used " + RN[res], 3 * r);
        }
        if (!fg && r >= 2)
            addPenalty(a, string("background access to ") + RN[res] + " while app idle", 2 * r);

        if (a.restricted && a.purpose[res]) { dec = "DOWNGRADE"; note = "restricted mode"; }
        if (a.score < 50 && dec == "ALLOW") dec = "DOWNGRADE";
        if (dec == "DOWNGRADE") {
            if (res == LOCATION) note = "approximate location only (city-level)";
            else if (res == CONTACTS) note = "dummy contacts returned";
            else if (res == FILES) note = "empty/decoy file returned";
            else { dec = "DENY"; note = "blank stream, no real data"; }
        }
        if (dec != "DENY") { a.lastReadRes = res; a.lastReadTick = T; }
    }
    logEvent(a.name, "ACCESS", string(RN[res]) + (fg ? " fg " : " bg ") + dec + (note.empty() ? "" : " (" + note + ")"));
    if (verbose) printDecision(a, dec, res, fg, note);
    return dec;
}

// Apps cannot reach the network themselves: the broker performs the send,
// so the destination logged is the REAL one, not what the app claims.
static void handleSend(App& a, const string& dest, int kb, bool verbose) {
    string dec = "ALLOW", note;
    if (a.suspended || a.blocked.count(dest)) {
        dec = "DENY"; note = "destination blocked";
    } else {
        bool known = a.known.count(dest) > 0;
        bool flagged = false;
        if (!known) {
            int lr = (a.lastReadRes >= 0 && T - a.lastReadTick <= 2) ? RISK[a.lastReadRes] : 1;
            string after = (lr > 1) ? string(" right after reading ") + RN[a.lastReadRes] : "";
            a.unknownSeen.insert(dest);
            addPenalty(a, "sent data to unknown destination '" + dest + "'" + after, 8 * lr);
            flagged = true;
            if (a.score < 80 || a.restricted) { dec = "DENY"; note = "unknown destination blocked"; }
            else note = "first-time destination, flagged";
        }
        if (kb > 100 && kb > 8 * a.kbMean) {
            addPenalty(a, "unusual upload volume: " + to_string(kb) + " KB vs normal ~" + f0(a.kbMean) + " KB", 10);
            flagged = true;
        }
        if (!flagged) a.kbMean = 0.8 * a.kbMean + 0.2 * kb;
    }
    logEvent(a.name, "SEND", dest + " " + to_string(kb) + "KB " + dec + (note.empty() ? "" : " (" + note + ")"));
    if (verbose) {
        string c = dec == "ALLOW" ? G : R;
        cout << "  " << D << "t" << setw(3) << T << X << "  " << setw(9) << left << a.name << right << " "
             << setw(10) << left << "UPLOAD" << right << "    " << c << setw(9) << left << dec << right << X
             << " " << D << dest << " " << kb << "KB " << note << X << "\n";
    }
}

// end of tick: adaptive baseline, spike check, apply + explain penalties
static void endTick(App& a, bool verbose) {
    double x = a.tickCount;
    bool spike = false;
    if (a.ticksSeen >= 5 && !a.restricted) {
        double sd = max(sqrt(a.var), 1.0);
        double z = (x - a.mean) / sd;
        if (z > 3.0 && x >= 6) {
            spike = true;
            addPenalty(a, "access spike: " + f0(x) + " requests this tick vs normal ~" + f1(a.mean) + " (z=" + f1(z) + ")",
                       (int)min(30.0, 5 * z));
        }
    }
    // do not let attacker "teach" the baseline: skip update during a spike
    if (!spike) {
        double diff = x - a.mean;
        a.mean += 0.2 * diff;
        a.var = 0.8 * (a.var + 0.2 * diff * diff);
    }
    a.ticksSeen++;

    int sum = 0; for (auto& r : a.pending) sum += r.amount;
    double before = a.score;
    if (sum == 0) {
        a.score = min(100.0, a.score + 1);          // slow recovery on clean behaviour
    } else {
        int total = min(sum, 30);                    // cap per tick
        a.score = max(0.0, a.score - total);
        if (verbose) {
            cout << "  " << R << a.name << " trust " << f0(before) << " -> " << f0(a.score) << X << "  why:\n";
            for (auto& r : a.pending)
                cout << "      " << R << "-" << r.amount << X << "  " << r.text
                     << (r.count > 1 ? " (x" + to_string(r.count) + ")" : "") << "\n";
            if (sum > total) cout << "      " << D << "(capped at -30 per tick)" << X << "\n";
        }
        string why;
        for (auto& r : a.pending) why += "-" + to_string(r.amount) + " " + r.text + "; ";
        logEvent(a.name, "SCORE", f0(before) + "->" + f0(a.score) + " | " + why);
        if (total >= 10) raiseAlert(a, a.score < 50 ? "HIGH" : "MEDIUM",
                                    "trust dropped " + f0(before) + " -> " + f0(a.score), verbose);
    }
    // policy: below 50 -> responses are downgraded automatically
    if (a.score < 50 && !a.belowPolicy) {
        a.belowPolicy = true;
        raiseAlert(a, "HIGH", "POLICY: trust below 50 - responses now downgraded; restriction recommended", verbose);
    }
    if (a.score >= 50) a.belowPolicy = false;
    a.pending.clear();
    a.tickCount = 0;
    a.tripAlerted = false;
    a.history.push_back(a.score);
}

// ----------------------------- simulation ----------------------------
static const char* ROGUE_DEST = "data-harvest.xyz";

static void simulateApp(App& a, bool verbose) {
    vector<Res> mine;
    for (int i = 0; i < NRES; i++) if (a.purpose[i]) mine.push_back((Res)i);
    if (!a.rogue) {
        int n = 1 + rng() % 3;
        for (int i = 0; i < n; i++) handleRequest(a, mine[rng() % mine.size()], true, false, verbose);
        if (T % 3 == 0) handleSend(a, *a.known.begin(), 5 + rng() % 16, verbose);
    } else {
        // ROGUE MODE: asks for more permissions, 5x the usual rate, runs in the
        // background, touches the decoy file and uploads a lot to an unknown server
        static const Res pool[] = {CONTACTS, LOCATION, MIC, CONTACTS, FILES};
        int n = 9 + rng() % 5;
        for (int i = 0; i < n; i++) {
            Res rs = pool[rng() % 5];
            bool canary = (rs == FILES && rng() % 2 == 0);
            handleRequest(a, rs, false, canary, verbose);
        }
        handleSend(a, ROGUE_DEST, 900, verbose);
    }
}

static void tickAll(bool verbose) {
    for (auto& a : apps) { simulateApp(a, verbose); endTick(a, verbose); }
    T++;
}

static void initApps() {
    auto mk = [](const string& n, const string& p, initializer_list<Res> purpose,
                 initializer_list<Res> granted, const string& dest) {
        App a; a.name = n; a.purposeText = p;
        for (Res r : purpose) a.purpose[r] = true;
        for (Res r : granted) a.granted[r] = true;
        a.known.insert(dest); a.history.push_back(100);
        return a;
    };
    apps.push_back(mk("PhotoEdit", "photo editing", {CAMERA, FILES}, {CAMERA, FILES}, "cdn.photoedit.com"));
    apps.push_back(mk("FitTrack", "fitness tracking", {LOCATION, FILES}, {LOCATION, FILES}, "sync.fittrack.io"));
    // NoteSync was granted CONTACTS at install, but its declared purpose is only notes/files
    apps.push_back(mk("NoteSync", "note syncing", {FILES}, {FILES, CONTACTS}, "sync.notesync.com"));
}

// -------------------------- recommendations --------------------------
static vector<string> recommendations(const App& a) {
    vector<string> out;
    for (int r : a.outsidePurpose)
        if (a.granted[r]) out.push_back(string("REVOKE ") + RN[r] + ": granted but outside declared purpose '" + a.purposeText + "' (risk " + to_string(RISK[r]) + ")");
    for (auto& d : a.unknownSeen)
        if (!a.blocked.count(d)) out.push_back("BLOCK destination '" + d + "' (never seen before)");
    if (a.score < 50 && !a.restricted && !a.suspended) out.push_back("RESTRICT app to foreground, declared-purpose access only");
    // unused permissions
    for (int r = 0; r < NRES; r++)
        if (a.granted[r] && !a.purpose[r] && !a.outsidePurpose.count(r))
            out.push_back(string("REVIEW ") + RN[r] + ": granted but not needed for '" + a.purposeText + "'");
    return out;
}

static void applyRecommendations(App& a) {
    for (int r : a.outsidePurpose) a.granted[r] = false;
    for (int r = 0; r < NRES; r++) if (a.granted[r] && !a.purpose[r]) a.granted[r] = false;
    for (auto& d : a.unknownSeen) a.blocked.insert(d);
    a.restricted = true;
    logEvent(a.name, "ACTION", "user applied recommendations: revoked out-of-purpose permissions, blocked destinations, restricted app");
}

// ------------------------------ display ------------------------------
static void printDashboard() {
    cout << "\n" << B << "==================== E.D.I.T.H. DASHBOARD  (tick " << T << ") ====================" << X << "\n";
    cout << left << setw(11) << " APP" << setw(12) << "STATUS" << setw(26) << "TRUST SCORE" << "GRANTED PERMISSIONS\n" << right;
    for (auto& a : apps) {
        string st = statusOf(a);
        int fill = (int)round(a.score / 5.0);
        string bar = "[" + string(fill, '#') + string(20 - fill, '.') + "]";
        string gr;
        for (int r = 0; r < NRES; r++) if (a.granted[r]) gr += string(RN[r]) + " ";
        cout << " " << left << setw(10) << a.name << statusColor(st) << setw(12) << st << X
             << bar << " " << setw(4) << f0(a.score) << right << " " << (gr.empty() ? "(none)" : gr) << "\n";
    }
    cout << B << "------------------------------------------------------------------------" << X << "\n";
}

static void printRecs() {
    bool any = false;
    for (auto& a : apps) {
        auto rec = recommendations(a);
        if (rec.empty() || (a.score >= 80 && !a.rogue && a.outsidePurpose.empty() && a.unknownSeen.empty())) continue;
        any = true;
        cout << "\n " << B << "Recommendations for " << a.name << X << " (trust " << f0(a.score) << ")\n";
        for (auto& s : rec) cout << "   " << Y << "->" << X << " " << s << "\n";
    }
    if (!any) cout << "\n " << G << "No recommendations: all apps behave within their declared purpose." << X << "\n";
}

static void printAlerts(size_t last = 8) {
    cout << "\n " << B << "Recent alerts" << X << "\n";
    if (alerts.empty()) { cout << "   (none)\n"; return; }
    size_t from = alerts.size() > last ? alerts.size() - last : 0;
    for (size_t i = from; i < alerts.size(); i++)
        cout << "   t" << setw(3) << alerts[i].tick << "  " << (alerts[i].severity == "CRITICAL" ? R : Y) << setw(9) << left
             << alerts[i].severity << right << X << " " << alerts[i].app << ": " << alerts[i].text << "\n";
}

static void printVerify() {
    int bad = verifyChain();
    if (bad < 0) cout << "\n " << G << "AUDIT LOG OK" << X << ": " << logv.size() << " entries, hash chain intact.\n";
    else cout << "\n " << R << "AUDIT LOG TAMPERED" << X << ": chain breaks at entry #" << bad << " (" << logv[bad].event << " by " << logv[bad].app << ").\n";
}

// ----------------------------- HTML report ---------------------------
static string esc(const string& s) {
    string o; for (char c : s) { if (c == '&') o += "&amp;"; else if (c == '<') o += "&lt;"; else if (c == '>') o += "&gt;"; else if (c == '"') o += "&quot;"; else o += c; } return o;
}
static void exportHtml(const string& path) {
    ofstream f(path);
    if (!f) { cout << " Could not write " << path << "\n"; return; }
    int bad = verifyChain();
    f << R"HTML(<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>E.D.I.T.H. Dashboard</title><style>
:root{--bg:#f5f5f8;--card:#fff;--ink:#1a1a22;--mut:#6b6b78;--line:#e4e4ea;--red:#d91e2b;--green:#2e9e5b;--amber:#e09a1a}
@media(prefers-color-scheme:dark){:root{--bg:#14141a;--card:#1d1d26;--ink:#f0f0f4;--mut:#9a9aa8;--line:#2e2e3a}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 Segoe UI,Arial,sans-serif;padding:24px 16px}
.w{max-width:1000px;margin:0 auto}h1{margin:0 0 4px;font-size:28px}h2{font-size:15px;letter-spacing:.08em;text-transform:uppercase;color:var(--red);margin:28px 0 10px}
.sub{color:var(--mut);margin-bottom:18px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:12px}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:16px}
.n{font-weight:700;font-size:18px}.big{font-size:40px;font-weight:800}.pill{display:inline-block;padding:2px 10px;border-radius:99px;color:#fff;font-size:12px;font-weight:700}
.bar{height:8px;background:var(--line);border-radius:9px;margin:8px 0}.bar i{display:block;height:100%;border-radius:9px}
table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--mut);font-weight:600}code{font-family:Consolas,monospace;font-size:12px;color:var(--mut)}canvas{width:100%;height:280px}
.ok{color:var(--green);font-weight:700}.bad{color:var(--red);font-weight:700}.sev-CRITICAL,.sev-HIGH{color:var(--red);font-weight:700}.sev-MEDIUM{color:var(--amber);font-weight:700}
.sc{overflow-x:auto}</style></head><body><div class="w">
<h1>E.D.I.T.H. <span style="color:var(--red)">Permission Firewall</span></h1>
<div class="sub">Enhanced Digital Identity, Trust &amp; Heuristics &middot; simulation tick )HTML" << T << R"HTML(</div>
<h2>App trust</h2><div class="grid">)HTML";
    for (auto& a : apps) {
        string st = statusOf(a);
        string col = (st == "TRUSTED") ? "var(--green)" : (st == "WATCH" ? "var(--amber)" : "var(--red)");
        string gr; for (int r = 0; r < NRES; r++) if (a.granted[r]) gr += string(RN[r]) + " ";
        f << "<div class=card><div class=n>" << esc(a.name) << " <span class=pill style='background:" << col << "'>" << st << "</span></div>"
          << "<div class=big style='color:" << col << "'>" << f0(a.score) << "</div><div class=bar><i style='width:" << f0(a.score) << "%;background:" << col << "'></i></div>"
          << "<div style='color:var(--mut);font-size:13px'>Purpose: " << esc(a.purposeText) << "<br>Granted: " << (gr.empty() ? "none" : esc(gr)) << "</div></div>";
    }
    f << "</div><h2>Trust score over time</h2><div class=card><canvas id=c width=940 height=280></canvas><div id=lg style='font-size:13px;margin-top:6px'></div></div>";
    f << "<h2>Recommendations</h2><div class=card>";
    bool any = false;
    for (auto& a : apps) for (auto& s : recommendations(a)) {
        if (a.score >= 80 && a.outsidePurpose.empty() && a.unknownSeen.empty()) continue;
        any = true; f << "<div><b>" << esc(a.name) << "</b>: " << esc(s) << "</div>";
    }
    if (!any) f << "<div class=ok>All apps behave within their declared purpose.</div>";
    f << "</div><h2>Security alerts</h2><div class='card sc'><table><tr><th>Tick</th><th>Severity</th><th>App</th><th>Alert</th></tr>";
    for (auto it = alerts.rbegin(); it != alerts.rend(); ++it)
        f << "<tr><td>" << it->tick << "</td><td class=sev-" << it->severity << ">" << it->severity << "</td><td>" << esc(it->app) << "</td><td>" << esc(it->text) << "</td></tr>";
    if (alerts.empty()) f << "<tr><td colspan=4>No alerts</td></tr>";
    f << "</table></div><h2>Tamper-evident audit log</h2><div class='card sc'><div>";
    if (bad < 0) f << "<span class=ok>Hash chain intact</span> (" << logv.size() << " entries)";
    else f << "<span class=bad>CHAIN BROKEN at entry #" << bad << "</span>";
    f << "</div><table><tr><th>#</th><th>Tick</th><th>App</th><th>Event</th><th>Detail</th><th>Hash</th></tr>";
    size_t from = logv.size() > 120 ? logv.size() - 120 : 0;
    for (size_t i = logv.size(); i-- > from;) {
        auto& e = logv[i];
        f << "<tr><td>" << e.idx << "</td><td>" << e.tick << "</td><td>" << esc(e.app) << "</td><td>" << e.event << "</td><td>" << esc(e.detail) << "</td><td><code>" << e.hash << "</code></td></tr>";
    }
    f << "</table></div></div><script>const D={";
    for (size_t i = 0; i < apps.size(); i++) {
        f << "'" << apps[i].name << "':[";
        for (size_t k = 0; k < apps[i].history.size(); k++) f << (k ? "," : "") << f0(apps[i].history[k]);
        f << "]" << (i + 1 < apps.size() ? "," : "");
    }
    f << R"HTML(};
const cols=['#2b6cb0','#2e9e5b','#d91e2b'];const cv=document.getElementById('c'),x=cv.getContext('2d');
const W=cv.width,H=cv.height,P=34;const st=getComputedStyle(document.body);const mut=st.getPropertyValue('--mut')||'#888';
let n=0;for(const k in D)n=Math.max(n,D[k].length);
function X(i){return P+i*(W-P-10)/Math.max(n-1,1)}function Y(v){return H-P-(v/100)*(H-P-10)}
x.font='12px sans-serif';x.fillStyle=mut;x.strokeStyle='#8884';
for(const v of [0,50,80,100]){x.beginPath();x.moveTo(P,Y(v));x.lineTo(W-10,Y(v));x.setLineDash(v==50||v==80?[5,4]:[]);x.stroke();x.fillText(v,4,Y(v)+4)}
x.setLineDash([]);let j=0,lg='';
for(const k in D){x.strokeStyle=cols[j%3];x.lineWidth=2.5;x.beginPath();D[k].forEach((v,i)=>{i?x.lineTo(X(i),Y(v)):x.moveTo(X(i),Y(v))});x.stroke();
lg+='<span style="color:'+cols[j%3]+';font-weight:700;margin-right:14px">&#9632; '+k+'</span>';j++}
document.getElementById('lg').innerHTML=lg+'<span style="color:var(--mut)">dashed lines: 80 = Trusted, 50 = Suspicious</span>';
</script></body></html>)HTML";
    cout << "\n " << G << "Dashboard written to " << path << X << "  (open it in your browser)\n";
}

// ------------------------------- actions -----------------------------
static void banner() {
    cout << B << R << "\n  E.D.I.T.H." << X << B << "  Enhanced Digital Identity, Trust & Heuristics\n" << X
         << D << "  The Permission Firewall - apps never touch your data directly.\n" << X;
}

static void tamperToggle() {
    if (logv.size() < 5) return;
    if (tamperIdx < 0) {
        tamperIdx = (int)logv.size() / 2;
        tamperBackup = logv[tamperIdx].detail;
        logv[tamperIdx].detail += " [EDITED BY ATTACKER]";
        cout << "\n " << Y << "Simulated attack: log entry #" << tamperIdx << " was edited." << X << "\n";
    } else {
        logv[tamperIdx].detail = tamperBackup; tamperIdx = -1;
        cout << "\n " << G << "Log entry restored." << X << "\n";
    }
}

static int pickApp() {
    cout << " App? "; for (size_t i = 0; i < apps.size(); i++) cout << "[" << i + 1 << "] " << apps[i].name << "  ";
    cout << "\n > ";
    string s; getline(cin, s);
    try { int v = stoi(s); if (v >= 1 && v <= (int)apps.size()) return v - 1; } catch (...) {}
    return -1;
}

static void runDemo() {
    banner();
    cout << "\n " << B << "STEP 1 - Learning phase: 3 apps behave normally" << X << "\n";
    printDashboard(); pauseMs(1800);

    cout << "\n " << B << "STEP 2 - Normal activity (every request passes through the Data Broker)" << X << "\n";
    for (int i = 0; i < 2; i++) { tickAll(true); pauseMs(700); }
    printDashboard(); pauseMs(1800);

    cout << "\n " << B << R << "STEP 3 - NoteSync goes ROGUE" << X << B << ": extra permissions, 5x access rate, background use, unknown upload" << X << "\n";
    apps[2].rogue = true; pauseMs(1200);
    for (int i = 0; i < 3; i++) { cout << "\n"; tickAll(true); pauseMs(1200); }
    printDashboard(); printAlerts(); pauseMs(2000);

    cout << "\n " << B << "STEP 4 - E.D.I.T.H. recommends restrictions" << X;
    printRecs(); pauseMs(2200);

    cout << "\n " << B << "STEP 5 - User clicks APPLY: revoke, block destination, restrict" << X << "\n";
    applyRecommendations(apps[2]); pauseMs(800);
    for (int i = 0; i < 2; i++) { cout << "\n"; tickAll(true); pauseMs(800); }
    printDashboard(); pauseMs(1800);

    cout << "\n " << B << "STEP 6 - Tamper-proof audit log" << X; printVerify(); pauseMs(1200);
    tamperToggle(); printVerify(); pauseMs(1200);
    tamperToggle(); printVerify();
    exportHtml("dashboard.html");
    cout << "\n " << B << "Demo complete." << X << "\n";
}

int main(int argc, char** argv) {
    bool demo = false, color = true;
    for (int i = 1; i < argc; i++) {
        string s = argv[i];
        if (s == "--demo") demo = true; else if (s == "--fast") FAST = true; else if (s == "--nocolor") color = false;
    }
#ifdef _WIN32
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE); DWORD m = 0;
    if (h && GetConsoleMode(h, &m)) SetConsoleMode(h, m | 0x0004); else color = false;
#endif
    setColors(color);
    initApps();
    for (int i = 0; i < 12; i++) tickAll(false);   // silent learning phase: baselines form

    if (demo) { runDemo(); return 0; }

    banner();
    while (true) {
        cout << "\n " << B << "MENU" << X << "\n"
             << "  1) Show dashboard            6) Approve app (restore trust)\n"
             << "  2) Run 1 normal tick         7) Suspend app\n"
             << "  3) Toggle ROGUE mode (app)   8) Verify audit log / simulate tamper\n"
             << "  4) Show recommendations      9) Export dashboard.html\n"
             << "  5) Apply recommendations     a) Show alerts      0) Exit\n > ";
        string c; if (!getline(cin, c)) break;
        if (c == "0") break;
        else if (c == "1") printDashboard();
        else if (c == "2") { cout << "\n"; tickAll(true); printDashboard(); }
        else if (c == "3") { int i = pickApp(); if (i >= 0) { apps[i].rogue = !apps[i].rogue; cout << " " << apps[i].name << " rogue mode " << (apps[i].rogue ? "ON" : "OFF") << "\n"; } }
        else if (c == "4") printRecs();
        else if (c == "5") { int i = pickApp(); if (i >= 0) { applyRecommendations(apps[i]); cout << " Applied to " << apps[i].name << "\n"; } }
        else if (c == "6") { int i = pickApp(); if (i >= 0) { App& a = apps[i]; a.restricted = a.suspended = a.rogue = false; a.score = max(a.score, 75.0); a.pending.clear(); logEvent(a.name, "ACTION", "user approved app, trust reset to 75"); cout << " Approved " << a.name << "\n"; } }
        else if (c == "7") { int i = pickApp(); if (i >= 0) { apps[i].suspended = true; logEvent(apps[i].name, "ACTION", "user suspended app"); cout << " Suspended " << apps[i].name << "\n"; } }
        else if (c == "8") { printVerify(); tamperToggle(); printVerify(); }
        else if (c == "9") exportHtml("dashboard.html");
        else if (c == "a" || c == "A") printAlerts(15);
    }
    return 0;
}
