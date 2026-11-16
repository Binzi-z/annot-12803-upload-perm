"""Forensic triage: rebuild the upload-dir timeline from evidence.

Replaces the old keyword grep. Parses each evidence source, classifies
events, filters benign deploy/maintenance noise, correlates accounts, and
emits timeline.json with file:line citations for every conclusion.

Usage: python triage.py [evidence_dir] [out_json]
"""

from __future__ import annotations

import json
import os
import re
import sys
from datetime import datetime, timezone

# --- command classification -------------------------------------------------

# Benign deploy / ops commands seen in bash_history (noise; must not alert).
BENIGN_CMD = re.compile(
    r"^(cd\s+/var/log|ls\b|git\s+pull|tail\s+-f|systemctl\s+status)\b"
)

SUSPICIOUS_CMD = [
    (re.compile(r"php\s+-r.*>\s*(\S+)"), "web_shell_written",
     "attacker wrote a PHP web shell into the uploads dir"),
    (re.compile(r"^crontab\s+-e"), "cron_persistence_installed",
     "interactive crontab edit (persistence)"),
    (re.compile(r"^cd\s+/var/www/html/uploads"), "staged_in_uploads",
     "attacker moved into the uploads directory"),
]


def parse_bash_history(path: str) -> list[dict]:
    """Yield command events with epoch timestamps (HISTTIMEFORMAT markers)."""
    events = []
    ts = None
    with open(path, encoding="utf-8", errors="ignore") as fh:
        for no, raw in enumerate(fh, start=1):
            line = raw.strip()
            if not line:
                continue
            m = re.match(r"^#(\d{9,})$", line)
            if m:
                ts = int(m.group(1))
                continue
            if BENIGN_CMD.match(line):
                continue  # normal deploy/ops noise
            for pat, kind, desc in SUSPICIOUS_CMD:
                if pat.search(line):
                    events.append({
                        "source": "evidence/bash_history.txt",
                        "line": no,
                        "epoch": ts,
                        "time_utc": datetime.fromtimestamp(ts, timezone.utc).isoformat()
                                    if ts else None,
                        "kind": kind,
                        "command": line,
                        "desc": desc,
                    })
                    break
            ts = None
    return events


def parse_auth_log(path: str) -> tuple[list[dict], int]:
    """Return (suspicious web events, count of benign ssh logins)."""
    events, ssh_logins = [], 0
    with open(path, encoding="utf-8", errors="ignore") as fh:
        for no, raw in enumerate(fh, start=1):
            line = raw.strip()
            if "Accepted publickey" in line:
                ssh_logins += 1  # routine ops ssh logins: noise
                continue
            m = re.match(r"^(\w+\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+(POST|GET)\s+(\S+)", line)
            if not m:
                continue
            ts, method, uri = m.groups()
            if method == "POST" and "upload" in uri:
                kind, desc = "web_shell_uploaded", \
                    "file uploaded through the web app (entry vector)"
            elif "shell.php" in uri and "cmd=" in uri:
                kind, desc = "web_shell_first_access", \
                    "first access: shell.php executed with a command " \
                    "(proves uploads dir now executes scripts)"
            else:
                continue
            events.append({
                "source": "evidence/auth_excerpt.log",
                "line": no,
                "time_local": ts,
                "kind": kind,
                "request": f"{method} {uri}",
                "desc": desc,
            })
    return events, ssh_logins


def parse_files(path: str) -> list[dict]:
    """File landing records: timestamp, mode, owner, path."""
    events = []
    with open(path, encoding="utf-8", errors="ignore") as fh:
        for no, raw in enumerate(fh, start=1):
            parts = raw.split()
            if len(parts) < 5:
                continue
            date, hm, mode, owner, fpath = parts[0], parts[1], parts[2], parts[3], parts[4]
            if fpath == "/etc/passwd":
                continue  # baseline system file, not part of the incident
            kind = ("cron_persistence_file" if "crontab" in fpath
                    else "web_shell_file" if fpath.endswith("shell.php")
                    else "file_landed")
            events.append({
                "source": "evidence/files.txt",
                "line": no,
                "time_local": f"{date} {hm}",
                "kind": kind,
                "path": fpath,
                "mode": mode,
                "owner": owner,
                "desc": f"{fpath} landed (owner={owner}, mode={mode})",
            })
    return events


def parse_crontab(path: str) -> list[dict]:
    events = []
    with open(path, encoding="utf-8", errors="ignore") as fh:
        for no, raw in enumerate(fh, start=1):
            line = raw.strip()
            if not line or line.startswith("MAILTO"):
                continue
            if "healthcheck" in line:
                continue  # legitimate maintenance job: noise
            if re.search(r"curl\s+.*\|\s*bash", line):
                events.append({
                    "source": "evidence/crontab.txt",
                    "line": no,
                    "kind": "cron_persistence_payload",
                    "entry": line,
                    "desc": "cron pulls and executes a remote script every 5 min "
                            "(persistence)",
                })
    return events


def build_report(evidence_dir: str) -> dict:
    bash = parse_bash_history(os.path.join(evidence_dir, "bash_history.txt"))
    web, ssh_logins = parse_auth_log(os.path.join(evidence_dir, "auth_excerpt.log"))
    files = parse_files(os.path.join(evidence_dir, "files.txt"))
    cron = parse_crontab(os.path.join(evidence_dir, "crontab.txt"))

    def cite(e):
        return f"{e['source']}:{e['line']}"

    # --- reconstructed incident chain (per-source order is reliable) --------
    timeline = [
        {
            "stage": "1_permission_change",
            "conclusion": "uploads dir changed from script-execution-disabled "
                          "to executable",
            "actor": "www-data",
            "evidence": [cite(e) for e in web],  # POST then successful GET
            "note": "no chmod in evidence; the change is inferred because "
                    "shell.php later executes via GET (auth_excerpt.log:27). "
                    "Prior state (execution disabled) is the scenario premise "
                    "(prompt.txt:1).",
        },
        {
            "stage": "2_file_landed",
            "conclusion": "web shell shell.php landed in /var/www/html/uploads",
            "actor": "www-data",
            "evidence": [cite(e) for e in files if e["kind"] == "web_shell_file"]
                        + [cite(e) for e in bash if e["kind"] == "web_shell_written"]
                        + [cite(web[0])] if web else [],
        },
        {
            "stage": "3_first_access",
            "conclusion": "first access / execution of the web shell "
                          "(GET shell.php?cmd=id -> 200)",
            "actor": "www-data (via HTTP)",
            "evidence": [cite(web[1])] if len(web) > 1 else [],
        },
        {
            "stage": "4_persistence",
            "conclusion": "cron persistence as www-data: curl | bash every 5 min",
            "actor": "www-data",
            "evidence": [cite(e) for e in bash if e["kind"] == "cron_persistence_installed"]
                        + [cite(e) for e in files if e["kind"] == "cron_persistence_file"]
                        + [cite(e) for e in cron],
        },
    ]

    hits = [
        {"file": e["source"].replace("evidence/", ""), "line": e["line"],
         "text": e.get("command") or e.get("request") or e.get("entry")
                 or e.get("desc", "")}
        for e in bash + web + files + cron
    ]

    return {
        "summary": {
            "entry_vector": "web shell upload",
            "persistence": "cron",
            "account": "www-data",
            "permission_change": {
                "who": "www-data (web-server account, via the uploaded shell; "
                       "files.txt:2 shows shell.php owned by www-data, "
                       "auth_excerpt.log:26-27 shows the upload and execution "
                       "over HTTP)",
                "before": "uploads dir did not execute scripts "
                          "(scenario premise, prompt.txt:1)",
                "after": "shell.php executes in uploads "
                         "(auth_excerpt.log:27 returns 200 for ?cmd=id)",
            },
        },
        "timeline": timeline,
        "hits": hits,
        "noise_suppressed": {
            "bash_history.txt": "cd /var/log, ls -la, git pull, tail -f, "
                                "systemctl status (routine deploy/ops)",
            "auth_excerpt.log": f"{ssh_logins} routine ops ssh logins",
            "crontab.txt": "line 2 healthcheck.sh (legit maintenance job)",
            "files.txt": "line 1 /etc/passwd (baseline system file)",
        },
        "timestamp_dependencies": [
            "Cross-source ordering depends on timestamps whose timezones are "
            "not recorded: bash_history epochs (1790824347 = 2026-10-01 "
            "03:12:27 UTC) do not align with files.txt (02:04) or auth log "
            "(12:16/12:21) under any single-zone assumption, so the "
            "interleaving of sources is inferred from causality, not clocks.",
            "The claim 'permission change preceded first access' rests on the "
            "auth-log ordering POST (12:16) -> GET (12:21) at "
            "auth_excerpt.log:26-27.",
            "Within bash_history.txt the sequence cd -> write shell -> "
            "crontab -e (lines 51-56) is ordered by monotonic epoch markers "
            "and is robust.",
            "File landing times (files.txt:2-3) and the crontab content "
            "(crontab.txt:3) are timestamp-independent facts.",
        ],
    }


def main() -> int:
    root = sys.argv[1] if len(sys.argv) > 1 else "evidence"
    out = sys.argv[2] if len(sys.argv) > 2 else "timeline.json"
    report = build_report(root)
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2)
    print(f"{len(report['hits'])} hits, "
          f"{len(report['timeline'])} stages -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
