"""Shared, local account-store compatibility layer.

This module only handles local account records. It does not authenticate with
or call any game/provider endpoint.
"""
import json, os, tempfile, threading
from pathlib import Path

_LOCK = threading.RLock()
_FIELDS = ("uid", "pass", "name", "region", "open_id", "access_token", "jwt",
           "ingame_id", "game_url", "platform")

def _clean(value):
    if value is None: return ""
    # Legacy accs.txt is pipe-delimited; prevent malformed records.
    return str(value).replace("|", "_").replace("\n", " ").replace("\r", " ")

def load_accounts(path="accs.txt", *, preserve_slots=False):
    """Load accounts; optionally keep each nonblank row as a squad position.

    In slot-preserving mode duplicate UIDs are retained for later validation,
    and an invalid row becomes None. This prevents a bad row from silently
    moving accounts from one fixed four-person squad into another.
    """
    p = Path(path)
    if not p.exists(): return []
    rows, seen = [], set()
    with _LOCK, p.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line: continue
            try:
                if line.startswith("{"):
                    rec = json.loads(line)
                else:
                    parts = line.split("|")
                    if len(parts) < 9:
                        if preserve_slots: rows.append(None)
                        continue
                    rec = dict(zip(_FIELDS, parts + ["4"] * max(0, 10-len(parts))))
                uid = _clean(rec.get("uid"))
                if not uid:
                    if preserve_slots: rows.append(None)
                    continue
                if uid in seen and not preserve_slots: continue
                seen.add(uid)
                rec["uid"] = uid
                rec["ingame_id"] = int(rec.get("ingame_id") or 0)
                rec["platform"] = int(rec.get("platform") or 4)
                rows.append(rec)
            except (ValueError, TypeError, AttributeError, OverflowError, json.JSONDecodeError):
                if preserve_slots: rows.append(None)
    return rows

def append_account(account, path="accs.txt"):
    if not isinstance(account, dict): raise TypeError("account must be a dict")
    uid = _clean(account.get("uid"))
    if not uid: raise ValueError("account uid is required")
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with _LOCK:
        current = load_accounts(path)
        if any(str(x.get("uid")) == uid for x in current):
            raise ValueError("duplicate account uid")
        values = [_clean(account.get(k, 4 if k == "platform" else "")) for k in _FIELDS]
        with p.open("a", encoding="utf-8") as f:
            f.write("|".join(values) + "\n")
            f.flush(); os.fsync(f.fileno())


def update_account(uid, updates, path="accs.txt"):
    """Update one record atomically, preserving all other lines verbatim."""
    p = Path(path)
    with _LOCK:
        lines = p.read_text(encoding="utf-8").splitlines(keepends=True)
        matches = []
        for idx, line in enumerate(lines):
            raw = line.strip()
            if not raw: continue
            try:
                if raw.startswith('{'):
                    record = json.loads(raw)
                else:
                    parts = raw.split('|')
                    if len(parts) < 9: continue
                    record = dict(zip(_FIELDS, parts + ['4'] * max(0, 10-len(parts))))
                if str(record.get('uid', '')) == str(uid): matches.append((idx, record))
            except (ValueError, TypeError, json.JSONDecodeError):
                continue
        if len(matches) != 1: raise ValueError("account uid missing or duplicated")
        idx, record = matches[0]
        record.update({k: v for k, v in updates.items() if k in _FIELDS and k != 'uid'})
        lines[idx] = '|'.join(_clean(record.get(k, 4 if k == 'platform' else '')) for k in _FIELDS) + '\n'
        fd, temp_name = tempfile.mkstemp(prefix='.accs-', dir=str(p.parent), text=True)
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                f.writelines(lines); f.flush(); os.fsync(f.fileno())
            os.replace(temp_name, p)
        finally:
            if os.path.exists(temp_name): os.unlink(temp_name)
