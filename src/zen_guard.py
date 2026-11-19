"""Watches OpenCode's log for quota walls and rotates the active egress."""

from __future__ import annotations

import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Ensure local script and bundled directories are resolvable
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))
_SCRIPTS = Path(os.environ.get("LOCALAPPDATA", "")) / "opencode-unlimited" / "scripts"
if _SCRIPTS.is_dir() and str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

from ouc_common import (
    GUARD_LOG_FILE,
    GUARD_STATE_FILE,
    OPENCODE_LOG_FILE,
    acquire_mutex,
    append_log,
    ensure_dirs,
    find_warp_cli,
    get_egress_v6,
    get_warp_local_v6,
    hop_once,
    keeper_pause_ctx,
    normalize_v6_64,
)

POLL_SECONDS = 10
COOLDOWN_SECONDS = 75
MAX_HOP_TRIES = 4
BLACKLIST_MAX = 200
MAX_READ_BYTES = 4_000_000
# Loop protection: if the limit comes back this soon after a new IP, that IP
# didn't help. The pause is short because WARP's /64 blocks are shared and the
# next one is often fine.
REWALL_SECONDS = 180
FAILED_HOPS_MAX = 2
BACKOFF_SECONDS = 2 * 60
# A hop that could not be confirmed is not worth retrying every cooldown:
# each attempt reconnects WARP and cuts live streams.
ROTATION_RETRY_SECONDS = 10 * 60
# Confirmed new IPv6 addresses that still hit the free wall mean the allowance
# is not following the IP. Stop rotating until it resets at 00:00 UTC.
FREE_WALL_HOPS_MAX = 2
HEARTBEAT_FILE = GUARD_LOG_FILE.parent / "heartbeat.txt"
PENDING_MAX_AGE = 30 * 60


def _heartbeat() -> None:
    """Cheap liveness signal the app checks; a running but hung guard stops writing this."""
    try:
        HEARTBEAT_FILE.write_text(str(int(time.time())), encoding="utf-8")
    except Exception:
        pass


def _default_state(offset: int = 0) -> dict:
    return {
        "blacklist": [],
        "offset": offset,
        "last_hop": 0,
        "hops": 0,
        "current": "",
        "wall_pending": False,
        "wall_seen": 0,
        "last_ok_hop": 0,
        "last_wait_log": 0,
        "pending": {},
        "resumed": {},
        "failed_hops": 0,
        "backoff_until": 0,
        "hop_counted": 0,
        "backoff_logged": 0,
        "last_free_wall": 0,
        "free_wall_hops": 0,
        "free_wall_counted": 0,
        "free_wall_until": 0,
    }


def _load_state() -> dict:
    if not GUARD_STATE_FILE.is_file():
        offset = OPENCODE_LOG_FILE.stat().st_size if OPENCODE_LOG_FILE.is_file() else 0
        state = _default_state(offset)
        _save_state(state)
        return state
    try:
        data = json.loads(GUARD_STATE_FILE.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return {**_default_state(), **data}
    except Exception:
        pass
    return _default_state()


def _save_state(state: dict) -> None:
    try:
        GUARD_STATE_FILE.write_text(json.dumps(state), encoding="utf-8")
    except Exception:
        pass


def _resumable(state: dict) -> list[str]:
    """Chats that hit the limit and haven't had a 'continue' since the last new IP."""
    last_hop = float(state.get("last_ok_hop", 0) or 0)
    resumed = state.get("resumed") or {}
    return [sid for sid in (state.get("pending") or {}) if float(resumed.get(sid, 0) or 0) < last_hop]


def _prune(state: dict) -> None:
    cutoff = time.time() - PENDING_MAX_AGE
    for key in ("pending", "resumed"):
        state[key] = {k: v for k, v in (state.get(key) or {}).items() if float(v or 0) >= cutoff}


def _dispatch_auto_resume(state: dict) -> None:
    """After a new IP: send 'continue' to every chat that hit the limit, not just the latest one."""
    try:
        from auto_resume import resume_active_session, is_auto_resume_enabled, clear_opencode_free_limit

        # Always clear client-side free-limit locks immediately upon rotation
        clear_opencode_free_limit()

        sids = _resumable(state)
        if is_auto_resume_enabled():
            time.sleep(1.5)
            ok, res_msg = resume_active_session(sids or None)
            append_log(GUARD_LOG_FILE, f"[auto-resume] Limit bypassed -> {res_msg}")
        now = time.time()
        for sid in sids:
            state.setdefault("resumed", {})[sid] = now
            (state.get("pending") or {}).pop(sid, None)
        _prune(state)
        _save_state(state)
    except Exception as exc:
        append_log(GUARD_LOG_FILE, f"[auto-resume] note: {exc}")


def _next_utc_midnight(now: int) -> int:
    """Return the next 00:00 UTC, when the gateway's free allowance resets."""
    stamp = datetime.fromtimestamp(now, timezone.utc)
    reset = (stamp + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    return int(reset.timestamp())


def _note_wall(state: dict, now: int) -> bool:
    """Track walls that return right after a new IP and pause rotation when it's clearly a loop.

    Returns True while auto-rotation is paused (the caller should not rotate or resume).
    """
    backoff_until = int(state.get("backoff_until", 0) or 0)
    if backoff_until and now >= backoff_until:
        state["backoff_until"] = 0
        state["failed_hops"] = 0
        state["free_wall_hops"] = 0
        state["free_wall_until"] = 0
        append_log(GUARD_LOG_FILE, "rotation pause is over - trying again on the next limit")
    if now < int(state.get("backoff_until", 0) or 0):
        if now - int(state.get("backoff_logged", 0) or 0) >= 60:
            state["backoff_logged"] = now
            _save_state(state)
            left = max(0, (int(state["backoff_until"]) - now) // 60)
            append_log(
                GUARD_LOG_FILE,
                f"limit seen again, but auto-rotation is paused for ~{left} more min "
                f"(new IPs kept hitting the limit immediately)",
            )
        return True

    last_hop = int(state.get("last_ok_hop", 0) or 0)
    if last_hop and now - last_hop <= REWALL_SECONDS:
        if int(state.get("hop_counted", 0) or 0) != last_hop:
            state["hop_counted"] = last_hop
            state["failed_hops"] = int(state.get("failed_hops", 0) or 0) + 1
            append_log(
                GUARD_LOG_FILE,
                f"limit came back {now - last_hop}s after the last IP change "
                f"(failed attempt {state['failed_hops']} of {FAILED_HOPS_MAX})",
            )
    elif last_hop:
        # The previous IP lasted long enough: this isn't a rotation loop.
        state["failed_hops"] = 0

    free_wall = int(state.get("last_free_wall", 0) or 0)
    fresh_free = bool(last_hop) and bool(free_wall) and 0 <= free_wall - last_hop <= REWALL_SECONDS
    if fresh_free:
        if int(state.get("free_wall_counted", 0) or 0) != last_hop:
            state["free_wall_counted"] = last_hop
            state["free_wall_hops"] = int(state.get("free_wall_hops", 0) or 0) + 1
            append_log(
                GUARD_LOG_FILE,
                f"free limit came back {free_wall - last_hop}s after a confirmed new IPv6 "
                f"address ({state['free_wall_hops']} of {FREE_WALL_HOPS_MAX})",
            )
    else:
        state["free_wall_hops"] = 0

    if int(state.get("free_wall_hops", 0) or 0) >= FREE_WALL_HOPS_MAX:
        until = _next_utc_midnight(now)
        state["free_wall_until"] = until
        state["backoff_until"] = until
        state["backoff_logged"] = now
        state["hop_counted"] = last_hop
        reset_at = datetime.fromtimestamp(until, timezone.utc).strftime("%H:%M UTC")
        append_log(
            GUARD_LOG_FILE,
            f"free limit is not following the IP: {FREE_WALL_HOPS_MAX} confirmed new IPv6 "
            f"addresses hit it again. Pausing rotation until {reset_at}. Another provider, "
            f"OpenCode Go, or pressing Try now is the way forward.",
        )
        _save_state(state)
        return True

    if int(state.get("failed_hops", 0) or 0) >= FAILED_HOPS_MAX:
        state["backoff_until"] = now + BACKOFF_SECONDS
        state["backoff_logged"] = now
        append_log(
            GUARD_LOG_FILE,
            f"pausing auto-rotation for {BACKOFF_SECONDS // 60} min: the last "
            f"{FAILED_HOPS_MAX} new addresses hit the limit again immediately. "
            f"It will try one more address by itself after that, or press Rotate /64 Now.",
        )
    _save_state(state)
    return now < int(state.get("backoff_until", 0) or 0)


def _blacklist_add(state: dict, addr: str) -> None:
    prefix = normalize_v6_64(addr)
    if not prefix:
        return
    bl = [x for x in state.get("blacklist", []) if x and normalize_v6_64(x) != prefix]
    bl.append(prefix)
    state["blacklist"] = bl[-BLACKLIST_MAX:]


def _is_burnt(state: dict, addr: str) -> bool:
    prefix = normalize_v6_64(addr)
    if not prefix:
        return False
    return any(x and normalize_v6_64(x) == prefix for x in state.get("blacklist", []))


def _read_new_log_bytes(state: dict) -> tuple[bool, list[str]]:
    """(wall seen since the last offset?, session IDs of the chats that hit it)."""
    if not OPENCODE_LOG_FILE.is_file():
        return False, []
    try:
        size = OPENCODE_LOG_FILE.stat().st_size
    except OSError:
        return False, []

    offset = int(state.get("offset", 0) or 0)
    if size < offset:
        offset = 0

    start = max(offset, size - MAX_READ_BYTES)
    delta = size - start
    wall = False
    sessions: list[str] = []
    if delta > 0:
        try:
            with OPENCODE_LOG_FILE.open("rb") as fh:
                fh.seek(start)
                chunk = fh.read(delta).decode("utf-8", errors="replace")
            chunk_lower = chunk.lower()
            wall_patterns = (
                "quotaexceeded",
                "quota exceeded",
                "quota_exceeded",
                "free usage limit",
                "free usage exceeded",
                "free-tier usage limit",
                "usage limit reached",
                "exceeded your current quota",
                "credits exhausted",
                "rate limit exceeded",
                "rate_limit_exceeded",
                "rate limited",
                "ratelimited",
                "resource_exhausted",
                "429 too many requests",
                "status=429",
                "status: 429",
                "status 429",
                "code=429",
            )
            if any(p in chunk_lower for p in wall_patterns):
                wall = True
                try:
                    from auto_resume import session_id_in
                except Exception:
                    session_id_in = None
                if session_id_in:
                    for line in chunk.splitlines():
                        low = line.lower()
                        if any(p in low for p in wall_patterns):
                            sid = session_id_in(line)
                            if sid and sid not in sessions:
                                sessions.append(sid)
        except OSError:
            pass

    state["offset"] = size
    if wall:
        state["wall_pending"] = True
        state["wall_seen"] = int(time.time())
        if "free usage limit" in chunk_lower:
            state["last_free_wall"] = state["wall_seen"]
    _save_state(state)
    return wall, sessions


def _rotate(state: dict, warp_bin: str | None) -> bool:
    now = int(time.time())

    # Detect active egress mode
    mode = "warp"
    try:
        from proxy_chain import get_egress_config
        mode = get_egress_config().get("mode", "warp")
    except Exception:
        pass

    # 1. Tor Network mode: rotate Tor circuit to get a new exit node IP
    if mode == "tor":
        append_log(GUARD_LOG_FILE, "wall detected in Tor mode — rotating circuit for fresh exit identity")
        try:
            from tor_manager import rotate_tor_circuit
            ok, msg = rotate_tor_circuit()
            state["last_hop"] = now
            state["hops"] = int(state.get("hops", 0) or 0) + 1
            if ok:
                state["last_ok_hop"] = now
            _save_state(state)
            append_log(GUARD_LOG_FILE, f"Tor rotated #{state['hops']}: {msg}")
            if ok:
                _dispatch_auto_resume(state)
            return ok
        except Exception as exc:
            append_log(GUARD_LOG_FILE, f"Tor rotation error: {exc}")
            return False

    # 2. Custom Proxy mode: cycle proxy node in pool
    if mode == "custom":
        append_log(GUARD_LOG_FILE, "wall detected in Custom Proxy mode — cycling proxy node")
        try:
            from proxy_chain import rotate_custom_proxy
            ok, msg = rotate_custom_proxy()
            state["last_hop"] = now
            state["hops"] = int(state.get("hops", 0) or 0) + 1
            if ok:
                state["last_ok_hop"] = now
            _save_state(state)
            append_log(GUARD_LOG_FILE, f"Custom proxy rotated #{state['hops']}: {msg}")
            if ok:
                _dispatch_auto_resume(state)
            return ok
        except Exception as exc:
            append_log(GUARD_LOG_FILE, f"Custom proxy rotation error: {exc}")
            state["last_hop"] = now
            state["hops"] = int(state.get("hops", 0) or 0) + 1
            _save_state(state)
            return False

    # 3. WARP / Clean Endpoint mode: rotate IPv6 /64 subnet
    if not warp_bin:
        append_log(GUARD_LOG_FILE, "wall detected but warp-cli is not installed for WARP rotation")
        return False

    old_v6 = (
        get_egress_v6(timeout=8.0)
        or (get_warp_local_v6() or "")
        or str(state.get("current", ""))
    )
    old_prefix = normalize_v6_64(old_v6)
    append_log(GUARD_LOG_FILE, f"wall detected — rotating WARP /64 (was: {old_v6 or '?'})")
    _blacklist_add(state, old_v6)
    _save_state(state)

    new_v6 = ""
    with keeper_pause_ctx("zen-guard", seconds=600):
        avoid = {str(x) for x in state.get("blacklist", []) if x}
        for attempt in range(1, MAX_HOP_TRIES + 1):
            cand = hop_once(
                warp_bin,
                avoid_prefixes=avoid,
                previous=old_v6,
            )
            if not cand:
                append_log(GUARD_LOG_FILE, f"try {attempt}: rotation produced no fresh /64")
                continue
            if old_prefix and normalize_v6_64(cand) == old_prefix:
                append_log(
                    GUARD_LOG_FILE,
                    f"try {attempt}: WARP returned the same /64 again ({cand}) - not a new IP",
                )
                continue
            if _is_burnt(state, cand):
                append_log(
                    GUARD_LOG_FILE,
                    f"try {attempt}: cloudflare returned a blacklisted /64 ({cand}) — again",
                )
                continue
            new_v6 = cand
            break

        if not new_v6:
            append_log(GUARD_LOG_FILE, "everything blacklisted — recycling oldest block")
            cand = hop_once(
                warp_bin,
                avoid_prefixes=set(),
                previous=old_v6,
            )
            if cand:
                new_v6 = cand

    state["last_hop"] = now
    same_address = bool(old_prefix) and bool(new_v6) and normalize_v6_64(new_v6) == old_prefix
    if new_v6 and not same_address:
        state["current"] = new_v6
        state["hops"] = int(state.get("hops", 0) or 0) + 1
        state["last_ok_hop"] = now
        state["failed_hops"] = 0
        state["backoff_until"] = 0
        state["backoff_logged"] = 0
        state["hop_counted"] = 0
        _save_state(state)
        append_log(GUARD_LOG_FILE, f"rotated #{state['hops']}: {old_v6} -> {new_v6}")
        try:
            from ouc_common import LANE_DIR
            (LANE_DIR / "edge_reroll").write_text(str(time.time()), encoding="utf-8")
        except Exception:
            pass
        _dispatch_auto_resume(state)
        return True

    if same_address:
        # Don't send "continue" on the same limited IP: that is exactly the loop users saw.
        # last_ok_hop is deliberately left alone so the next wall is not treated as
        # a fresh IP (and so no resume is sent here).
        state["failed_hops"] = int(state.get("failed_hops", 0) or 0) + 1
        if state["failed_hops"] >= FAILED_HOPS_MAX:
            state["backoff_until"] = now + BACKOFF_SECONDS
            state["backoff_logged"] = now
            append_log(
                GUARD_LOG_FILE,
                f"pausing auto-rotation for {BACKOFF_SECONDS // 60} min: WARP kept "
                f"returning the same /64 ({new_v6}). It will try again by itself after that.",
            )
        else:
            append_log(
                GUARD_LOG_FILE,
                f"rotation ended on the same /64 ({new_v6}) - chat left paused instead of looping",
            )
        _save_state(state)
        return False

    state["backoff_until"] = now + ROTATION_RETRY_SECONDS
    state["backoff_logged"] = now
    _save_state(state)
    append_log(
        GUARD_LOG_FILE,
        f"rotation failed — no confirmed new IPv6 egress. Pausing retries for "
        f"{ROTATION_RETRY_SECONDS // 60} min so the tunnel is not reconnected in a loop.",
    )
    return False


def main() -> int:
    ensure_dirs()
    mutex = acquire_mutex("OpencodeUnlimitedGuard")
    if mutex is None:
        return 0

    warp_bin = find_warp_cli()
    state = _load_state()
    append_log(
        GUARD_LOG_FILE,
        f"guard up (poll {POLL_SECONDS}s, cooldown {COOLDOWN_SECONDS}s, warp={'found' if warp_bin else 'none'})",
    )
    _heartbeat()

    while True:
        time.sleep(POLL_SECONDS)
        try:
            _heartbeat()
            state = _load_state()
            now = int(time.time())
            backoff_until = int(state.get("backoff_until", 0) or 0)
            if backoff_until and now >= backoff_until:
                state["backoff_until"] = 0
                state["failed_hops"] = 0
                state["backoff_logged"] = 0
                state["hop_counted"] = 0
                _save_state(state)
                append_log(GUARD_LOG_FILE, "rotation pause is over - trying again")
            wall, sessions = _read_new_log_bytes(state)
            if not wall and not state.get("wall_pending"):
                continue

            if wall:
                pending = state.setdefault("pending", {})
                for sid in sessions:
                    pending.setdefault(sid, now)
                _save_state(state)
                if _note_wall(state, now):
                    continue
            elif int(state.get("backoff_until", 0) or 0) > now:
                # Still paused: leave the wall queued for after the break.
                continue

            last_hop = int(state.get("last_hop", 0) or 0)
            last_ok = int(state.get("last_ok_hop", 0) or 0)
            seen = int(state.get("wall_seen", 0) or 0)
            if seen and seen <= last_ok:
                # The wall came from the session that was already rotated.
                for sid in list(state.get("pending") or {}):
                    state.setdefault("resumed", {})[sid] = last_ok
                    (state.get("pending") or {}).pop(sid, None)
                _prune(state)
                state["wall_pending"] = False
                _save_state(state)
                continue

            age = now - last_hop
            if age >= COOLDOWN_SECONDS:
                state["wall_pending"] = False
                _save_state(state)
                if not _rotate(state, warp_bin):
                    state["wall_pending"] = True
                    _save_state(state)
            else:
                # Only continue other tabs when the last hop really produced a
                # new IP. A failed hop or one that stayed on the same /64 must
                # not send 'continue' on the old, limited address.
                fresh_ip = wall and last_ok >= last_hop
                resumable = _resumable(state) if fresh_ip else []
                if resumable:
                    # Other tabs that were cut off by the same wall arrived after
                    # the IP change; the new IP is fresh, so continue them too.
                    append_log(
                        GUARD_LOG_FILE,
                        f"{len(resumable)} more chat(s) hit the limit around the last IP change "
                        f"({age}s ago) - sending them 'continue'",
                    )
                    _dispatch_auto_resume(state)
                else:
                    last_log = int(state.get("last_wait_log", 0) or 0)
                    if now - last_log >= 60:
                        append_log(
                            GUARD_LOG_FILE,
                            f"wall queued — waiting out cooldown ({age}s < {COOLDOWN_SECONDS}s)",
                        )
                        state["last_wait_log"] = now
                        _save_state(state)
        except Exception as exc:
            append_log(GUARD_LOG_FILE, f"guard error: {exc}")


if __name__ == "__main__":
    raise SystemExit(main())
