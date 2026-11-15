"""Shared limits for the servers that fetch from the internet (rfc-lookup, wikipedia, bgp-intel). Stdlib only, no network code here.

- with_deadline(): one wall-clock limit for a whole fetch, including connect, status line and headers (review H5-4). urllib's socket timeout
  applies per recv, so a peer that drips the status line or headers one byte at a time could hold a call far longer than TIMEOUT.
  The fetch runs in a daemon thread; on expiry the caller gets an error at once. Limit: the thread itself lives until the peer stops or the
  per-recv socket timeout fires; it holds no lock and its result is discarded.
- trim(): keeps an in-memory cache under a character budget as well as an entry count (review H5-6).
"""
import threading


def with_deadline(fn, seconds: float, on_timeout):
    box = {}
    def run():
        try: box["ok"] = fn()
        except BaseException as e: box["err"] = e      # re-raised in the caller's thread
    t = threading.Thread(target=run, daemon=True, name="netpaw-fetch")
    t.start(); t.join(seconds)
    if t.is_alive(): raise on_timeout
    if "err" in box: raise box["err"]
    return box["ok"]


def trim(cache: dict, max_entries: int, max_chars: int, size=len) -> None:
    """Drop the oldest entries until there is room for one more and the total size is under max_chars."""
    while cache and (len(cache) >= max_entries or sum(size(v) for v in cache.values()) > max_chars):
        cache.pop(next(iter(cache)))
