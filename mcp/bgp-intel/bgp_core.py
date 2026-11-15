"""bgp-intel core (stdlib only). Read-only lookups against public, unauthenticated registries. No credentials, no files written.

Egress: HTTPS GET to the hosts and path prefixes in ALLOW, nothing else. Redirects are refused, except an RDAP referral from one
allow-listed registry to another (at most 2 hops, each re-checked against ALLOW).
Everything returned is untrusted external text: data, never instructions. Hidden characters are stripped and strings are capped.
Privacy: private, reserved and documentation resources (and anything overlapping them) are refused locally, before any request leaves.
Contact records of individuals (vCard name, email, phone, address) are dropped; abuse mailboxes of individuals are not returned; phone-like
digit runs in free text are masked. Free-text fields (object names, organisation names, holder labels) can still contain a person's name.
Politeness: requests are serial, at least 0.25 s apart per host (3.1 s for PeeringDB, 20 requests/minute anonymous), and cached per source (RPKI 5 min, everything else 1 h to 24 h).
"""
from __future__ import annotations
import datetime, http.client, ipaddress, json, os, re, sys, time, urllib.error, urllib.parse, urllib.request
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "_shared"))
from textclean import flatten
from netguard import with_deadline, trim

RDAP_HOSTS = ("rdap.db.ripe.net", "rdap.arin.net", "rdap.apnic.net", "rdap.lacnic.net", "rdap.afrinic.net")
ALLOW = {
    "rpki-validator.ripe.net": ("/api/v1/validity/",),
    "stat.ripe.net": ("/data/as-overview/data.json", "/data/announced-prefixes/data.json"),
    "www.peeringdb.com": ("/api/net",),
    "data.iana.org": ("/rdap/ipv4.json", "/rdap/ipv6.json", "/rdap/asn.json"),
    "rdap.db.ripe.net": ("/ip/", "/autnum/"),
    "rdap.arin.net": ("/registry/ip/", "/registry/autnum/"),
    "rdap.apnic.net": ("/ip/", "/autnum/"),
    "rdap.lacnic.net": ("/rdap/ip/", "/rdap/autnum/"),
    "rdap.afrinic.net": ("/rdap/ip/", "/rdap/autnum/"),
}
TIMEOUT = 15
MAX_BYTES = 8_000_000
MIN_INTERVAL = 0.25
HOST_INTERVAL = {"www.peeringdb.com": 3.1}   # PeeringDB anonymous limit is 20 requests/minute (tester B-2)
SOURCEAPP = "netpaw"                        # RIPEstat asks callers to identify themselves (tester B-7)
UA = "netpaw-bgp-intel/0.1 (+https://github.com/supachai-j/netpaw)"
CTYPES = ("application/json", "application/rdap+json")
TTL = {"rpki-validator.ripe.net": 300, "stat.ripe.net": 3600, "www.peeringdb.com": 3600, "data.iana.org": 86400}
TTL_RDAP = 86400
CACHE_MAX = 64
CACHE_CHARS = 24_000_000      # total characters kept (review H5-6; was up to 64 x 8 MB)
_cache: dict[str, tuple[float, str]] = {}
_last: dict[str, float] = {}

C_RPKI = ["not_found means no ROA covers the prefix. That is the common case on the internet and is not a finding.",
          "invalid has two different causes (reason 'as' or 'length'); do not merge them.",
          "Single validator (RIPE NCC); the result is not corroborated by a second one."]
C_RDAP = ["Registry data shows who the resource is registered to, not who announces it in BGP.",
          "Person names, phone numbers and postal addresses are removed from this result on purpose."]
C_STAT = ["Visibility is what RIPE RIS collectors see, not the whole internet. Low or no visibility has legitimate causes."]
C_PDB = ["PeeringDB is self-reported. No record means nobody entered one, not that the network does not peer."]


class BgpError(ValueError):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


_PHONE = re.compile(r"(?<![\w.])\+?\d[\d ()./-]{6,}\d(?![\w.])")


def _s(v, n=200) -> str:
    return flatten(v)[:n].strip() if isinstance(v, (str, int, float)) and not isinstance(v, bool) else ""


def _t(v, n=200) -> str:
    """Free text from a registry (names, holder labels): phone-number-like digit runs are masked (H5-1). Names of people cannot be detected."""
    def mask(m):
        t = m.group(0)
        if sum(ch.isdigit() for ch in t) < 8 or re.fullmatch(r"\d{4}-\d{2}-\d{2}", t) or re.search(r"\d{1,3}(\.\d{1,3}){3}", t): return t   # dates and anything carrying an IPv4 address

        return "[number removed]"
    return _PHONE.sub(mask, _s(v, n))


def allowed(url: str) -> bool:
    try: u = urllib.parse.urlsplit(url)
    except ValueError: return False
    if u.scheme != "https" or u.netloc != u.hostname or u.fragment or u.hostname not in ALLOW: return False
    if ".." in u.path or "//" in u.path or "\\" in url or "%" in u.path: return False
    return any(u.path == p if p.endswith(".json") or p == "/api/net" else u.path.startswith(p) and len(u.path) > len(p) for p in ALLOW[u.hostname])


def _read(r, limit: int, end: float) -> bytes:
    buf = bytearray()
    while len(buf) < limit:
        if time.monotonic() > end: raise BgpError("source unavailable: response too slow (overall timeout)")
        chunk = r.read1(min(65536, limit - len(buf)))
        if not chunk: break
        buf += chunk
    return bytes(buf)


def _http(url: str, hops: int = 0):
    """Wall-clock limit for one request including connect, status line and headers (review H5-4). Referral hops get their own limit."""
    if not allowed(url): raise BgpError("refused: URL outside the allow-list")
    host = urllib.parse.urlsplit(url).hostname
    return with_deadline(lambda: _http_once(url, hops), TIMEOUT + 5,
                         BgpError(f"source unavailable: {host} too slow (overall timeout, including headers). This is not the same as 'no record'."))


def _http_once(url: str, hops: int = 0):
    """The only function that touches the network."""
    if not allowed(url): raise BgpError("refused: URL outside the allow-list")
    host = urllib.parse.urlsplit(url).hostname
    wait = max(MIN_INTERVAL, HOST_INTERVAL.get(host, 0.0)) - (time.monotonic() - _last.get(host, 0.0))
    if wait > 0: time.sleep(wait)
    _last[host] = time.monotonic()
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/rdap+json, application/json"})
    try:
        with urllib.request.build_opener(_NoRedirect).open(req, timeout=TIMEOUT) as r:
            ctype = (r.headers.get("Content-Type") or "").split(";")[0].strip().lower()
            if ctype not in CTYPES: raise BgpError(f"source unavailable: unexpected content-type from {host}")
            data = _read(r, MAX_BYTES + 1, time.monotonic() + TIMEOUT)
            final = host
    except BgpError: raise
    except urllib.error.HTTPError as e:
        loc = e.headers.get("Location") if e.headers else None
        code = e.code; e.close()
        if code in (301, 302, 303, 307, 308) and host in RDAP_HOSTS and loc and hops < 2 and allowed(loc) and urllib.parse.urlsplit(loc).hostname in RDAP_HOSTS:
            return _http(loc, hops + 1)     # returns (text, host that actually answered)
        if code in (301, 302, 303, 307, 308):
            to = _s(urllib.parse.urlsplit(loc or "").hostname or "an unknown host", 80)
            raise BgpError(f"referral not followed: {host} refers this resource to {to}, which is not on the allow-list (for example a national registry). Registration data is not available through this tool; this is not 'no record'.") from None
        if code == 404: raise BgpError(f"no record at {host} (HTTP 404)") from None
        if code == 429: raise BgpError(f"source unavailable: {host} is rate limiting (HTTP 429); wait, do not retry in a loop") from None
        raise BgpError(f"source unavailable: HTTP {code} from {host}. This is not the same as 'no record'.") from None
    except urllib.error.URLError as e:
        raise BgpError(f"source unavailable: network error reaching {host} ({_s(str(e.reason), 80)}). This is not the same as 'no record'.") from None
    except (TimeoutError, OSError):
        raise BgpError(f"source unavailable: timeout or connection error reaching {host}. This is not the same as 'no record'.") from None
    except (http.client.HTTPException, ValueError):      # tester B-1: a peer that does not speak HTTP (BadStatusLine, IncompleteRead, bad headers)
        raise BgpError(f"source unavailable: malformed HTTP response from {host}. This is not the same as 'no record'.") from None
    if len(data) > MAX_BYTES: raise BgpError(f"source unavailable: response from {host} exceeds the size cap")
    return data.decode("utf-8", "replace"), final


def _get(url: str, fresh: bool = False):
    """Returns (parsed JSON dict, meta). Cached per URL with a per-source lifetime."""
    if not allowed(url): raise BgpError("refused: URL outside the allow-list")
    host = urllib.parse.urlsplit(url).hostname
    ttl, now, hit = TTL.get(host, TTL_RDAP), time.time(), _cache.get(url)
    cached = bool(hit) and not fresh and now - hit[0] < ttl
    if not cached:
        got = _http(url)
        text, answered = got if isinstance(got, tuple) else (got, host)
        _cache.pop(url, None)
        trim(_cache, CACHE_MAX, CACHE_CHARS - len(text), size=lambda h: len(h[1]))
        _cache[url] = hit = (now, text, answered)
    answered = hit[2] if len(hit) > 2 else host
    try: d = json.loads(hit[1])
    except (ValueError, RecursionError):
        _cache.pop(url, None); raise BgpError(f"source unavailable: {host} did not return valid JSON") from None
    if not isinstance(d, dict): raise BgpError(f"source unavailable: unexpected response shape from {host}")
    meta = {"untrusted_external_text": True, "source": answered, "source_url": url,
            "retrieved_at": datetime.datetime.fromtimestamp(hit[0], datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "cached": cached, "cache_age_seconds": int(now - hit[0]) if cached else None}
    if answered != host: meta["referred_from"] = host     # tester B-4: name the registry that actually answered
    return d, meta


# ---------------------------------------------------------------- input validation (local, before any request)
_RESERVED_ASN = ((0, 0), (23456, 23456), (64496, 64511), (64512, 65534), (65535, 65551), (65552, 131071), (4200000000, 4294967295))


def asn(value) -> int:
    m = re.fullmatch(r"(?:[Aa][Ss])?\s*(\d{1,10})", _s(value, 20)) if not isinstance(value, bool) else None
    if not m: raise BgpError("ASN must look like 3333 or AS3333")
    n = int(m.group(1))
    if n > 4294967295: raise BgpError("ASN out of range")
    if any(a <= n <= b for a, b in _RESERVED_ASN):
        raise BgpError(f"AS{n} is a private, documentation or reserved ASN; refused locally (nothing was sent to a public registry)")
    return n


_EMBED = (ipaddress.ip_network("64:ff9b::/96"), ipaddress.ip_network("64:ff9b:1::/48"), ipaddress.ip_network("::ffff:0:0/96"), ipaddress.ip_network("::/96"))


def _embedded_v4(net):
    """IPv4 carried inside an IPv6 prefix (NAT64, IPv4-mapped/compatible, 6to4, Teredo): tester B-5."""
    a = net.network_address
    if any(net.subnet_of(b) for b in _EMBED): return ipaddress.ip_address(int(a) & 0xFFFFFFFF)
    return a.sixtofour or (a.teredo[1] if a.teredo else None)


# IANA special-purpose registries (RFC 6890 and updates) plus deprecated site-local: a query that overlaps any of them is refused (H5-8)
_SPECIAL = tuple(ipaddress.ip_network(x) for x in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24",
    "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
    "::/128", "::1/128", "::ffff:0:0/96", "64:ff9b:1::/48", "100::/64", "2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20", "5f00::/16",
    "fc00::/7", "fe80::/10", "fec0::/10", "ff00::/8"))
_GLOBAL_EXCEPTIONS = tuple(ipaddress.ip_network(x) for x in ("2001:4:112::/48", "2001:20::/28", "2001:30::/28", "2001:3::/32", "2001:1::1/128", "2001:1::2/128"))


def _public(net) -> None:
    # ip_network.is_global is true for a supernet such as 0.0.0.0/0 that contains private space, so both ends and the length are checked too
    short = net.prefixlen < (8 if net.version == 4 else 16)
    v4 = _embedded_v4(net) if net.version == 6 else None
    if v4 is not None and not v4.is_global:
        raise BgpError(f"{net} carries the IPv4 address {v4}, which is private or reserved; refused locally (nothing was sent to a public registry)")
    hits = [s for s in _SPECIAL if s.version == net.version and net.overlaps(s) and not any(net.subnet_of(g) for g in _GLOBAL_EXCEPTIONS if g.version == net.version)]
    if hits and not (net.version == 6 and v4 is not None):
        raise BgpError(f"{net} overlaps special-purpose space {hits[0]}; refused locally (nothing was sent to a public registry). Ask about a more specific public prefix.")
    if short or not net.is_global or net.is_multicast or not net.network_address.is_global or not net.broadcast_address.is_global:
        raise BgpError(f"{net} is private, reserved, documentation or multicast space; refused locally (nothing was sent to a public registry)")


def prefix(value):
    t = _s(value, 60)
    if "/" not in t: raise BgpError("prefix must be CIDR, for example 193.0.0.0/21")
    try: net = ipaddress.ip_network(t, strict=True)
    except ValueError: raise BgpError("prefix must be a valid CIDR with no host bits set, for example 193.0.0.0/21") from None
    _public(net); return net


def resource(value):
    """-> ('asn', int) | ('ip', ip_network). Accepts an ASN, an IP address or a CIDR prefix."""
    t = _s(value, 60)
    if re.fullmatch(r"(?:[Aa][Ss])\s*\d{1,10}", t): return "asn", asn(t)
    if re.fullmatch(r"\d{1,10}", t): raise BgpError("ambiguous number: write an ASN as AS3333")
    try: net = ipaddress.ip_network(t, strict=True)
    except ValueError: raise BgpError("resource must be an ASN (AS3333), an IP address or a CIDR prefix") from None
    _public(net); return "ip", net


def _safe(fn):
    def wrapper(*a, **k):
        try: return fn(*a, **k)
        except BgpError: raise
        except (AttributeError, TypeError, KeyError, IndexError, ValueError, RecursionError, UnicodeError):
            raise BgpError("source unavailable: unexpected response shape (the lookup did not complete; this is not 'no record')") from None
    wrapper.__name__ = fn.__name__; wrapper.__doc__ = fn.__doc__
    return wrapper


def _q(kind, v) -> str:
    return f"AS{v}" if kind == "asn" else str(v.network_address) if v.prefixlen == v.max_prefixlen else str(v)


def _d(x): return x if isinstance(x, dict) else {}
def _l(x): return x if isinstance(x, list) else []


# ---------------------------------------------------------------- RPKI
@_safe
def rpki_validate(pfx, origin_asn, fresh: bool = False) -> dict:
    net, n = prefix(pfx), asn(origin_asn)
    try: d, meta = _get(f"https://rpki-validator.ripe.net/api/v1/validity/AS{n}/{net}", fresh)
    except BgpError as e:
        raise BgpError(f"validation_unavailable: {e}. The RPKI state is unknown; do not report it as not_found.") from None
    route = _d(_d(d.get("validated_route")).get("route"))
    try: same = _s(route.get("origin_asn"), 16).upper() == f"AS{n}" and ipaddress.ip_network(_s(route.get("prefix"), 60), strict=False) == net
    except ValueError: same = False
    if not same: raise BgpError("validation_unavailable: the validator answered about a different route than the one asked. The RPKI state is unknown.")
    v = _d(_d(d.get("validated_route")).get("validity"))
    raw = _s(v.get("state"), 20).lower()
    if raw not in ("valid", "invalid", "not-found"): raise BgpError("validation_unavailable: the validator returned an unknown state. The RPKI state is unknown.")
    vrps = _d(v.get("VRPs"))
    fmt = lambda xs: [{"asn": _s(_d(x).get("asn"), 16), "prefix": _s(_d(x).get("prefix"), 50), "max_length": _s(_d(x).get("max_length"), 4)} for x in _l(xs)[:20]]
    data = {"prefix": str(net), "origin_asn": f"AS{n}", "state": raw.replace("-", "_")}
    if raw == "invalid":
        bad_as, bad_len = _l(vrps.get("unmatched_as")), _l(vrps.get("unmatched_length"))
        data["reason"] = "length" if bad_len else "as" if bad_as else "unknown"
        data["meaning"] = ("the origin AS is authorised but this prefix is more specific than the ROA max length allows" if bad_len else
                           "a ROA covers this prefix but authorises a different AS" if bad_as else "the validator did not say why")
        data["covering_vrps"] = fmt(bad_len or bad_as)
    elif raw == "valid": data["matched_vrps"] = fmt(vrps.get("matched"))
    else: data["meaning"] = "no ROA covers this prefix (RFC 6811 NotFound); normal for unsigned space, not a finding"
    return {**meta, "outcome": "ok", "data": data, "caveats": C_RPKI}


# ---------------------------------------------------------------- RDAP
def _bootstrap(kind: str, value) -> str:
    """IANA RDAP bootstrap (RFC 9224) -> base URL of the responsible registry; only allow-listed registries are accepted."""
    if kind == "asn":
        d, _ = _get("https://data.iana.org/rdap/asn.json")
        match = lambda key: (lambda a, _, b: int(a) <= value <= int(b or a))(*str(key).partition("-"))
        best = [(0, urls) for keys, urls in (s for s in _l(d.get("services")) if isinstance(s, list) and len(s) == 2) for k in _l(keys) if re.fullmatch(r"\d+(-\d+)?", str(k)) and match(k)]
    else:
        d, _ = _get(f"https://data.iana.org/rdap/ipv{value.version}.json")
        best = []
        for s in _l(d.get("services")):
            if not (isinstance(s, list) and len(s) == 2): continue
            for k in _l(s[0]):
                try: blk = ipaddress.ip_network(str(k), strict=False)
                except ValueError: continue
                if blk.version == value.version and value.subnet_of(blk): best.append((blk.prefixlen, s[1]))
    for _, urls in sorted(best, key=lambda x: -x[0]):
        for u in _l(urls):
            u = str(u)
            if u.startswith("https://") and urllib.parse.urlsplit(u).hostname in RDAP_HOSTS: return u if u.endswith("/") else u + "/"
    raise BgpError("no RDAP registry is listed for this resource in the IANA bootstrap (or it is not one of the five RIRs)")


def _rdap(value, fresh: bool = False):
    kind, v = resource(value)
    base = _bootstrap(kind, v)
    path = f"autnum/{v}" if kind == "asn" else f"ip/{v.network_address}" + (f"/{v.prefixlen}" if v.prefixlen != v.max_prefixlen else "")
    d, meta = _get(base + path, fresh)
    return kind, v, d, meta


def _entities(node, depth=0):
    for e in _l(_d(node).get("entities"))[:50]:
        if isinstance(e, dict):
            yield e
            if depth < 3: yield from _entities(e, depth + 1)


def _vcard(e: dict) -> dict:
    out = {}
    arr = _l(e.get("vcardArray"))
    for item in _l(arr[1] if len(arr) > 1 else [])[:60]:
        if isinstance(item, list) and len(item) >= 4 and isinstance(item[0], str): out.setdefault(item[0].lower(), item[3])
    return out


@_safe
def registry_lookup(res, fresh: bool = False) -> dict:
    kind, v, d, meta = _rdap(res, fresh)
    orgs = []
    for e in _entities(d):
        vc = _vcard(e)
        if _s(vc.get("kind"), 20).lower() == "org" and _s(vc.get("fn")):   # organisations only; individuals and role groups are dropped
            o = {"name": _t(vc.get("fn"), 120), "handle": _s(e.get("handle"), 60), "roles": [_s(r, 30) for r in _l(e.get("roles"))[:6]]}
            if o not in orgs: orgs.append(o)
    data = {"query": _q(kind, v), "handle": _s(d.get("handle"), 80), "name": _t(d.get("name"), 120), "type": _s(d.get("type"), 60),
            "country": _s(d.get("country"), 8), "status": [_s(x, 40) for x in _l(d.get("status"))[:6]],
            "events": [{"action": _s(_d(x).get("eventAction"), 40), "date": _s(_d(x).get("eventDate"), 40)} for x in _l(d.get("events"))[:6]],
            "organisations": orgs[:10]}
    if kind == "ip":
        data.update(start_address=_s(d.get("startAddress"), 50), end_address=_s(d.get("endAddress"), 50), parent_handle=_s(d.get("parentHandle"), 80),
                    cidrs=[f"{_s(_d(c).get('v4prefix') or _d(c).get('v6prefix'), 50)}/{_s(_d(c).get('length'), 4)}" for c in _l(d.get("cidr0_cidrs"))[:20]])
    else: data.update(start_autnum=_s(d.get("startAutnum"), 12), end_autnum=_s(d.get("endAutnum"), 12))
    return {**meta, "outcome": "ok", "data": data, "caveats": C_RDAP}


_EMAIL = re.compile(r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}")


@_safe
def registry_abuse_contact(res, fresh: bool = False) -> dict:
    kind, v, d, meta = _rdap(res, fresh)
    found, personal = [], 0
    for e in _entities(d):
        if "abuse" in [_s(r, 30).lower() for r in _l(e.get("roles"))]:
            vc = _vcard(e)
            if _s(vc.get("kind"), 20).lower() == "individual": personal += 1; continue    # H5-1: a person's own mailbox is not returned
            mail = _s(vc.get("email"), 254)
            if _EMAIL.fullmatch(mail) and mail not in found: found.append(mail)
    data = {"query": _q(kind, v), "registered_object": _s(d.get("handle"), 80), "abuse_mailboxes": found[:5]}
    caveats = ["Only mailboxes of role or organisation entities with the RDAP role 'abuse' are returned; a mailbox may still belong to one person at small holders.",
               "The mailbox is registry data and unverified. Use it for abuse reports about this resource, nothing else."]
    if personal: caveats.insert(0, f"{personal} abuse contact(s) registered as an individual were not returned (personal data). The user can look them up at the registry directly.")
    if not found: caveats.insert(0, "No abuse contact is published on this object. Try the covering allocation (parent) with registry_lookup.")
    return {**meta, "outcome": "ok" if found else "no_record", "data": data, "caveats": caveats}


# ---------------------------------------------------------------- RIPEstat
def _stat(call: str, n: int, fresh: bool):
    d, meta = _get(f"https://stat.ripe.net/data/{call}/data.json?resource=AS{n}&sourceapp={SOURCEAPP}", fresh)
    if _s(d.get("status"), 20).lower() != "ok": raise BgpError("source unavailable: stat.ripe.net did not return status ok. This is not the same as 'no record'.")
    return _d(d.get("data")), meta


@_safe
def routing_as_overview(a, fresh: bool = False) -> dict:
    n = asn(a); d, meta = _stat("as-overview", n, fresh)
    blk = _d(d.get("block"))
    data = {"asn": f"AS{n}", "holder": _t(d.get("holder"), 200), "announced": d.get("announced") if isinstance(d.get("announced"), bool) else None,
            "iana_block": {"range": _s(blk.get("resource"), 40), "description": _t(blk.get("desc"), 120)}}
    return {**meta, "outcome": "ok", "data": data, "caveats": C_STAT + ["holder is a registry label, not proof of who operates the network today."]}


@_safe
def routing_announced_prefixes(a, limit: int = 100, fresh: bool = False) -> dict:
    n = asn(a)
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 500: raise BgpError("limit must be 1..500")
    d, meta = _stat("announced-prefixes", n, fresh)
    seen = []
    for p in _l(d.get("prefixes"))[:200000]:
        try: seen.append(ipaddress.ip_network(_s(_d(p).get("prefix"), 60), strict=False))
        except ValueError: continue
    seen = sorted(set(seen), key=lambda x: (x.version, x))
    data = {"asn": f"AS{n}", "total": len(seen), "ipv4": sum(1 for x in seen if x.version == 4), "ipv6": sum(1 for x in seen if x.version == 6),
            "prefixes": [str(x) for x in seen[:limit]], "truncated": len(seen) > limit}
    return {**meta, "outcome": "ok" if seen else "no_record", "data": data,
            "caveats": C_STAT + ["Routes seen by fewer than 10 RIS full-feed peers are excluded by the source.", "An empty list means RIS saw nothing recently, not that the AS does not exist."]}


# ---------------------------------------------------------------- PeeringDB
def _pdb(n: int, depth2: bool, fresh: bool):
    url = f"https://www.peeringdb.com/api/net?asn={n}" + ("&depth=2" if depth2 else "")
    try: d, meta = _get(url, fresh)
    except BgpError as e:
        if not str(e).startswith("no record at "): raise
        return None, {"untrusted_external_text": True, "source": "www.peeringdb.com", "source_url": url,
                      "retrieved_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "cached": False, "cache_age_seconds": None}
    rows = [x for x in _l(d.get("data")) if isinstance(x, dict)]
    return (rows[0] if rows else None), meta


def _web(v) -> str:
    """Only http(s) links with a host; javascript:, data: and the like are dropped (tester B-3)."""
    u = _s(v, 200)
    try: p = urllib.parse.urlsplit(u)
    except ValueError: return ""
    return u if p.scheme.lower() in ("http", "https") and p.hostname and not re.search(r"\s", u) else ""


@_safe
def peering_network(a, fresh: bool = False) -> dict:
    n = asn(a); row, meta = _pdb(n, False, fresh)
    if row is None: return {**meta, "outcome": "no_record", "data": {"asn": f"AS{n}"}, "caveats": C_PDB}
    num = lambda k: row.get(k) if isinstance(row.get(k), int) and not isinstance(row.get(k), bool) else None
    data = {"asn": f"AS{n}", "name": _t(row.get("name"), 120), "aka": _t(row.get("aka"), 120), "website": _web(row.get("website")), "irr_as_set": _s(row.get("irr_as_set"), 200),
            "network_type": _s(row.get("info_type"), 40), "traffic": _s(row.get("info_traffic"), 40), "ratio": _s(row.get("info_ratio"), 40), "scope": _s(row.get("info_scope"), 40),
            "prefixes_ipv4": num("info_prefixes4"), "prefixes_ipv6": num("info_prefixes6"), "peering_policy": _s(row.get("policy_general"), 40),
            "ix_count": num("ix_count"), "facility_count": num("fac_count"), "record_updated": _s(row.get("updated"), 40)}
    return {**meta, "outcome": "ok", "data": data, "caveats": C_PDB + ["Contact records (poc) are not requested or returned."]}


@_safe
def peering_presence(a, limit: int = 50, fresh: bool = False) -> dict:
    n = asn(a)
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 200: raise BgpError("limit must be 1..200")
    row, meta = _pdb(n, True, fresh)
    if row is None: return {**meta, "outcome": "no_record", "data": {"asn": f"AS{n}"}, "caveats": C_PDB}
    ix = [{"exchange": _s(_d(x).get("name"), 120), "speed_mbps": _d(x).get("speed") if isinstance(_d(x).get("speed"), int) else None, "ipv4": _s(_d(x).get("ipaddr4"), 50),
           "ipv6": _s(_d(x).get("ipaddr6"), 50), "route_server_peer": _d(x).get("is_rs_peer") is True, "operational": _d(x).get("operational") is not False} for x in _l(row.get("netixlan_set"))]
    # depth=2 also brings poc_set (contact records); it is never read or returned
    fac = [{"facility": _s(_d(x).get("name"), 120), "city": _s(_d(x).get("city"), 80), "country": _s(_d(x).get("country"), 8)} for x in _l(row.get("netfac_set"))]
    data = {"asn": f"AS{n}", "name": _t(row.get("name"), 120), "exchange_count": len(ix), "facility_count": len(fac), "exchanges": ix[:limit], "facilities": fac[:limit],
            "truncated": len(ix) > limit or len(fac) > limit}
    return {**meta, "outcome": "ok", "data": data, "caveats": C_PDB}
