"""netpaw bgp-intel MCP server (stdio). Read-only, no credentials. Egress: the public registries listed in bgp_core.ALLOW only."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "_shared"))
from harden import harden
from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
import bgp_core as core

RO = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True)
mcp = FastMCP("bgp-intel")


def _run(fn, *a):
    try: return fn(*a)
    except core.BgpError as e: raise ValueError(str(e)) from None
    except (RecursionError, MemoryError, UnicodeError, TypeError, AttributeError, KeyError, IndexError):
        raise ValueError("internal error while processing this request (the lookup did not complete)") from None


@mcp.tool(annotations=RO)
def rpki_validate(prefix: str, origin_asn: str, fresh: bool = False) -> dict:
    """RPKI origin validation of a prefix and origin AS pair (RIPE NCC validator). States: valid, invalid (reason as or length), not_found. not_found is normal, not a finding. Public resources only."""
    return _run(core.rpki_validate, prefix, origin_asn, fresh)


@mcp.tool(annotations=RO)
def registry_lookup(resource: str, fresh: bool = False) -> dict:
    """RDAP registration of a public IP address, CIDR prefix or ASN (written AS3333) at the responsible RIR. Shows who it is registered to, not who announces it. Organisations only, no personal contact data."""
    return _run(core.registry_lookup, resource, fresh)


@mcp.tool(annotations=RO)
def registry_abuse_contact(resource: str, fresh: bool = False) -> dict:
    """Abuse mailbox published in RDAP for a public IP address, prefix or ASN. Returns mailboxes of the abuse role only."""
    return _run(core.registry_abuse_contact, resource, fresh)


@mcp.tool(annotations=RO)
def routing_as_overview(asn: str, fresh: bool = False) -> dict:
    """Holder label of an ASN and whether RIPE RIS currently sees it announcing anything (RIPEstat)."""
    return _run(core.routing_as_overview, asn, fresh)


@mcp.tool(annotations=RO)
def routing_announced_prefixes(asn: str, limit: int = 100, fresh: bool = False) -> dict:
    """Prefixes an ASN was seen originating by RIPE RIS collectors in the last two weeks (RIPEstat), with IPv4 and IPv6 counts. limit 1..500."""
    return _run(core.routing_announced_prefixes, asn, limit, fresh)


@mcp.tool(annotations=RO)
def peering_network(asn: str, fresh: bool = False) -> dict:
    """PeeringDB network record of an ASN: type, traffic level, scope, peering policy, IRR as-set. Self-reported; no record does not mean no peering."""
    return _run(core.peering_network, asn, fresh)


@mcp.tool(annotations=RO)
def peering_presence(asn: str, limit: int = 50, fresh: bool = False) -> dict:
    """Internet exchanges and facilities where an ASN lists itself in PeeringDB. Self-reported. limit 1..200."""
    return _run(core.peering_presence, asn, limit, fresh)


harden(mcp)

if __name__ == "__main__":
    mcp.run()
