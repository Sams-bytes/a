"""Who owns the server behind an IP address?

Owning a DOMAIN is not owning the SERVER. dam-bv.com is yours, but its website
runs on Hostinger's shared hosting, a machine that also serves other customers.
Port-scanning it would be port-scanning Hostinger. So before a full scan we ask
the public RDAP registry (the modern WHOIS for IP addresses, run by RIPE, ARIN,
...) who holds the address block, and if it's a hosting/cloud company, Aegis
does a LIGHT scan (what any browser visit sees) unless the customer confirms
the machine is their own (VPS / dedicated server).

Only the IP address is sent to rdap.org; answers are cached for 7 days.
"""

from __future__ import annotations

import ipaddress

import httpx

from app.db import Store

CACHE_S = 7 * 24 * 3600

# keyword in RDAP network name / organisation -> display name
PROVIDERS = [
    ("hostinger", "Hostinger"), ("amazon", "Amazon AWS"), ("aws", "Amazon AWS"),
    ("google", "Google Cloud"), ("microsoft", "Microsoft Azure"), ("azure", "Microsoft Azure"),
    ("cloudflare", "Cloudflare"), ("akamai", "Akamai"), ("linode", "Akamai/Linode"), ("fastly", "Fastly"),
    ("ovh", "OVHcloud"), ("hetzner", "Hetzner"), ("digitalocean", "DigitalOcean"),
    ("transip", "TransIP"), ("strato", "Strato"), ("ionos", "IONOS"), ("1and1", "IONOS"),
    ("godaddy", "GoDaddy"), ("leaseweb", "Leaseweb"), ("scaleway", "Scaleway"), ("online s.a.s", "Scaleway"),
    ("contabo", "Contabo"), ("vercel", "Vercel"), ("netlify", "Netlify"), ("github", "GitHub"),
    ("shopify", "Shopify"), ("squarespace", "Squarespace"), ("wix", "Wix"), ("automattic", "Automattic (WordPress.com)"),
    ("ipxo", "IPXO (leased IP range, operator unknown)"),
]


def provider_from(texts: list[str]) -> str | None:
    blob = " ".join(t for t in texts if t).lower()
    return next((name for kw, name in PROVIDERS if kw in blob), None)


def parse_rdap(d: dict) -> dict:
    names = []
    for e in d.get("entities", []) or []:
        for v in (e.get("vcardArray") or [None, []])[1]:
            if v and v[0] == "fn":
                names.append(str(v[3]))
    network = d.get("name") or ""
    return {"network": network, "org": "; ".join(names), "provider": provider_from([network, *names])}


def lookup(ip: str, store: Store | None = None, http_get=httpx.get) -> dict:
    """{'network', 'org', 'provider'} for one IP. provider 'unknown' if the lookup failed."""
    addr = ipaddress.ip_address(ip)
    if addr.is_loopback or addr.is_private:
        return {"network": "this computer / private network", "org": "", "provider": None}
    key = f"rdap:{ip}"
    if store:
        cached = store.get_cache(key, CACHE_S)
        if cached is not None:
            return cached
    try:
        r = http_get(f"https://rdap.org/ip/{ip}", follow_redirects=True, timeout=20)
        r.raise_for_status()
        info = parse_rdap(r.json())
    except (httpx.HTTPError, ValueError):
        return {"network": "", "org": "", "provider": "unknown"}  # not cached: try again next time
    if store:
        store.set_cache(key, info)
    return info


def classify(ips: list[str], store: Store | None = None, http_get=httpx.get) -> str | None:
    """The hosting provider behind these IPs, or None if none of them is a known provider.

    'unknown' (lookup failed) counts as a provider: when in doubt, scan lightly.
    """
    found = [lookup(ip, store, http_get)["provider"] for ip in ips]
    real = [p for p in found if p and p != "unknown"]
    if real:
        return real[0] if len(set(real)) == 1 else " / ".join(sorted(set(real)))
    return "unknown" if "unknown" in found else None
