"""Subdomain discovery: which names under your domain exist - including forgotten ones?

Sources (all passive / normal DNS questions, nothing is scanned here):
  1. Certificate Transparency logs - every HTTPS certificate is published in
     public logs, so subdomains that ever had a certificate show up there.
     We ask two log search services (crt.sh and certspotter) because each has gaps.
  2. DNS records - mail servers (MX) and service records (SRV).
  3. Educated guesses - ~120 common names (vpn, mail, dev, test, old, ...).

Two classic traps handled here:
  * Wildcard DNS: some domains answer for ANY name. We ask for a random name
    first; if it answers, guesses that only hit the wildcard are dropped.
  * Subdomain takeover: shop.company.nl -> CNAME -> company.myshopify.com, the
    shop was cancelled but the DNS alias stayed. If that target no longer
    exists, an attacker can claim it and serve THEIR page on YOUR subdomain.
    We detect it with DNS only (target answers NXDOMAIN = doesn't exist).

Privacy: the domain name goes to crt.sh / certspotter (public logs), IPs go
to rdap.org (public registry). Nothing else leaves the computer.
"""

from __future__ import annotations

import secrets
from concurrent.futures import ThreadPoolExecutor

import dns.exception
import dns.resolver
import httpx

from app import hosting
from app.db import Store

WORDLIST = """www mail webmail smtp imap pop autodiscover autoconfig mx mx1 mx2 ns ns1 ns2 dns
vpn remote rdp citrix sslvpn gateway gw firewall fw owa exchange outlook teams sip lync
portal intranet extranet login sso auth id admin administrator panel cpanel plesk whm
dev develop development test testing staging stage acc acceptance uat qa demo sandbox preview beta
old new legacy backup backups bak archive tmp temp
shop store webshop pay payment checkout crm erp hr helpdesk support service servicedesk ticket
api api2 app apps mobile m cdn static assets media img images files upload download docs wiki kb
git gitlab github jenkins ci build jira confluence grafana kibana monitor status nagios zabbix
db sql mysql postgres mongo redis elastic search
nas ftp sftp files cloud nextcloud owncloud share drive
blog news cms wp wordpress forum community events academy learn
office mail2 email newsletter mailing lists
server server1 srv host web web1 web2 www2 secure ssl
""".split()

# CNAME suffix -> (provider, takeover possible if the target is gone)
CNAME_PROVIDERS = [
    ("github.io", "GitHub Pages", True), ("herokuapp.com", "Heroku", True), ("herokudns.com", "Heroku", True),
    ("azurewebsites.net", "Microsoft Azure App Service", True), ("cloudapp.net", "Microsoft Azure", True),
    ("cloudapp.azure.com", "Microsoft Azure", True), ("trafficmanager.net", "Azure Traffic Manager", True),
    ("blob.core.windows.net", "Azure Storage", True), ("s3.amazonaws.com", "Amazon S3", True),
    ("s3-website", "Amazon S3", True), ("cloudfront.net", "Amazon CloudFront", True),
    ("elasticbeanstalk.com", "AWS Elastic Beanstalk", True), ("myshopify.com", "Shopify", True),
    ("netlify.app", "Netlify", True), ("netlify.com", "Netlify", True), ("vercel.app", "Vercel", True),
    ("wpengine.com", "WP Engine", True), ("ghost.io", "Ghost", True), ("webflow.io", "Webflow", True),
    ("pantheonsite.io", "Pantheon", True), ("surge.sh", "Surge", True), ("bitbucket.io", "Bitbucket", True),
    ("zendesk.com", "Zendesk", True), ("readme.io", "ReadMe", True), ("fly.dev", "Fly.io", True),
    ("outlook.com", "Microsoft 365", False), ("office.com", "Microsoft 365", False),
    ("hostinger", "Hostinger", False), ("cdn.cloudflare.net", "Cloudflare", False),
]


class DNS:
    """Small wrapper: query(name, type) -> list of answers, [] = no such record, None = name doesn't exist."""

    def __init__(self, lifetime: float = 4):
        self.r = dns.resolver.Resolver()
        self.r.lifetime = lifetime

    def query(self, name: str, rtype: str) -> list[str] | None:
        try:
            ans = self.r.resolve(name, rtype)
        except dns.resolver.NXDOMAIN:
            return None
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout,
                dns.resolver.YXDOMAIN, dns.name.EmptyLabel):
            return []
        return [r.to_text().rstrip(".").lower() for r in ans]


# ---- source 1: certificate logs ------------------------------------------------
def _clean(name: str, domain: str) -> str | None:
    n = name.strip().lower().rstrip(".")
    if n.startswith("*."):
        n = n[2:]
    return n if n.endswith("." + domain) and " " not in n and "@" not in n else None


def certificate_names(domain: str, http_get=httpx.get) -> tuple[set[str], dict[str, bool]]:
    names: set[str] = set()
    ok = {"crt.sh": False, "certspotter": False}
    try:
        r = http_get("https://crt.sh/", params={"q": f"%.{domain}", "output": "json"}, timeout=40)
        r.raise_for_status()
        for row in r.json():
            for n in str(row.get("name_value", "")).split("\n"):
                if (c := _clean(n, domain)):
                    names.add(c)
        ok["crt.sh"] = True
    except (httpx.HTTPError, ValueError):
        pass
    try:
        r = http_get("https://api.certspotter.com/v1/issuances",
                     params={"domain": domain, "include_subdomains": "true", "expand": "dns_names"}, timeout=40)
        r.raise_for_status()
        for row in r.json():
            for n in row.get("dns_names", []):
                if (c := _clean(n, domain)):
                    names.add(c)
        ok["certspotter"] = True
    except (httpx.HTTPError, ValueError, AttributeError):
        pass
    return names, ok


# ---- checking one name -----------------------------------------------------------
def cname_provider(target: str | None) -> tuple[str | None, bool]:
    if not target:
        return None, False
    return next(((p, t) for suffix, p, t in CNAME_PROVIDERS if suffix in target), (None, False))


def inspect(name: str, sources: set[str], resolver: DNS, wildcard_ips: set[str],
            classify=hosting.classify) -> dict | None:
    """Look one name up. None = drop it (a guess that doesn't really exist)."""
    cname = (resolver.query(name, "CNAME") or [None])[0]
    a, aaaa = resolver.query(name, "A"), resolver.query(name, "AAAA")
    ips = sorted(set((a or []) + (aaaa or [])))
    only_guess = sources == {"guess"}

    if only_guess and not ips and not cname:
        return None                       # guessed name doesn't exist
    if only_guess and wildcard_ips and not cname and set(ips) <= wildcard_ips:
        return None                       # just the wildcard answering

    provider, takeover_possible = cname_provider(cname)
    status = "ok" if ips else "no_address"
    if cname and takeover_possible and resolver.query(cname, "A") is None and resolver.query(cname, "AAAA") is None:
        status = "takeover_risk"          # alias points at something that no longer exists
    if not provider and ips:
        provider = classify(ips)
    return {"name": name, "sources": sorted(sources), "ips": ips, "cname": cname,
            "provider": provider, "status": status}


def discover(domain: str, store: Store | None = None, resolver: DNS | None = None, http_get=httpx.get,
             classify=None) -> dict:
    """Find subdomains of `domain`. Returns {'subdomains': [...], 'sources': {...}}."""
    resolver = resolver or DNS()
    classify = classify or (lambda ips: hosting.classify(ips, store, http_get))
    found: dict[str, set[str]] = {}

    ct, ok = certificate_names(domain, http_get)
    for n in ct:
        found.setdefault(n, set()).add("certificates")
    for rtype, qname in (("MX", domain), ("SRV", f"_autodiscover._tcp.{domain}"), ("SRV", f"_sip._tls.{domain}")):
        for rec in resolver.query(qname, rtype) or []:
            if (c := _clean(rec.split()[-1], domain)):
                found.setdefault(c, set()).add("dns")
    for word in WORDLIST:
        found.setdefault(f"{word}.{domain}", set()).add("guess")

    wildcard = resolver.query(f"aegis-{secrets.token_hex(6)}.{domain}", "A") or []
    with ThreadPoolExecutor(max_workers=20) as pool:
        rows = list(pool.map(lambda kv: inspect(kv[0], kv[1], resolver, set(wildcard), classify), found.items()))
    rows = sorted((r for r in rows if r), key=lambda r: (r["status"] != "takeover_risk", r["name"]))
    return {"subdomains": rows, "sources": {**ok, "dns": True, "wildcard_dns": bool(wildcard)}}
