# RAZVILKA data-source policy

RAZVILKA deliberately separates **block-state data**, **service ownership/classification**, and **vendor network requirements**.

## Source priority

1. **Official vendor documentation** — authoritative for the vendor's own domains/IPs/protocol requirements.
2. **Official regulator lookup** — authoritative for point checks, but not usable as a public bulk feed for ordinary users.
3. **Multiple community block aggregators** — operational evidence of restrictions; never trusted alone.
4. **Service-classification repositories** — useful for grouping domains, but not evidence that something is blocked.
5. **Runtime observations** — DNS/connection/service probes on the user's own network, used to choose routes.

## Initial providers

### Roskomnadzor unified registry

- Purpose: point verification.
- Use: reference/manual verification only.
- RAZVILKA must not pretend it is a public complete bulk feed.

### Re:filter

- `domains_all.lst`: filtered domain list.
- `ipsum.lst`: summarized IP/CIDR list.
- Use: primary operational block-list candidate after validation.
- Important: previous list-quality incidents are the reason RAZVILKA rejects malformed/TLD entries and never replaces a working cache before validation succeeds.

### RunetFreedom russia-blocked-geosite / russia-blocked-geoip

- Use: independent second aggregator and ready-made GeoSite/GeoIP/SRS/MRS ecosystem source.
- The repositories state that they rebuild automatically every six hours.
- Prefer service categories/domain rules where possible.

### v2fly/domain-list-community

- Use: service/domain classification (YouTube, Google, OpenAI, Discord, etc.).
- It explicitly does not claim a listed domain is blocked or should be proxied.
- Never use it as a block-status oracle.

### Vendor-specific feeds

- OpenAI network allowlist: source of ChatGPT/OpenAI service manifest data.
- Telegram `resources/cidr.txt`: source of Telegram-published IPv4/IPv6 ranges.
- More vendor feeds will be added per service when an official machine-readable source exists.

## Domain-first routing

Large services share Cloudflare, Google, AWS, Fastly and other CDN address space. Routing an entire provider subnet because one service uses an IP can hijack unrelated traffic.

Default policy:

```text
service domain rule
  > vendor-specific exact CIDR
  > independently-confirmed service CIDR
  > broad blocked-IP aggregate (opt-in / last resort)
```

## Validation pipeline

```text
HTTPS fetch
  → byte limit
  → syntax validation
  → normalize
  → remove duplicates
  → reject TLD-only / invalid domain entries
  → reject private/link-local/default/over-broad CIDRs
  → minimum-entry sanity threshold
  → SHA-256 of normalized cache
  → atomic rename
```

If any gate fails, RAZVILKA keeps the previous working cache.
