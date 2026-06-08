# Demo 01 - Basic merge

You ran three different subdomain enumeration tools against an **authorized**
scope (`example.com`) and each wrote its own output file. They overlap, use
inconsistent formatting (schemes, ports, wildcards, mixed case), and include
stray out-of-scope and malformed lines. SUBHUNT merges them into one clean,
deduplicated, in-scope set with provenance.

## Inputs

- `subfinder.txt` - plain `host` per line, some with `https://` and ports.
- `amass.txt` - `host,ip` style (host is first CSV field), wildcards, comments.
- `assetfinder.txt` - mixed case, trailing dots, an out-of-scope host and junk.

## Run

Merge all sources, restrict to scope, emit JSON:

```bash
python -m subhunt merge demos/01-basic -s example.com -f json
```

Human-readable table:

```bash
python -m subhunt merge demos/01-basic -s example.com
```

## What to expect

- Duplicates collapsed; `www.example.com` and friends appear once with all
  reporting sources listed.
- `https://api.example.com:8443/` normalizes to `api.example.com`.
- `*.dev.example.com` normalizes to `dev.example.com`.
- `evil-corp.com` (out of scope) and `not a host` (invalid) are dropped and
  counted in the stats header.
- Exit code is `1` because findings were produced (pipeline-friendly).
