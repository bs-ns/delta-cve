> [!IMPORTANT]
> This tool had been vibecoded using cursor and tested with Claude Sonnet
> Although the human who was in the loop tested the result, he hasn't inspected closely the code right now

# delta-cve

CLI that lists CVEs with Red Hat errata for a given product and source package, using the [Red Hat Security Data API](https://access.redhat.com/hydra/rest/securitydata).

With `--since-version`, only CVEs whose matching fix has an RPM version strictly newer than the given version are printed. Give it the version-release exactly as `dnf`/`rpm -q` shows it (e.g. `1.1.1k-7.el8_6`), with no epoch prefix.

## Setup

Python 3 is required.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

The only runtime dependency is `requests` (`>=2.31.0`).

## Usage

```bash
python3 rhsec_cve.py --product "Red Hat Enterprise Linux 7" --package kernel
```

| Flag | Description |
| --- | --- |
| `--product` | Product name (required), e.g. `Red Hat Enterprise Linux 7` |
| `--package` | Source RPM name (required), e.g. `kernel` or `kernel-rt` |
| `--since-version` | Keep only CVEs fixed in a package version strictly newer than this RPM EVR |
| `--include-variants` | Also match EUS, ELS, RT, and related streams for the same major release |
| `--verbose` | Print CSAF pagination progress on stderr |
| `--limit` | Cap how many CVE lines printed |

### Examples

All fixed kernel CVEs with errata on RHEL 7:

```bash
python3 rhsec_cve.py \
  --product "Red Hat Enterprise Linux 7" \
  --package kernel
```

Only fixes newer than a given kernel EVR, with progress on stderr:

```bash
python3 rhsec_cve.py \
  --product "Red Hat Enterprise Linux 7" \
  --package kernel \
  --since-version 3.10.0-1160.el7 \
  --verbose
```

## How it works

1. Paginate `csaf.json?package=...` (advisory index).
2. For each RHSA, keep `released_packages` that match the source package name and the product's RHEL dist tag (`.el7`, `.el10_0`, `.el10_2`, …).
3. Prefer `.src` NEVRAs when present; keep the newest EVR for that advisory.
4. Attach the advisory's CVE list to that fix.
5. If `--since-version` is set, keep only advisories whose EVR is strictly greater than that value (local compare; no extra HTTP).

This avoids per-CVE detail fetches. Runtime is dominated by a modest number of CSAF list pages.

## Layout

| File | Role |
| --- | --- |
| `rhsec_cve.py` | CLI, CSAF query loop, and output |
| `rhsec_client.py` | HTTP client (retries, CSAF/CVE pagination) |
| `filters.py` | Package/dist-tag matching and helpers |
| `rpmver.py` | NEVRA version parsing and RPM-style EVR comparison |

## Limitations

- Product scope is inferred from NEVRA dist tags (`.el7`, `.el10_0`, …), not CSAF product names/CPEs. Some AltArch or atypical builds that share a dist tag may appear.
- Advisories without a matching per-package NEVRA are skipped.
- Base matching includes `.el{major}` and `.el{major}_{digits}` (RHEL 8+ GA/minor). `--include-variants` also allows letter-suffixed tags such as `.el7a`.
