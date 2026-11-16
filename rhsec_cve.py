#!/usr/bin/env python3
"""Query fixed CVEs for a Red Hat product/package via the Security Data API."""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from typing import Optional

from filters import (
    find_matching_csaf_packages,
    pick_best_csaf_package,
)
from rpmver import compare_versions
from rhsec_client import RhsecClient


@dataclass
class QueryResult:
    cve: str
    advisory: str
    package: str
    version: str
    product_name: str


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Query the Red Hat Security Data API for fixed CVEs (with errata) "
            "affecting a given package on a given product."
        ),
        epilog=(
            "Notes:\n"
            "  - Scans the CSAF advisory index (package NEVRAs + CVE lists), not\n"
            "    per-CVE detail documents, so runs stay relatively fast.\n"
            "  - Product scope is inferred from RHEL dist tags in NEVRAs (.el7,\n"
            "    .el10_0, .el10_2, …). Use --include-variants for letter-suffixed\n"
            "    tags such as .el7a.\n"
            "  - Advisories without a matching per-package NEVRA are skipped."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--product",
        required=True,
        help='Product name or regex, e.g. "Red Hat Enterprise Linux 7"',
    )
    parser.add_argument(
        "--package",
        required=True,
        help='Source RPM name, e.g. "kernel" or "kernel-rt"',
    )
    parser.add_argument(
        "--since-version",
        help=(
            "Only include CVEs fixed in a package version strictly newer than this "
            "version-release, exactly as shown by dnf/rpm -q (e.g. 1.1.1k-7.el8_6, "
            "no epoch prefix)"
        ),
    )
    parser.add_argument(
        "--include-variants",
        action="store_true",
        help="Also match letter-suffixed dist tags (e.g. .el7a)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show CSAF pagination progress on stderr",
    )
    parser.add_argument(
        "--limit",
        type=int,
        help="Limit the number of CVE lines printed",
    )
    return parser.parse_args(argv)


def log(verbose: bool, message: str) -> None:
    if verbose:
        print(message, file=sys.stderr)


def _keep_newest(existing: Optional[QueryResult], candidate: QueryResult) -> QueryResult:
    if existing is None:
        return candidate
    if compare_versions(candidate.version, existing.version) > 0:
        return candidate
    return existing


def query_fixed_cves(
    client: RhsecClient,
    product: str,
    package: str,
    include_variants: bool,
    since_version: Optional[str],
    verbose: bool,
) -> tuple[list[QueryResult], list[QueryResult]]:
    fixed_by_cve: dict[str, QueryResult] = {}
    since_by_cve: dict[str, QueryResult] = {}
    matched_advisories = 0

    def list_progress(page: int, count: int) -> None:
        log(verbose, f"Fetched CSAF page {page} ({count} entries)")

    for advisory in client.iter_csaf_summaries(package, list_progress):
        rhsa = advisory.get("RHSA")
        cves = advisory.get("CVEs") or []
        released_packages = advisory.get("released_packages") or []

        if not rhsa or not cves:
            continue

        matches = find_matching_csaf_packages(
            released_packages=released_packages,
            product=product,
            package=package,
            include_variants=include_variants,
        )
        if not matches:
            continue

        best_package, best_version = pick_best_csaf_package(matches)
        matched_advisories += 1
        newer_than_since = (
            since_version is not None
            and compare_versions(best_version, since_version) > 0
        )

        for cve_id in cves:
            if not isinstance(cve_id, str) or not cve_id:
                continue

            result = QueryResult(
                cve=cve_id,
                advisory=rhsa,
                package=best_package,
                version=best_version,
                product_name=product,
            )
            fixed_by_cve[cve_id] = _keep_newest(fixed_by_cve.get(cve_id), result)
            if newer_than_since:
                since_by_cve[cve_id] = _keep_newest(since_by_cve.get(cve_id), result)

    log(verbose, f"Matched {matched_advisories} advisories for {product} / {package}")

    fixed_results = sorted(fixed_by_cve.values(), key=lambda item: item.cve)
    since_results = sorted(since_by_cve.values(), key=lambda item: item.cve)
    return fixed_results, since_results


def print_results(
    product: str,
    package: str,
    include_variants: bool,
    fixed_results: list[QueryResult],
    since_results: list[QueryResult],
    since_version: Optional[str],
    limit: Optional[int],
) -> None:
    scope = "base + variants" if include_variants else "base"
    print(f"Product: {product} ({scope})")
    print(f"Package: {package}")
    print(f"Fixed CVEs with errata: {len(fixed_results)}")

    if since_version:
        print(f"\nCVEs fixed since {since_version}: {len(since_results)}")
        output = since_results
    else:
        print()
        output = fixed_results

    printed = 0
    for result in output:
        print(f"{result.cve} ({result.advisory}, {result.package})")
        printed += 1
        if limit is not None and printed >= limit:
            remaining = len(output) - printed
            if remaining > 0:
                print(f"... {remaining} more not shown (use --limit to adjust)")
            break


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    client = RhsecClient(verbose=args.verbose)

    try:
        fixed_results, since_results = query_fixed_cves(
            client=client,
            product=args.product,
            package=args.package,
            include_variants=args.include_variants,
            since_version=args.since_version,
            verbose=args.verbose,
        )
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print_results(
        product=args.product,
        package=args.package,
        include_variants=args.include_variants,
        fixed_results=fixed_results,
        since_results=since_results,
        since_version=args.since_version,
        limit=args.limit,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
