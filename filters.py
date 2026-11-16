"""Product scope and package matching for Red Hat Security Data API records."""

from __future__ import annotations

import re
from typing import Iterable, Optional

from rpmver import compare_versions, parse_nevra_version


def extract_major_version(product: str) -> Optional[str]:
    match = re.search(r"(\d+)\s*$", product.strip())
    if match:
        return match.group(1)
    return None


def package_matches(package_field: str, requested_package: str) -> bool:
    if not package_field:
        return False

    pattern = rf"^{re.escape(requested_package)}-\d+:"
    return re.match(pattern, package_field) is not None


def dist_tag_matches(package_field: str, major: str, include_variants: bool) -> bool:
    """Match RHEL dist tags in a NEVRA.

    Base includes classic tags (.el7) and modern GA/minor tags (.el10_0, .el10_2).
    --include-variants also allows letter-suffixed tags (e.g. .el7a).
    """
    # .el7 / .el10_0 / .el10_2, then .arch or end of string.
    if re.search(rf"\.el{re.escape(major)}(?:_\d+)?(?:\.|$)", package_field):
        return True
    if include_variants:
        return re.search(rf"\.el{re.escape(major)}[a-zA-Z]", package_field) is not None
    return False


def find_matching_csaf_packages(
    released_packages: Iterable[str],
    product: str,
    package: str,
    include_variants: bool,
) -> list[tuple[str, str]]:
    """Return (nevra, evr) pairs from a CSAF advisory that match package + product stream."""
    major = extract_major_version(product)
    if not major:
        return []

    matches: list[tuple[str, str]] = []
    for package_field in released_packages:
        if not package_matches(package_field, package):
            continue
        if not dist_tag_matches(package_field, major, include_variants):
            continue
        version = parse_nevra_version(package_field)
        if not version:
            continue
        matches.append((package_field, version))

    return matches


def pick_best_csaf_package(packages: list[tuple[str, str]]) -> tuple[str, str]:
    """Prefer .src NEVRAs and the EVR shared by the most packages (then newest)."""
    if not packages:
        raise ValueError("packages must not be empty")

    src_packages = [item for item in packages if item[0].endswith(".src")]
    candidates = src_packages or packages

    counts: dict[str, int] = {}
    for _, version in candidates:
        counts[version] = counts.get(version, 0) + 1

    max_count = max(counts.values())
    top_versions = [version for version, count in counts.items() if count == max_count]
    best_version = top_versions[0]
    for version in top_versions[1:]:
        if compare_versions(version, best_version) > 0:
            best_version = version

    for package_field, version in candidates:
        if version == best_version:
            return package_field, version

    return candidates[0]
