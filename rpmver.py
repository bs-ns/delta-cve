"""RPM version parsing and comparison (rpmvercmp semantics)."""

from __future__ import annotations

import re
from typing import Optional

# Common RPM arches seen in Red Hat Security Data / CSAF package lists.
_KNOWN_ARCHES = frozenset(
    {
        "src",
        "nosrc",
        "noarch",
        "x86_64",
        "i386",
        "i686",
        "aarch64",
        "ppc64",
        "ppc64le",
        "s390x",
        "armv7hl",
    }
)


def parse_nevra_version(package: str) -> Optional[str]:
    """Extract the EVR string from a NEVRA like kernel-0:3.10.0-1160.132.1.el7.x86_64."""
    if not package:
        return None

    match = re.match(r"^[^-]+-\d+:(.+)$", package)
    if match:
        return _strip_arch(match.group(1))

    if ":" in package:
        return _strip_arch(package.split(":", 1)[1])

    return None


def _strip_arch(evr_with_arch: str) -> str:
    if "." not in evr_with_arch:
        return evr_with_arch
    maybe_evr, maybe_arch = evr_with_arch.rsplit(".", 1)
    if maybe_arch in _KNOWN_ARCHES:
        return maybe_evr
    return evr_with_arch


def _split_evr(value: str) -> tuple[int, str, str]:
    """Split an EVR into (epoch, version, release)."""
    epoch = 0
    rest = value

    if ":" in rest:
        epoch_part, maybe_rest = rest.split(":", 1)
        if epoch_part.isdigit():
            epoch = int(epoch_part)
            rest = maybe_rest

    if "-" in rest:
        version, release = rest.split("-", 1)
    else:
        version, release = rest, ""

    return epoch, version, release


def _rpmvercmp(a: str, b: str) -> int:
    """Compare two RPM version or release strings. Returns -1, 0, or 1.

    Mirrors rpmvercmp: walk alphanumeric segments; digits beat letters;
    non-alphanumeric separators are skipped.
    """
    while a or b:
        a = _lstrip_separators(a)
        b = _lstrip_separators(b)

        if not a and not b:
            return 0
        if not a:
            return -1
        if not b:
            return 1

        a_is_num = a[0].isdigit()
        b_is_num = b[0].isdigit()

        if a_is_num != b_is_num:
            # Numeric segments are newer than alphabetic ones.
            return 1 if a_is_num else -1

        if a_is_num:
            a_seg, a = _split_num_str(a)
            b_seg, b = _split_num_str(b)
            a_val = int(a_seg)
            b_val = int(b_seg)
            if a_val > b_val:
                return 1
            if a_val < b_val:
                return -1
        else:
            a_seg, a = _split_alpha(a)
            b_seg, b = _split_alpha(b)
            if a_seg > b_seg:
                return 1
            if a_seg < b_seg:
                return -1

    return 0


def _lstrip_separators(value: str) -> str:
    index = 0
    while index < len(value) and not value[index].isalnum():
        index += 1
    return value[index:]


def _split_alpha(value: str) -> tuple[str, str]:
    match = re.match(r"^[a-zA-Z]+", value)
    if not match:
        return "", value
    return match.group(0), value[len(match.group(0)) :]


def _split_num_str(value: str) -> tuple[str, str]:
    match = re.match(r"^\d+", value)
    if not match:
        return "0", value
    return match.group(0), value[len(match.group(0)) :]


def compare_versions(left: str, right: str) -> int:
    """Compare RPM EVR strings like 0:3.10.0-1160.1.el7 or 3.10.0-1160.el7."""
    left_epoch, left_version, left_release = _split_evr(left)
    right_epoch, right_version, right_release = _split_evr(right)

    if left_epoch > right_epoch:
        return 1
    if left_epoch < right_epoch:
        return -1

    version_cmp = _rpmvercmp(left_version, right_version)
    if version_cmp != 0:
        return version_cmp

    return _rpmvercmp(left_release, right_release)


def version_gt(left: str, right: str) -> bool:
    return compare_versions(left, right) > 0


def version_gte(left: str, right: str) -> bool:
    return compare_versions(left, right) >= 0
