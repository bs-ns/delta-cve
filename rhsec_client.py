"""Client for the Red Hat Security Data API."""

from __future__ import annotations

import time
from typing import Callable, Iterator, Optional

import requests


BASE_URL = "https://access.redhat.com/hydra/rest/securitydata"
DEFAULT_HEADERS = {
    "User-Agent": "delta-cve/1.0 (Red Hat Security Data API client)",
    "Accept": "application/json",
}
DEFAULT_PER_PAGE = 1000
MAX_RETRIES = 3
RETRY_BACKOFF_SECONDS = 1.5


class RhsecClient:
    def __init__(
        self,
        session: Optional[requests.Session] = None,
        per_page: int = DEFAULT_PER_PAGE,
        verbose: bool = False,
    ) -> None:
        self.session = session or requests.Session()
        self.session.headers.update(DEFAULT_HEADERS)
        self.per_page = per_page
        self.verbose = verbose

    def _get_json(self, path: str, params: Optional[dict] = None) -> object:
        url = f"{BASE_URL}/{path.lstrip('/')}"
        last_error: Optional[Exception] = None

        for attempt in range(1, MAX_RETRIES + 1):
            try:
                response = self.session.get(url, params=params, timeout=60)
                response.raise_for_status()
                return response.json()
            except (requests.RequestException, ValueError) as exc:
                last_error = exc
                if attempt == MAX_RETRIES:
                    break
                sleep_for = RETRY_BACKOFF_SECONDS * attempt
                if self.verbose:
                    print(f"Retrying {url} after error: {exc} (sleep {sleep_for:.1f}s)")
                time.sleep(sleep_for)

        raise RuntimeError(f"Failed to fetch {url}: {last_error}") from last_error

    def iter_csaf_summaries(
        self,
        package: str,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> Iterator[dict]:
        page = 1

        while True:
            params = {
                "package": package,
                "page": page,
                "per_page": self.per_page,
                "isCompressed": "false",
            }
            data = self._get_json("csaf.json", params=params)

            if not isinstance(data, list):
                raise RuntimeError(f"Unexpected CSAF list response on page {page}")

            if not data:
                break

            if progress_callback:
                progress_callback(page, len(data))

            yield from data

            if len(data) < self.per_page:
                break

            page += 1
