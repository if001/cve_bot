#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Iterable

import requests
import yaml


NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_TIMEOUT_SEC = 20
MAX_RETRIES = 3


@dataclass(frozen=True)
class CvssInfo:
    version: str
    base_score: float | None
    severity: str | None


@dataclass(frozen=True)
class CveItem:
    cve_id: str
    published: str
    cvss: CvssInfo
    summary: str
    tags: list[str]
    references: list[str]
    nvd_url: str


def _isoformat_z(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _load_watchlist(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    data.setdefault("queries", [])
    data.setdefault("tag_rules", {})
    return data


def _request_with_retry(url: str, params: dict, headers: dict) -> dict:
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            response = requests.get(
                url,
                params=params,
                headers=headers,
                timeout=NVD_TIMEOUT_SEC,
            )
        except requests.RequestException as exc:
            if attempt == MAX_RETRIES:
                raise RuntimeError(f"NVD request failed: {exc}") from exc
            time.sleep(2**attempt)
            continue

        if response.status_code in {429, 500, 502, 503, 504}:
            if attempt == MAX_RETRIES:
                response.raise_for_status()
            time.sleep(2**attempt)
            continue

        response.raise_for_status()
        return response.json()

    raise RuntimeError("NVD request failed after retries.")


def _extract_cvss(cve: dict) -> CvssInfo:
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if not entries:
            continue
        cvss_data = (entries[0] or {}).get("cvssData", {})
        version = str(cvss_data.get("version", ""))
        base_score = cvss_data.get("baseScore")
        severity = cvss_data.get("baseSeverity")
        return CvssInfo(version=version, base_score=base_score, severity=severity)
    return CvssInfo(version="N/A", base_score=None, severity=None)


def _extract_summary(cve: dict) -> str:
    descriptions = cve.get("descriptions", [])
    for entry in descriptions:
        if entry.get("lang") == "en" and entry.get("value"):
            return entry["value"].strip()
    if descriptions:
        return (descriptions[0] or {}).get("value", "").strip()
    return ""


def _extract_references(cve: dict, limit: int = 3) -> list[str]:
    refs = cve.get("references", []) or []
    urls = [ref.get("url") for ref in refs if ref.get("url")]
    return urls[:limit]


def _tag_item(summary: str, references: Iterable[str], tag_rules: dict) -> list[str]:
    corpus = " ".join([summary, *references]).lower()
    tags = []
    for tag, keywords in tag_rules.items():
        if any(keyword.lower() in corpus for keyword in keywords or []):
            tags.append(tag)
    return tags


def _normalize_item(cve: dict, tag_rules: dict) -> CveItem:
    cve_id = cve.get("id") or "UNKNOWN"
    published = cve.get("published") or cve.get("lastModified") or ""
    summary = _extract_summary(cve)
    references = _extract_references(cve)
    cvss = _extract_cvss(cve)
    tags = _tag_item(summary, references, tag_rules)
    nvd_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    return CveItem(
        cve_id=cve_id,
        published=published,
        cvss=cvss,
        summary=summary,
        tags=tags,
        references=references,
        nvd_url=nvd_url,
    )


def _fetch_cves(queries: list[str], api_key: str | None, hours_back: int) -> list[CveItem]:
    now = datetime.now(timezone.utc)
    start = now - timedelta(hours=hours_back)
    params_base = {
        "pubStartDate": _isoformat_z(start),
        "pubEndDate": _isoformat_z(now),
    }
    headers = {"User-Agent": "cve-bot/0.1"}
    if api_key:
        headers["apiKey"] = api_key

    items: dict[str, CveItem] = {}
    tag_rules = _load_watchlist(WATCHLIST_PATH).get("tag_rules", {})

    for query in queries:
        for severity in ("HIGH", "CRITICAL"):
            params = {
                **params_base,
                "keywordSearch": query,
                "cvssV3Severity": severity,
            }
            data = _request_with_retry(NVD_API_BASE, params, headers)
            for entry in data.get("vulnerabilities", []) or []:
                cve = (entry or {}).get("cve", {})
                if not cve:
                    continue
                item = _normalize_item(cve, tag_rules)
                items[item.cve_id] = item

    return sorted(items.values(), key=lambda item: item.published, reverse=True)


def _load_posted(path: str) -> set[str]:
    if not os.path.exists(path):
        return set()
    with open(path, "r", encoding="utf-8") as handle:
        try:
            data = json.load(handle)
        except json.JSONDecodeError:
            return set()
    return set(data.get("cve_ids", []))


def _save_posted(path: str, cve_ids: Iterable[str]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    payload = {
        "posted_at": _isoformat_z(datetime.now(timezone.utc)),
        "cve_ids": sorted(set(cve_ids)),
    }
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=True)
        handle.write("\n")


def _format_message(item: CveItem) -> str:
    cvss_part = "N/A"
    if item.cvss.base_score is not None:
        cvss_part = f"{item.cvss.base_score} ({item.cvss.severity})"
    tags_part = ", ".join(item.tags) if item.tags else "none"
    lines = [
        f"*{item.cve_id}*",
        f"Published: {item.published}",
        f"CVSS: {cvss_part}",
        f"Tags: {tags_part}",
        f"Summary: {item.summary[:300]}",
        f"NVD: {item.nvd_url}",
    ]
    if item.references:
        lines.append("References: " + ", ".join(item.references))
    return "\n".join(lines)


def _post_to_slack(webhook_url: str, text: str) -> None:
    response = requests.post(webhook_url, json={"text": text}, timeout=15)
    response.raise_for_status()


WATCHLIST_PATH = os.getenv("WATCHLIST_PATH", "watchlist.yml")
POSTED_PATH = os.getenv("POSTED_PATH", os.path.join("posted", "posted.json"))


def main() -> int:
    webhook_url = os.getenv("SLACK_WEBHOOK_URL")
    if not webhook_url:
        print("SLACK_WEBHOOK_URL is required.", file=sys.stderr)
        return 1

    watchlist = _load_watchlist(WATCHLIST_PATH)
    queries = watchlist.get("queries", [])
    if not queries:
        print("watchlist.yml has no queries.", file=sys.stderr)
        return 1

    hours_back = int(os.getenv("HOURS_BACK", "24"))
    api_key = os.getenv("NVD_API_KEY")

    try:
        items = _fetch_cves(queries, api_key, hours_back)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    posted_ids = _load_posted(POSTED_PATH)
    to_post = [item for item in items if item.cve_id not in posted_ids]

    if not to_post:
        print("No new CVEs to post.")
        return 0

    posted_now = set(posted_ids)
    for item in to_post:
        try:
            _post_to_slack(webhook_url, _format_message(item))
        except requests.RequestException as exc:
            print(f"Slack post failed for {item.cve_id}: {exc}", file=sys.stderr)
            break
        else:
            posted_now.add(item.cve_id)

    _save_posted(POSTED_PATH, posted_now)
    print(f"Posted {len(posted_now) - len(posted_ids)} CVEs.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
