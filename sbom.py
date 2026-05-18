import json
import re
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional


# Fallback offline vulnerability database, used when OSV.dev is unreachable.
# A version v is affected by an entry when introduced <= v < fixed.
STATIC_VULNERABILITIES = {
    "jquery": [
        {"introduced": "0", "fixed": "1.9.0", "id": "CVE-2012-6708", "severity": "medium",
         "desc": "選擇器解析造成的 XSS"},
        {"introduced": "0", "fixed": "3.0.0", "id": "CVE-2015-9251", "severity": "medium",
         "desc": "跨網域 ajax 回應造成的 XSS"},
        {"introduced": "0", "fixed": "3.4.0", "id": "CVE-2019-11358", "severity": "medium",
         "desc": "$.extend 原型污染 (prototype pollution)"},
        {"introduced": "0", "fixed": "3.5.0", "id": "CVE-2020-11022", "severity": "medium",
         "desc": "htmlPrefilter 處理 HTML 造成的 XSS"},
    ],
    "bootstrap": [
        {"introduced": "3.0.0", "fixed": "3.4.0", "id": "CVE-2018-14041", "severity": "medium",
         "desc": "data-target 屬性造成的 XSS"},
        {"introduced": "3.0.0", "fixed": "3.4.1", "id": "CVE-2019-8331", "severity": "medium",
         "desc": "tooltip/popover 的 XSS"},
        {"introduced": "4.0.0", "fixed": "4.3.1", "id": "CVE-2019-8331", "severity": "medium",
         "desc": "tooltip/popover 的 XSS"},
    ],
    "lodash": [
        {"introduced": "0", "fixed": "4.17.12", "id": "CVE-2019-10744", "severity": "high",
         "desc": "defaultsDeep 原型污染"},
        {"introduced": "0", "fixed": "4.17.19", "id": "CVE-2020-8203", "severity": "high",
         "desc": "zipObjectDeep 原型污染"},
        {"introduced": "0", "fixed": "4.17.21", "id": "CVE-2021-23337", "severity": "high",
         "desc": "template 函式的指令注入"},
    ],
    "moment": [
        {"introduced": "0", "fixed": "2.19.3", "id": "CVE-2017-18214", "severity": "medium",
         "desc": "字串解析造成的 ReDoS"},
        {"introduced": "0", "fixed": "2.29.4", "id": "CVE-2022-31129", "severity": "high",
         "desc": "字串解析造成的 ReDoS"},
    ],
    "axios": [
        {"introduced": "0", "fixed": "0.21.4", "id": "CVE-2021-3749", "severity": "medium",
         "desc": "trim 正規表達式造成的 ReDoS"},
        {"introduced": "0", "fixed": "1.6.0", "id": "CVE-2023-45857", "severity": "medium",
         "desc": "XSRF token 經由跨網域請求洩漏"},
    ],
    "angular": [
        {"introduced": "0", "fixed": "1.7.9", "id": "CVE-2019-10768", "severity": "medium",
         "desc": "AngularJS merge 原型污染"},
        {"introduced": "0", "fixed": "1.8.0", "id": "CVE-2020-7676", "severity": "medium",
         "desc": "AngularJS 經由 SVG 的 XSS"},
    ],
}

# Map detected names to vulnerability-DB keys.
_NAME_ALIASES = {
    "jquery": "jquery",
    "bootstrap": "bootstrap",
    "lodash": "lodash",
    "moment": "moment",
    "axios": "axios",
    "angular": "angular",
    "angularjs": "angular",
    "angular.js": "angular",
}

# npm package name queried from OSV.dev for each tracked library.
TRACKED_PACKAGES = {
    "jquery": "jquery",
    "bootstrap": "bootstrap",
    "lodash": "lodash",
    "moment": "moment",
    "axios": "axios",
    "angular": "angular",
}

OSV_API_URL = "https://api.osv.dev/v1/query"

SEVERITY_ICONS = {"high": "🔴", "medium": "🟠", "low": "🟡"}

# package@version  (jsdelivr/unpkg style, optionally /npm/ prefixed, optional @scope)
_PAT_AT_VERSION = re.compile(r'/(?:npm/)?(@?[\w.-]+(?:/[\w.-]+)?)@(\d[\w.\-]*)')
# /<pkg>/<version>/  (cdnjs and bootstrapcdn style, requires full x.y.z version)
_PAT_PATH_VERSION = re.compile(r'/([\w.-]+)/v?(\d+\.\d+\.\d+)(?:/|$)')
# filename like jquery-3.4.1.min.js
_PAT_FILENAME = re.compile(r'/([\w]+?)[-.]v?(\d+\.\d+(?:\.\d+)?)\.(?:min\.|slim\.)*(?:js|css)\b')

# Active vulnerability DB; refreshed from OSV.dev at startup, falls back to static.
_active_db = {k: list(v) for k, v in STATIC_VULNERABILITIES.items()}
_db_metadata = {"source": "內建靜態清單（尚未更新）", "updated_at": None}


@dataclass
class Dependency:
    name: str
    version: Optional[str]
    source: str
    kind: str
    vulnerabilities: List[dict] = field(default_factory=list)


def get_db_metadata() -> dict:
    return dict(_db_metadata)


def _clean_name(raw: str) -> str:
    name = raw.lower().rsplit("/", 1)[-1]
    name = re.sub(r'\.(min|slim|bundle|esm|umd|core)$', '', name)
    return name


def _version_tuple(v: str):
    parts = re.findall(r'\d+', v)
    while len(parts) < 3:
        parts.append("0")
    return tuple(int(p) for p in parts[:3])


def _is_precise(v: Optional[str]) -> bool:
    return bool(v) and len(re.findall(r'\d+', v)) >= 3


def parse_resource(url: str, kind: str) -> Dependency:
    name, version = None, None
    for pattern in (_PAT_AT_VERSION, _PAT_FILENAME, _PAT_PATH_VERSION):
        match = pattern.search(url)
        if match:
            name = _clean_name(match.group(1))
            version = match.group(2)
            break
    if name is None:
        segment = url.rstrip("/").rsplit("/", 1)[-1]
        segment = re.sub(r'\.(js|css|mjs)(\?.*)?$', '', segment)
        name = _clean_name(segment) or url

    dep = Dependency(name=name, version=version, source=url, kind=kind)

    db_key = _NAME_ALIASES.get(name)
    if db_key and _is_precise(version):
        vt = _version_tuple(version)
        for vuln in _active_db.get(db_key, []):
            introduced = _version_tuple(vuln.get("introduced", "0"))
            fixed = _version_tuple(vuln["fixed"])
            if introduced <= vt < fixed:
                dep.vulnerabilities.append(vuln)
    return dep


def analyze_dependencies(resources: List[tuple]) -> List[Dependency]:
    deps = []
    seen = set()
    for url, kind in resources:
        if not url or url in seen:
            continue
        seen.add(url)
        deps.append(parse_resource(url, kind))
    return deps


def _osv_query(npm_name: str, timeout: float) -> dict:
    payload = json.dumps({"package": {"name": npm_name, "ecosystem": "npm"}}).encode("utf-8")
    req = urllib.request.Request(
        OSV_API_URL, data=payload,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _severity_label(vuln: dict) -> str:
    raw = str((vuln.get("database_specific") or {}).get("severity", "")).upper()
    return {"LOW": "low", "MODERATE": "medium", "MEDIUM": "medium",
            "HIGH": "high", "CRITICAL": "high"}.get(raw, "medium")


def _parse_osv_vuln(vuln: dict, npm_name: str) -> List[dict]:
    entries = []
    cve = next((a for a in vuln.get("aliases", []) if a.startswith("CVE-")), None)
    vid = cve or vuln.get("id", "UNKNOWN")
    desc = (vuln.get("summary") or vuln.get("details") or "").strip().replace("\n", " ")
    if len(desc) > 80:
        desc = desc[:77] + "..."
    severity = _severity_label(vuln)

    for affected in vuln.get("affected", []):
        pkg = affected.get("package", {})
        if pkg.get("ecosystem") != "npm" or pkg.get("name") != npm_name:
            continue
        for rng in affected.get("ranges", []):
            if rng.get("type") not in ("SEMVER", "ECOSYSTEM"):
                continue
            introduced = "0"
            for event in rng.get("events", []):
                if "introduced" in event:
                    introduced = event["introduced"]
                elif "fixed" in event:
                    entries.append({
                        "introduced": introduced, "fixed": event["fixed"],
                        "id": vid, "severity": severity, "desc": desc,
                    })
                    introduced = "0"
    return entries


def _dedupe(entries: List[dict]) -> List[dict]:
    seen, result = set(), []
    for e in entries:
        key = (e["id"], e["introduced"], e["fixed"])
        if key not in seen:
            seen.add(key)
            result.append(e)
    return result


def refresh_vulnerability_db(timeout: float = 6.0) -> dict:
    """Query OSV.dev for tracked packages and rebuild the active DB.

    Per-package failures fall back to the static DB for that package only.
    Runs all queries concurrently so total wait is roughly one timeout.
    """
    global _active_db, _db_metadata

    def fetch(item):
        our_key, npm_name = item
        try:
            data = _osv_query(npm_name, timeout)
        except Exception:
            return our_key, None
        entries = []
        for vuln in data.get("vulns", []):
            entries.extend(_parse_osv_vuln(vuln, npm_name))
        return our_key, _dedupe(entries)

    new_db = {k: list(v) for k, v in STATIC_VULNERABILITIES.items()}
    ok = 0
    with ThreadPoolExecutor(max_workers=len(TRACKED_PACKAGES)) as ex:
        for our_key, entries in ex.map(fetch, TRACKED_PACKAGES.items()):
            if entries is None:
                continue
            ok += 1
            if entries:
                new_db[our_key] = entries

    total = len(TRACKED_PACKAGES)
    if ok == total:
        source = "OSV.dev 線上資料庫"
    elif ok > 0:
        source = f"OSV.dev 線上資料庫（部分更新 {ok}/{total}，其餘使用內建備援）"
    else:
        source = "內建靜態清單（OSV.dev 連線失敗，已使用備援）"

    _active_db = new_db
    _db_metadata = {
        "source": source,
        "updated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    }
    return dict(_db_metadata)
