import re
from dataclasses import dataclass, field
from typing import List, Optional


# Curated offline vulnerability database for common front-end libraries.
# A version v is affected by an entry when introduced <= v < fixed.
# This is NOT an exhaustive CVE scan — it covers well-known issues only.
KNOWN_VULNERABILITIES = {
    "jquery": [
        {"fixed": "1.9.0", "id": "CVE-2012-6708", "severity": "medium",
         "desc": "選擇器解析造成的 XSS"},
        {"fixed": "3.0.0", "id": "CVE-2015-9251", "severity": "medium",
         "desc": "跨網域 ajax 回應造成的 XSS"},
        {"fixed": "3.4.0", "id": "CVE-2019-11358", "severity": "medium",
         "desc": "$.extend 原型污染 (prototype pollution)"},
        {"fixed": "3.5.0", "id": "CVE-2020-11022", "severity": "medium",
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
        {"fixed": "4.17.12", "id": "CVE-2019-10744", "severity": "high",
         "desc": "defaultsDeep 原型污染"},
        {"fixed": "4.17.19", "id": "CVE-2020-8203", "severity": "high",
         "desc": "zipObjectDeep 原型污染"},
        {"fixed": "4.17.21", "id": "CVE-2021-23337", "severity": "high",
         "desc": "template 函式的指令注入"},
    ],
    "moment": [
        {"fixed": "2.19.3", "id": "CVE-2017-18214", "severity": "medium",
         "desc": "字串解析造成的 ReDoS"},
        {"fixed": "2.29.4", "id": "CVE-2022-31129", "severity": "high",
         "desc": "字串解析造成的 ReDoS"},
    ],
    "axios": [
        {"fixed": "0.21.4", "id": "CVE-2021-3749", "severity": "medium",
         "desc": "trim 正規表達式造成的 ReDoS"},
        {"fixed": "1.6.0", "id": "CVE-2023-45857", "severity": "medium",
         "desc": "XSRF token 經由跨網域請求洩漏"},
    ],
    "angular": [
        {"fixed": "1.7.9", "id": "CVE-2019-10768", "severity": "medium",
         "desc": "AngularJS merge 原型污染"},
        {"fixed": "1.8.0", "id": "CVE-2020-7676", "severity": "medium",
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

SEVERITY_ICONS = {"high": "🔴", "medium": "🟠", "low": "🟡"}

# package@version  (jsdelivr/unpkg style, optionally /npm/ prefixed, optional @scope)
_PAT_AT_VERSION = re.compile(r'/(?:npm/)?(@?[\w.-]+(?:/[\w.-]+)?)@(\d[\w.\-]*)')
# /<pkg>/<version>/  (cdnjs and bootstrapcdn style, requires full x.y.z version)
_PAT_PATH_VERSION = re.compile(r'/([\w.-]+)/v?(\d+\.\d+\.\d+)(?:/|$)')
# filename like jquery-3.4.1.min.js
_PAT_FILENAME = re.compile(r'/([\w]+?)[-.]v?(\d+\.\d+(?:\.\d+)?)\.(?:min\.|slim\.)*(?:js|css)\b')


@dataclass
class Dependency:
    name: str
    version: Optional[str]
    source: str
    kind: str
    vulnerabilities: List[dict] = field(default_factory=list)


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
        for vuln in KNOWN_VULNERABILITIES.get(db_key, []):
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
