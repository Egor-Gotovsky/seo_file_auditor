from __future__ import annotations

import csv
import datetime as dt
import gzip
import io
import re
import time
import urllib.parse
import urllib.robotparser
import xml.etree.ElementTree as ET
from dataclasses import dataclass, asdict
from difflib import SequenceMatcher
from typing import Dict, Iterable, List, Optional, Tuple

import httpx
from bs4 import BeautifulSoup


DEFAULT_HEADERS = {
    "User-Agent": "SEOFileAuditor/0.3 (+local audit tool)",
    "Accept": "text/html,application/xhtml+xml,application/xml,text/xml;q=0.9,*/*;q=0.8",
}

COMMON_SITEMAP_PATHS = [
    "/sitemap.xml",
    "/sitemap_index.xml",
    "/wp-sitemap.xml",
    "/sitemap-index.xml",
]

SENSITIVE_PATHS = [
    "/.env",
    "/wp-config.php",
    "/composer.json",
    "/.git/config",
]

REDIRECT_STATUSES = {301, 302, 303, 307, 308}


@dataclass
class RobotsResult:
    url: str
    status_code: Optional[int]
    exists: bool
    size_bytes: int
    sitemaps: List[str]
    user_agents: List[str]
    groups: List[Dict[str, object]]
    directives: List[Dict[str, object]]
    raw_groups: List[Dict[str, object]]
    rules_total: int
    warnings: List[str]
    raw_text: str = ""
    error: Optional[str] = None


@dataclass
class SitemapResult:
    sitemap_url: str
    status_code: Optional[int]
    type: str
    urls_found: int
    urls_checked: int
    nested_sitemaps: List[str]
    warnings: List[str]
    error: Optional[str] = None


@dataclass
class PageResult:
    url: str
    status_code: Optional[int]
    final_url: Optional[str]
    redirect_count: int
    blocked_googlebot: Optional[bool]
    blocked_yandexbot: Optional[bool]
    title: str
    title_len: int
    description: str
    description_len: int
    h1_count: int
    h1_text: str
    canonical: str
    meta_robots: str
    html_warnings: List[str]
    error: Optional[str] = None


# ----------------------------- Common helpers -----------------------------


def normalize_base_url(raw_url: str) -> str:
    raw_url = (raw_url or "").strip()
    if not raw_url:
        raise ValueError("Введите домен или URL")

    if not re.match(r"^https?://", raw_url, re.I):
        raw_url = "https://" + raw_url

    parsed = urllib.parse.urlparse(raw_url)
    if not parsed.netloc:
        raise ValueError("Не удалось определить домен")

    return f"{parsed.scheme}://{parsed.netloc}".rstrip("/")


def normalize_any_url(raw_url: str) -> str:
    raw_url = (raw_url or "").strip()
    if not raw_url:
        raise ValueError("Введите URL")
    if not re.match(r"^https?://", raw_url, re.I):
        raw_url = "https://" + raw_url
    parsed = urllib.parse.urlparse(raw_url)
    if not parsed.netloc:
        raise ValueError("Не удалось определить домен")
    return urllib.parse.urlunparse(parsed)


def absolutize(base_url: str, value: str) -> str:
    return urllib.parse.urljoin(base_url.rstrip("/") + "/", value.strip())


def fetch(
    client: httpx.Client,
    url: str,
    *,
    follow_redirects: bool = True,
    timeout: float = 15.0,
) -> Tuple[Optional[httpx.Response], Optional[str]]:
    try:
        response = client.get(url, follow_redirects=follow_redirects, timeout=timeout)
        return response, None
    except httpx.RequestError as exc:
        return None, str(exc)


def decode_upload(uploaded_file) -> str:
    if uploaded_file is None:
        return ""
    raw = uploaded_file.getvalue()
    if isinstance(raw, str):
        return raw
    for encoding in ("utf-8-sig", "utf-8", "cp1251"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


def strip_xml_namespace(tag: str) -> str:
    return tag.split("}", 1)[-1].lower()


# ------------------------------- robots.txt -------------------------------


def parse_robots_text(text: str, base_url: str = "") -> Dict[str, object]:
    """Parse robots.txt into SEO-friendly structures.

    The parser is practical, not a complete RFC implementation. It is built for
    audits: directives, groups, syntax hints and rule-level URL checks.
    """
    sitemaps: List[str] = []
    user_agents: List[str] = []
    directives: List[Dict[str, object]] = []
    warnings: List[str] = []
    groups: List[Dict[str, object]] = []
    raw_groups: List[Dict[str, object]] = []

    current_group: Optional[Dict[str, object]] = None
    current_raw_group: Optional[Dict[str, object]] = None
    current_group_has_rules = False

    known_directives = {
        "user-agent",
        "allow",
        "disallow",
        "sitemap",
        "crawl-delay",
        "clean-param",
        "host",
        "noindex",
        "request-rate",
        "visit-time",
    }

    for line_no, raw_line in enumerate(text.splitlines(), start=1):
        original = raw_line.rstrip("\n")
        clean = original.strip()

        if not clean or clean.startswith("#"):
            continue

        clean = clean.split("#", 1)[0].strip()
        if not clean:
            continue

        if ":" not in clean:
            warnings.append(f"Строка {line_no}: нет двоеточия после директивы — {clean[:80]}")
            continue

        key, value = clean.split(":", 1)
        key_original = key.strip()
        key_lower = key_original.lower()
        value = value.strip()

        directives.append(
            {
                "line": line_no,
                "directive": key_original,
                "value": value,
            }
        )

        if key_lower not in known_directives:
            warnings.append(f"Строка {line_no}: нестандартная директива {key_original}")

        if key_lower == "sitemap":
            if value:
                sitemap_value = absolutize(base_url, value) if base_url and not urllib.parse.urlparse(value).netloc else value
                sitemaps.append(sitemap_value)
                parsed_sitemap = urllib.parse.urlparse(value)
                if not parsed_sitemap.scheme or not parsed_sitemap.netloc:
                    warnings.append(f"Строка {line_no}: Sitemap лучше указывать абсолютным URL")
            else:
                warnings.append(f"Строка {line_no}: пустой Sitemap")
            continue

        if key_lower == "user-agent":
            if not value:
                warnings.append(f"Строка {line_no}: пустой User-agent")
                continue

            if current_group is None or current_group_has_rules:
                current_group = {
                    "user_agents": [],
                    "allow": [],
                    "disallow": [],
                    "crawl_delay": [],
                    "clean_param": [],
                    "other": [],
                }
                current_raw_group = {
                    "user_agents": [],
                    "rules": [],
                    "other": [],
                }
                groups.append(current_group)
                raw_groups.append(current_raw_group)
                current_group_has_rules = False

            current_group["user_agents"].append(value)
            current_raw_group["user_agents"].append(value)
            user_agents.append(value)
            continue

        if current_group is None:
            warnings.append(f"Строка {line_no}: директива {key_original} указана до первого User-agent")
            current_group = {
                "user_agents": ["<без User-agent>"],
                "allow": [],
                "disallow": [],
                "crawl_delay": [],
                "clean_param": [],
                "other": [],
            }
            current_raw_group = {
                "user_agents": ["<без User-agent>"],
                "rules": [],
                "other": [],
            }
            groups.append(current_group)
            raw_groups.append(current_raw_group)

        current_group_has_rules = True

        if key_lower == "allow":
            current_group["allow"].append(value)
            current_raw_group["rules"].append({"line": line_no, "type": "allow", "path": value})
        elif key_lower == "disallow":
            current_group["disallow"].append(value)
            current_raw_group["rules"].append({"line": line_no, "type": "disallow", "path": value})
        elif key_lower == "crawl-delay":
            current_group["crawl_delay"].append(value)
            if value and not re.match(r"^\d+(\.\d+)?$", value):
                warnings.append(f"Строка {line_no}: Crawl-delay должен быть числом")
        elif key_lower == "clean-param":
            current_group["clean_param"].append(value)
        else:
            current_group["other"].append(f"{key_original}: {value}")
            current_raw_group["other"].append({"line": line_no, "directive": key_original, "value": value})

    if text.strip() and not user_agents:
        warnings.append("В robots.txt не найден ни один User-agent")

    if not sitemaps:
        warnings.append("В robots.txt не указан Sitemap")

    normalized_groups: List[Dict[str, object]] = []
    for group in groups:
        agents = [str(item).strip() for item in group.get("user_agents", []) if str(item).strip()]
        allows = [str(item).strip() for item in group.get("allow", [])]
        disallows = [str(item).strip() for item in group.get("disallow", [])]
        crawl_delay = [str(item).strip() for item in group.get("crawl_delay", [])]
        clean_param = [str(item).strip() for item in group.get("clean_param", [])]
        other = [str(item).strip() for item in group.get("other", [])]

        if "*" in agents and "/" in disallows:
            warnings.append("Для User-agent: * найден Disallow: / — сайт может быть закрыт от обхода")

        normalized_groups.append(
            {
                "user_agents": ", ".join(agents),
                "allow_count": len([item for item in allows if item != ""]),
                "disallow_count": len([item for item in disallows if item != ""]),
                "allow": "\n".join(allows),
                "disallow": "\n".join(disallows),
                "crawl_delay": "\n".join(crawl_delay),
                "clean_param": "\n".join(clean_param),
                "other": "\n".join(other),
            }
        )

    return {
        "sitemaps": list(dict.fromkeys(sitemaps)),
        "user_agents": sorted(set(user_agents)),
        "groups": normalized_groups,
        "raw_groups": raw_groups,
        "directives": directives,
        "rules_total": len(directives),
        "warnings": list(dict.fromkeys(warnings)),
    }


def analyze_robots_text(text: str, source_label: str = "uploaded robots.txt", base_url: str = "") -> RobotsResult:
    parsed = parse_robots_text(text, base_url=base_url)
    warnings: List[str] = list(parsed["warnings"])

    size_bytes = len(text.encode("utf-8"))
    if size_bytes == 0:
        warnings.append("Файл пустой")
    if size_bytes > 500_000:
        warnings.append("robots.txt слишком большой: поисковые системы учитывают ограниченный размер файла")
    if text.lstrip().lower().startswith(("<!doctype html", "<html")):
        warnings.append("Файл похож на HTML-страницу, а не на robots.txt")

    return RobotsResult(
        url=source_label,
        status_code=200,
        exists=bool(text.strip()),
        size_bytes=size_bytes,
        sitemaps=list(parsed["sitemaps"]),
        user_agents=list(parsed["user_agents"]),
        groups=list(parsed["groups"]),
        raw_groups=list(parsed["raw_groups"]),
        directives=list(parsed["directives"]),
        rules_total=int(parsed["rules_total"]),
        warnings=list(dict.fromkeys(warnings)),
        raw_text=text[:300_000],
    )


def check_robots(client: httpx.Client, base_url: str) -> RobotsResult:
    robots_url = base_url.rstrip("/") + "/robots.txt"
    response, error = fetch(client, robots_url, follow_redirects=True)

    if error or response is None:
        return RobotsResult(
            url=robots_url,
            status_code=None,
            exists=False,
            size_bytes=0,
            sitemaps=[],
            user_agents=[],
            groups=[],
            raw_groups=[],
            directives=[],
            rules_total=0,
            warnings=["robots.txt не удалось получить"],
            raw_text="",
            error=error,
        )

    text = response.text if response.text else ""
    result = analyze_robots_text(text, source_label=str(response.url), base_url=base_url)
    result.status_code = response.status_code
    result.exists = response.status_code == 200

    warnings = list(result.warnings)
    if response.status_code != 200:
        warnings.append(f"robots.txt отдаёт статус {response.status_code}, ожидается 200")
    if response.history:
        chain = " → ".join([str(item.status_code) for item in response.history] + [str(response.status_code)])
        warnings.append(f"robots.txt открывается через редирект: {chain}")
    content_type = response.headers.get("content-type", "").lower()
    if result.exists and content_type and not any(token in content_type for token in ["text/plain", "text/html", "octet-stream"]):
        warnings.append(f"Нестандартный Content-Type для robots.txt: {content_type}")

    result.warnings = list(dict.fromkeys(warnings))
    return result


def load_robots_from_url(robots_url: str) -> RobotsResult:
    robots_url = normalize_any_url(robots_url)
    parsed = urllib.parse.urlparse(robots_url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    with httpx.Client(headers=DEFAULT_HEADERS, timeout=20) as client:
        response, error = fetch(client, robots_url, follow_redirects=True)
    if error or response is None:
        return RobotsResult(
            url=robots_url,
            status_code=None,
            exists=False,
            size_bytes=0,
            sitemaps=[],
            user_agents=[],
            groups=[],
            raw_groups=[],
            directives=[],
            rules_total=0,
            warnings=["robots.txt не удалось получить"],
            raw_text="",
            error=error,
        )
    result = analyze_robots_text(response.text or "", source_label=str(response.url), base_url=base_url)
    result.status_code = response.status_code
    result.exists = response.status_code == 200
    if response.status_code != 200:
        result.warnings.append(f"Файл отдаёт статус {response.status_code}, ожидается 200")
    if response.history:
        chain = " → ".join([str(item.status_code) for item in response.history] + [str(response.status_code)])
        result.warnings.append(f"Файл открывается через редирект: {chain}")
    return result


def build_robot_parser(robots_result: RobotsResult, client: Optional[httpx.Client] = None) -> Optional[urllib.robotparser.RobotFileParser]:
    if not robots_result.raw_text.strip():
        return None
    parser = urllib.robotparser.RobotFileParser()
    parser.set_url(robots_result.url)
    parser.parse(robots_result.raw_text.splitlines())
    return parser


def _ua_match_score(pattern: str, ua: str) -> int:
    pattern_l = pattern.lower().strip()
    ua_l = ua.lower().strip()
    if pattern_l == "*":
        return 1
    if pattern_l and pattern_l in ua_l:
        return len(pattern_l)
    return 0


def _robots_rule_matches(rule_path: str, target_path: str) -> bool:
    if rule_path == "":
        return False
    escaped = ""
    for char in rule_path:
        if char == "*":
            escaped += ".*"
        elif char == "$":
            escaped += "$"
        else:
            escaped += re.escape(char)
    pattern = "^" + escaped
    try:
        return re.search(pattern, target_path) is not None
    except re.error:
        return target_path.startswith(rule_path.replace("*", ""))


def explain_robots_access(robots_result: RobotsResult | Dict[str, object], url: str, user_agent: str) -> Dict[str, object]:
    url = normalize_any_url(url)
    parsed_url = urllib.parse.urlparse(url)
    target_path = parsed_url.path or "/"
    if parsed_url.query:
        target_path += "?" + parsed_url.query

    if isinstance(robots_result, dict):
        raw_groups = robots_result.get("raw_groups") or []
    else:
        raw_groups = robots_result.raw_groups or []
    best_score = 0
    selected_groups: List[Dict[str, object]] = []
    for group in raw_groups:
        scores = [_ua_match_score(str(agent), user_agent) for agent in group.get("user_agents", [])]
        score = max(scores or [0])
        if score > best_score:
            best_score = score
            selected_groups = [group]
        elif score == best_score and score > 0:
            selected_groups.append(group)

    if best_score == 0:
        return {
            "url": url,
            "user_agent": user_agent,
            "allowed": True,
            "matched_group": "—",
            "matched_rule": "Правил для этого User-agent нет",
            "matched_line": "—",
            "rule_type": "allow",
        }

    matching_rules: List[Dict[str, object]] = []
    for group in selected_groups:
        for rule in group.get("rules", []):
            path = str(rule.get("path", ""))
            if _robots_rule_matches(path, target_path):
                matching_rules.append(rule)

    matched_group_label = "; ".join(
        ", ".join([str(agent) for agent in group.get("user_agents", [])]) for group in selected_groups
    )

    if not matching_rules:
        return {
            "url": url,
            "user_agent": user_agent,
            "allowed": True,
            "matched_group": matched_group_label,
            "matched_rule": "Подходящих Allow/Disallow правил нет",
            "matched_line": "—",
            "rule_type": "allow",
        }

    def sort_key(rule: Dict[str, object]) -> Tuple[int, int]:
        path = str(rule.get("path", ""))
        specificity = len(path.replace("*", "").replace("$", ""))
        allow_priority = 1 if str(rule.get("type")) == "allow" else 0
        return specificity, allow_priority

    winner = sorted(matching_rules, key=sort_key, reverse=True)[0]
    is_disallow = str(winner.get("type")) == "disallow"
    return {
        "url": url,
        "user_agent": user_agent,
        "allowed": not is_disallow,
        "matched_group": matched_group_label,
        "matched_rule": f"{str(winner.get('type')).capitalize()}: {winner.get('path')}",
        "matched_line": winner.get("line", "—"),
        "rule_type": winner.get("type", ""),
    }


def check_robots_url_list(robots_result: RobotsResult, urls_text: str, user_agents: List[str]) -> List[Dict[str, object]]:
    urls = [line.strip() for line in (urls_text or "").splitlines() if line.strip()]
    rows: List[Dict[str, object]] = []
    for url in urls:
        for ua in user_agents:
            try:
                item = explain_robots_access(robots_result, url, ua)
                item["status"] = "Открыта" if item["allowed"] else "Закрыта"
                rows.append(item)
            except Exception as exc:
                rows.append(
                    {
                        "url": url,
                        "user_agent": ua,
                        "allowed": None,
                        "status": "Ошибка",
                        "matched_group": "—",
                        "matched_rule": "—",
                        "matched_line": "—",
                        "rule_type": "—",
                        "error": str(exc),
                    }
                )
    return rows


# ------------------------------- sitemap.xml ------------------------------


def parse_sitemap_xml_detailed(xml_text: str) -> Dict[str, object]:
    warnings: List[str] = []
    urls: List[Dict[str, object]] = []
    nested_sitemaps: List[Dict[str, object]] = []

    if not xml_text.strip():
        return {"type": "empty", "urls": [], "nested_sitemaps": [], "warnings": ["Файл пустой"]}

    if xml_text.lstrip().lower().startswith(("<!doctype html", "<html")):
        warnings.append("Файл похож на HTML-страницу, а не на XML sitemap")

    try:
        root = ET.fromstring(xml_text.encode("utf-8"))
    except ET.ParseError as exc:
        return {"type": "invalid", "urls": [], "nested_sitemaps": [], "warnings": [f"XML sitemap не парсится: {exc}"]}

    root_name = strip_xml_namespace(root.tag)
    if root_name == "sitemapindex":
        sitemap_type = "sitemap_index"
        for sitemap in root.findall(".//{*}sitemap"):
            loc = sitemap.find("{*}loc")
            lastmod = sitemap.find("{*}lastmod")
            nested_sitemaps.append(
                {
                    "loc": (loc.text or "").strip() if loc is not None else "",
                    "lastmod": (lastmod.text or "").strip() if lastmod is not None else "",
                }
            )
    elif root_name == "urlset":
        sitemap_type = "urlset"
        for url_node in root.findall(".//{*}url"):
            loc = url_node.find("{*}loc")
            lastmod = url_node.find("{*}lastmod")
            changefreq = url_node.find("{*}changefreq")
            priority = url_node.find("{*}priority")
            image_nodes = url_node.findall(".//{*}image")
            urls.append(
                {
                    "loc": (loc.text or "").strip() if loc is not None else "",
                    "lastmod": (lastmod.text or "").strip() if lastmod is not None else "",
                    "changefreq": (changefreq.text or "").strip() if changefreq is not None else "",
                    "priority": (priority.text or "").strip() if priority is not None else "",
                    "images": len(image_nodes),
                }
            )
    else:
        sitemap_type = "unknown"
        warnings.append(f"Неизвестный корневой тег sitemap: {root.tag}")

    locs = [item.get("loc", "") for item in urls]
    sitemap_locs = [item.get("loc", "") for item in nested_sitemaps]
    all_locs = locs or sitemap_locs

    if len(urls) > 50_000:
        warnings.append("В одном sitemap больше 50 000 URL")
    if len(nested_sitemaps) > 50_000:
        warnings.append("В sitemap index больше 50 000 sitemap-файлов")

    empty_locs = [idx + 1 for idx, loc in enumerate(all_locs) if not loc]
    if empty_locs:
        warnings.append(f"Есть пустые <loc>: {len(empty_locs)}")

    duplicates = sorted({loc for loc in all_locs if loc and all_locs.count(loc) > 1})
    if duplicates:
        warnings.append(f"Есть дубли <loc>: {len(duplicates)}")

    hosts = sorted({urllib.parse.urlparse(loc).netloc.lower() for loc in all_locs if urllib.parse.urlparse(loc).netloc})
    if len(hosts) > 1:
        warnings.append(f"В sitemap найдены разные хосты: {', '.join(hosts[:5])}")

    http_urls = [loc for loc in all_locs if loc.startswith("http://")]
    if http_urls:
        warnings.append(f"Есть HTTP URL вместо HTTPS: {len(http_urls)}")

    relative_locs = [loc for loc in all_locs if loc and not urllib.parse.urlparse(loc).scheme]
    if relative_locs:
        warnings.append(f"Есть не абсолютные URL в <loc>: {len(relative_locs)}")

    fragments = [loc for loc in all_locs if "#" in loc]
    if fragments:
        warnings.append(f"Есть URL с фрагментом #: {len(fragments)}")

    spaces = [loc for loc in all_locs if re.search(r"\s", loc)]
    if spaces:
        warnings.append(f"Есть URL с пробелами/переносами: {len(spaces)}")

    bad_lastmods = []
    for item in urls + nested_sitemaps:
        lastmod = str(item.get("lastmod", "")).strip()
        if lastmod:
            try:
                dt.datetime.fromisoformat(lastmod.replace("Z", "+00:00"))
            except ValueError:
                bad_lastmods.append(lastmod)
    if bad_lastmods:
        warnings.append(f"Есть некорректные lastmod: {len(bad_lastmods)}")

    bad_priorities = []
    for item in urls:
        priority = str(item.get("priority", "")).strip()
        if priority:
            try:
                value = float(priority)
                if value < 0 or value > 1:
                    bad_priorities.append(priority)
            except ValueError:
                bad_priorities.append(priority)
    if bad_priorities:
        warnings.append(f"Есть некорректные priority: {len(bad_priorities)}")

    return {
        "type": sitemap_type,
        "urls": urls,
        "nested_sitemaps": nested_sitemaps,
        "warnings": list(dict.fromkeys(warnings)),
    }


def parse_xml_sitemap(xml_text: str) -> Tuple[str, List[str], List[str], List[str]]:
    parsed = parse_sitemap_xml_detailed(xml_text)
    return (
        str(parsed["type"]),
        [str(item.get("loc", "")) for item in parsed["urls"] if item.get("loc")],
        [str(item.get("loc", "")) for item in parsed["nested_sitemaps"] if item.get("loc")],
        list(parsed["warnings"]),
    )


def analyze_sitemap_text(text: str, source_label: str = "uploaded sitemap") -> Dict[str, object]:
    parsed = parse_sitemap_xml_detailed(text)
    warnings = list(parsed["warnings"])
    size_bytes = len(text.encode("utf-8"))
    if size_bytes > 50 * 1024 * 1024:
        warnings.append("Размер sitemap больше 50 МБ")
    return {
        "source": source_label,
        "status_code": 200,
        "size_bytes": size_bytes,
        "type": parsed["type"],
        "urls": parsed["urls"],
        "nested_sitemaps": parsed["nested_sitemaps"],
        "urls_found": len(parsed["urls"]),
        "nested_found": len(parsed["nested_sitemaps"]),
        "warnings": list(dict.fromkeys(warnings)),
        "raw_text": text[:300_000],
    }


def load_sitemap_from_url(sitemap_url: str) -> Dict[str, object]:
    sitemap_url = normalize_any_url(sitemap_url)
    with httpx.Client(headers=DEFAULT_HEADERS, timeout=30) as client:
        response, error = fetch(client, sitemap_url, follow_redirects=True, timeout=30)
    if error or response is None:
        return {
            "source": sitemap_url,
            "status_code": None,
            "size_bytes": 0,
            "type": "error",
            "urls": [],
            "nested_sitemaps": [],
            "urls_found": 0,
            "nested_found": 0,
            "warnings": ["Sitemap не удалось получить"],
            "error": error,
            "raw_text": "",
        }
    text = response.text or ""
    result = analyze_sitemap_text(text, source_label=str(response.url))
    result["status_code"] = response.status_code
    if response.status_code != 200:
        result["warnings"].append(f"Sitemap отдаёт статус {response.status_code}, ожидается 200")
    if response.history:
        chain = " → ".join([str(item.status_code) for item in response.history] + [str(response.status_code)])
        result["warnings"].append(f"Sitemap открывается через редирект: {chain}")
    content_type = response.headers.get("content-type", "").lower()
    if content_type and not any(token in content_type for token in ["xml", "text/plain", "text/html", "octet-stream", "gzip"]):
        result["warnings"].append(f"Нестандартный Content-Type для sitemap: {content_type}")
    result["warnings"] = list(dict.fromkeys(result["warnings"]))
    return result


def check_urls_status(urls: Iterable[str], max_urls: int = 100, delay_sec: float = 0.0) -> List[Dict[str, object]]:
    rows: List[Dict[str, object]] = []
    url_list = [str(url).strip() for url in urls if str(url).strip()][:max_urls]
    with httpx.Client(headers=DEFAULT_HEADERS, timeout=20) as client:
        for url in url_list:
            try:
                norm = normalize_any_url(url)
                response, error = fetch(client, norm, follow_redirects=True, timeout=20)
                if error or response is None:
                    rows.append(
                        {
                            "url": url,
                            "status_code": None,
                            "final_url": "",
                            "redirect_count": 0,
                            "result": "Ошибка",
                            "comment": error or "Не удалось получить URL",
                        }
                    )
                else:
                    status = response.status_code
                    if status >= 400:
                        result = "Ошибка"
                        comment = f"URL отдаёт {status}"
                    elif len(response.history) > 0:
                        result = "Редирект"
                        comment = f"URL открывается через {len(response.history)} редирект(а/ов)"
                    else:
                        result = "OK"
                        comment = ""
                    rows.append(
                        {
                            "url": url,
                            "status_code": status,
                            "final_url": str(response.url),
                            "redirect_count": len(response.history),
                            "result": result,
                            "comment": comment,
                        }
                    )
            except Exception as exc:
                rows.append(
                    {
                        "url": url,
                        "status_code": None,
                        "final_url": "",
                        "redirect_count": 0,
                        "result": "Ошибка",
                        "comment": str(exc),
                    }
                )
            if delay_sec > 0:
                time.sleep(delay_sec)
    return rows


def collect_sitemap_urls(
    client: httpx.Client,
    sitemap_urls: List[str],
    *,
    max_urls: int = 100,
    max_sitemaps: int = 20,
) -> Tuple[List[str], List[SitemapResult]]:
    queue = list(dict.fromkeys(sitemap_urls))
    seen_sitemaps = set()
    collected_urls: List[str] = []
    results: List[SitemapResult] = []

    while queue and len(seen_sitemaps) < max_sitemaps and len(collected_urls) < max_urls:
        sitemap_url = queue.pop(0)
        if sitemap_url in seen_sitemaps:
            continue
        seen_sitemaps.add(sitemap_url)

        response, error = fetch(client, sitemap_url, follow_redirects=True, timeout=20)
        if error or response is None:
            results.append(
                SitemapResult(
                    sitemap_url=sitemap_url,
                    status_code=None,
                    type="error",
                    urls_found=0,
                    urls_checked=0,
                    nested_sitemaps=[],
                    warnings=["Sitemap не удалось получить"],
                    error=error,
                )
            )
            continue

        warnings: List[str] = []
        if response.status_code != 200:
            warnings.append(f"Sitemap отдаёт статус {response.status_code}, ожидается 200")

        sitemap_type, urls, nested, parse_warnings = parse_xml_sitemap(response.text)
        warnings.extend(parse_warnings)

        if nested:
            queue.extend([url for url in nested if url not in seen_sitemaps])

        free_slots = max_urls - len(collected_urls)
        added = urls[:free_slots]
        collected_urls.extend(added)

        if len(urls) > len(added):
            warnings.append(f"Проверена только часть URL: лимит {max_urls}")

        results.append(
            SitemapResult(
                sitemap_url=str(response.url),
                status_code=response.status_code,
                type=sitemap_type,
                urls_found=len(urls),
                urls_checked=len(added),
                nested_sitemaps=nested,
                warnings=list(dict.fromkeys(warnings)),
            )
        )

    return list(dict.fromkeys(collected_urls))[:max_urls], results


def discover_sitemaps(client: httpx.Client, base_url: str, robots_result: RobotsResult) -> List[str]:
    candidates = list(robots_result.sitemaps)
    for path in COMMON_SITEMAP_PATHS:
        candidates.append(base_url.rstrip("/") + path)

    existing: List[str] = []
    for url in dict.fromkeys(candidates):
        response, _ = fetch(client, url, follow_redirects=True, timeout=10)
        if response is not None and response.status_code == 200:
            content_type = response.headers.get("content-type", "").lower()
            head = response.text[:1000].lower()
            if "xml" in content_type or response.text.lstrip().startswith("<?xml") or "<urlset" in head or "<sitemapindex" in head:
                existing.append(str(response.url))
    return list(dict.fromkeys(existing))


# -------------------------------- .htaccess -------------------------------


def analyze_htaccess_text(text: str) -> Dict[str, object]:
    warnings: List[str] = []
    positives: List[str] = []
    rows: List[Dict[str, object]] = []
    counters = {
        "RewriteRule": 0,
        "RewriteCond": 0,
        "Redirect": 0,
        "Header": 0,
        "Options": 0,
        "ErrorDocument": 0,
        "Files/FilesMatch": 0,
    }

    lines = text.splitlines()
    if not text.strip():
        warnings.append("Файл пустой")

    rewrite_engine_on = False
    has_https_condition = False
    has_https_redirect = False
    has_www_rule = False
    has_nonwww_rule = False
    has_options_indexes_off = False
    has_cache = False
    has_compression = False
    has_sensitive_protection = False
    has_error_document_404 = False

    previous_conditions: List[str] = []
    active_files_block = ""

    for line_no, raw in enumerate(lines, start=1):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue

        lower = stripped.lower()
        directive = stripped.split(None, 1)[0] if stripped.split() else stripped
        comment = ""
        level = "info"

        if lower.startswith("rewriteengine"):
            if re.search(r"\bon\b", lower):
                rewrite_engine_on = True
                comment = "RewriteEngine включён"
            else:
                warnings.append(f"Строка {line_no}: RewriteEngine не включён")
                level = "warning"
        elif lower.startswith("rewritecond"):
            counters["RewriteCond"] += 1
            previous_conditions.append(stripped)
            if "%{https}" in lower and re.search(r"\boff\b|!=on", lower):
                has_https_condition = True
            if "%{server_port}" in lower and "80" in lower:
                has_https_condition = True
            if "%{http_host}" in lower and "www" in lower:
                has_www_rule = True
            comment = "Условие для следующего RewriteRule"
        elif lower.startswith("rewriterule"):
            counters["RewriteRule"] += 1
            conditions_text = " ".join(previous_conditions).lower()
            flags_match = re.search(r"\[(.*?)\]", stripped)
            flags = flags_match.group(1).lower() if flags_match else ""

            if "http" in lower and "https://" in lower:
                has_https_redirect = True
            if "https://" in lower and not (has_https_condition or "%{https}" in conditions_text or "%{server_port}" in conditions_text):
                warnings.append(f"Строка {line_no}: HTTPS-редирект без явного условия может давать цикл")
                level = "warning"
            if "www." in lower or "www" in conditions_text:
                has_www_rule = True
            if "http://%{http_host}" in lower:
                warnings.append(f"Строка {line_no}: правило может принудительно уводить на HTTP")
                level = "warning"
            if "r=" in flags or flags.startswith("r") or ",r" in flags:
                if "l" not in flags and "end" not in flags:
                    warnings.append(f"Строка {line_no}: редирект без флага L/END")
                    level = "warning"
                if "r=302" in flags or re.search(r"(^|,)r(,|$)", flags):
                    warnings.append(f"Строка {line_no}: временный 302-редирект, проверьте, нужен ли 301")
                    level = "warning"
            comment = "Правило перезаписи/редиректа"
            previous_conditions = []
        elif lower.startswith("redirect") or lower.startswith("redirectmatch"):
            counters["Redirect"] += 1
            if re.match(r"redirect\s+302\b", lower) or re.match(r"redirect\s+/", lower):
                warnings.append(f"Строка {line_no}: Redirect без 301 может работать как временный редирект")
                level = "warning"
            comment = "Простой Redirect/RedirectMatch"
        elif lower.startswith("options"):
            counters["Options"] += 1
            if "-indexes" in lower:
                has_options_indexes_off = True
            if "+indexes" in lower:
                warnings.append(f"Строка {line_no}: включён листинг директорий Options +Indexes")
                level = "warning"
            comment = "Настройки Options"
        elif lower.startswith("header"):
            counters["Header"] += 1
            if "cache-control" in lower:
                has_cache = True
            if "x-robots-tag" in lower and "noindex" in lower:
                warnings.append(f"Строка {line_no}: через Header задаётся X-Robots-Tag noindex")
                level = "warning"
            comment = "HTTP-заголовок"
        elif lower.startswith("expiresactive") or lower.startswith("expiresbytype") or lower.startswith("cache-control") or lower.startswith("fileetag"):
            has_cache = True
            comment = "Кэширование статики"
        elif "deflate" in lower or "brotli" in lower or "addoutputfilterbytype" in lower:
            has_compression = True
            comment = "Сжатие ответа"
        elif lower.startswith("errordocument"):
            counters["ErrorDocument"] += 1
            if re.match(r"errordocument\s+404\b", lower):
                has_error_document_404 = True
            comment = "Страница ошибки"
        elif lower.startswith("<files") or lower.startswith("<filesmatch"):
            counters["Files/FilesMatch"] += 1
            active_files_block = lower
            comment = "Блок защиты файлов"
        elif lower.startswith("</files"):
            active_files_block = ""
            comment = "Конец блока Files"
        elif lower.startswith("require all denied") or lower.startswith("deny from all"):
            if active_files_block and any(token in active_files_block for token in ["env", "wp-config", "composer", "git", "htaccess"]):
                has_sensitive_protection = True
            comment = "Запрет доступа"
        elif any(token in lower for token in [".env", "wp-config", "composer.json", ".git", ".htaccess"]):
            has_sensitive_protection = True
            comment = "Правило для служебных файлов"

        rows.append(
            {
                "line": line_no,
                "directive": directive,
                "text": stripped,
                "level": level,
                "comment": comment,
            }
        )

    if rewrite_engine_on:
        positives.append("RewriteEngine включён")
    elif any(row["directive"].lower().startswith("rewrite") for row in rows):
        warnings.append("Есть RewriteRule/RewriteCond, но не найден RewriteEngine On")

    if has_https_condition and has_https_redirect:
        positives.append("Найдено правило HTTPS-редиректа")
    elif any("http" in str(row["text"]).lower() for row in rows):
        warnings.append("Есть HTTP/HTTPS-правила, но HTTPS-редирект нужно проверить вручную")
    else:
        warnings.append("Не найдено явное правило HTTP → HTTPS")

    if has_www_rule or has_nonwww_rule:
        positives.append("Найдены правила для www/non-www")
    else:
        warnings.append("Не найдены явные правила склейки www/non-www")

    if has_options_indexes_off:
        positives.append("Листинг директорий отключён через Options -Indexes")
    else:
        warnings.append("Не найдено Options -Indexes для отключения листинга директорий")

    if has_sensitive_protection:
        positives.append("Есть признаки защиты служебных файлов")
    else:
        warnings.append("Не найдена явная защита .env/wp-config.php/composer.json/.git")

    if has_cache:
        positives.append("Есть настройки кэширования")
    else:
        warnings.append("Не найдены настройки кэширования статики")

    if has_compression:
        positives.append("Есть настройки gzip/brotli/deflate")
    else:
        warnings.append("Не найдены настройки сжатия gzip/brotli")

    if has_error_document_404:
        positives.append("Настроена 404-страница")

    return {
        "size_bytes": len(text.encode("utf-8")),
        "lines_total": len(lines),
        "rules": rows,
        "counters": counters,
        "positives": list(dict.fromkeys(positives)),
        "warnings": list(dict.fromkeys(warnings)),
        "raw_text": text[:300_000],
        "note": "Анализ .htaccess эвристический: сервис не исполняет правила Apache, а ищет SEO-рискованные конструкции.",
    }


# ---------------------------- Technical duplicates -------------------------


def canonicalize_url_for_compare(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    path = parsed.path or "/"
    if path != "/":
        path = path.rstrip("/")
    return urllib.parse.urlunparse((scheme, netloc, path, "", parsed.query, ""))


def generate_duplicate_variants(raw_url: str) -> List[str]:
    url = normalize_any_url(raw_url)
    parsed = urllib.parse.urlparse(url)
    host = parsed.netloc.lower()
    path = parsed.path or "/"
    if not path.startswith("/"):
        path = "/" + path

    base_hosts = [host]
    if host.startswith("www."):
        base_hosts.append(host[4:])
    else:
        base_hosts.append("www." + host)

    path_variants = {path}
    if path == "/" or path == "":
        path_variants.update(["/", "/index.php", "/index.html", "/index.htm"])
    else:
        path_variants.add(path.rstrip("/"))
        path_variants.add(path.rstrip("/") + "/")
        path_variants.add(path.lower())

    variants: List[str] = []
    for scheme in ["https", "http"]:
        for variant_host in base_hosts:
            for variant_path in path_variants:
                variants.append(f"{scheme}://{variant_host}{variant_path}")

    # Parameter variants for homepage/path. They are marked as soft checks.
    variants.append(urllib.parse.urlunparse((parsed.scheme, host, path, "", "utm_source=seo_audit", "")))
    variants.append(urllib.parse.urlunparse((parsed.scheme, host, path, "", "", "test")))
    return list(dict.fromkeys(variants))


def fetch_redirect_chain(client: httpx.Client, url: str, max_hops: int = 10) -> Dict[str, object]:
    current = normalize_any_url(url)
    hops: List[Dict[str, object]] = []
    seen = set()
    error = ""

    for hop_index in range(max_hops + 1):
        if current in seen:
            error = "redirect_loop"
            break
        seen.add(current)
        response, request_error = fetch(client, current, follow_redirects=False, timeout=15)
        if request_error or response is None:
            hops.append(
                {
                    "url": current,
                    "status_code": None,
                    "location": "",
                    "content_type": "",
                    "error": request_error or "Ошибка запроса",
                }
            )
            error = request_error or "Ошибка запроса"
            break

        location = response.headers.get("location", "")
        hops.append(
            {
                "url": current,
                "status_code": response.status_code,
                "location": location,
                "content_type": response.headers.get("content-type", ""),
                "error": "",
            }
        )

        if response.status_code in REDIRECT_STATUSES and location:
            current = urllib.parse.urljoin(current, location)
            continue
        break
    else:
        error = "too_many_redirects"

    final_url = hops[-1]["url"] if hops else current
    final_status = hops[-1]["status_code"] if hops else None
    redirect_count = max(0, len(hops) - 1) if final_status not in REDIRECT_STATUSES else len(hops)
    return {
        "start_url": url,
        "final_url": final_url,
        "final_status": final_status,
        "redirect_count": redirect_count,
        "status_chain": " → ".join([str(hop.get("status_code") or "ERR") for hop in hops]),
        "hops": hops,
        "error": error,
    }


def html_fingerprint(html: str) -> Dict[str, str]:
    soup = BeautifulSoup(html or "", "lxml")
    for tag in soup(["script", "style", "noscript", "svg"]):
        tag.decompose()
    title = text_or_empty(soup.find("title"))
    h1 = " | ".join([text_or_empty(item) for item in soup.find_all("h1")[:3]])
    canonical_node = soup.find("link", attrs={"rel": lambda value: value and "canonical" in value})
    canonical = canonical_node.get("href", "").strip() if canonical_node else ""
    text = " ".join(soup.get_text(" ", strip=True).split())[:5000]
    return {"title": title, "h1": h1, "canonical": canonical, "text": text}


def analyze_technical_duplicates(raw_url: str, max_extra_urls_text: str = "", delay_sec: float = 0.0) -> Dict[str, object]:
    primary_url = normalize_any_url(raw_url)
    variants = generate_duplicate_variants(primary_url)
    extra_urls = [line.strip() for line in (max_extra_urls_text or "").splitlines() if line.strip()]
    variants.extend(extra_urls)
    variants = list(dict.fromkeys(variants))

    rows: List[Dict[str, object]] = []
    chains: List[Dict[str, object]] = []
    fingerprints: Dict[str, Dict[str, str]] = {}
    warnings: List[str] = []

    with httpx.Client(headers=DEFAULT_HEADERS, timeout=20) as client:
        for url in variants:
            chain = fetch_redirect_chain(client, url, max_hops=10)
            chains.append(chain)
            issue = "OK"
            recommendation = ""
            final_status = chain["final_status"]
            redirect_count = int(chain["redirect_count"] or 0)
            error = str(chain.get("error") or "")

            if error == "redirect_loop":
                issue = "Петля редиректов"
                recommendation = "Проверить правила редиректов: URL возвращается в уже пройденную точку."
            elif error == "too_many_redirects":
                issue = "Слишком много редиректов"
                recommendation = "Сократить цепочку до одного прямого 301/308."
            elif error:
                issue = "Ошибка запроса"
                recommendation = "Проверить доступность URL и DNS/SSL."
            elif final_status is None:
                issue = "Ошибка запроса"
                recommendation = "Проверить доступность URL."
            elif final_status >= 400:
                issue = f"Финальный статус {final_status}"
                recommendation = "Для рабочих дублей нужен 301 на канонический URL или корректный 404/410 для удалённых страниц."
            elif redirect_count >= 2:
                issue = "Цепочка редиректов"
                recommendation = "Сделать прямой редирект с исходного URL на финальный URL."
            elif redirect_count == 0 and canonicalize_url_for_compare(url) != canonicalize_url_for_compare(chain["final_url"]):
                issue = "Возможный дубль без редиректа"
                recommendation = "Проверить, должна ли версия отдавать 301 на каноническую."

            rows.append(
                {
                    "start_url": url,
                    "final_url": chain["final_url"],
                    "final_status": final_status,
                    "redirect_count": redirect_count,
                    "status_chain": chain["status_chain"],
                    "issue": issue,
                    "recommendation": recommendation,
                }
            )

            # Fetch final HTML for duplicate content comparison only when it is a 200 final page.
            if final_status == 200 and chain["final_url"] not in fingerprints:
                response, _ = fetch(client, chain["final_url"], follow_redirects=True, timeout=15)
                if response is not None and response.status_code == 200:
                    content_type = response.headers.get("content-type", "").lower()
                    if "html" in content_type or "<html" in response.text[:1000].lower():
                        fingerprints[chain["final_url"]] = html_fingerprint(response.text)
            if delay_sec > 0:
                time.sleep(delay_sec)

    # Find different final URLs with highly similar content/title.
    final_urls = list(fingerprints.keys())
    similar_pairs: List[Dict[str, object]] = []
    for i in range(len(final_urls)):
        for j in range(i + 1, len(final_urls)):
            a, b = final_urls[i], final_urls[j]
            fp_a, fp_b = fingerprints[a], fingerprints[b]
            title_same = fp_a["title"] and fp_a["title"] == fp_b["title"]
            canonical_same = fp_a["canonical"] and fp_a["canonical"] == fp_b["canonical"]
            text_ratio = SequenceMatcher(None, fp_a["text"], fp_b["text"]).ratio() if fp_a["text"] and fp_b["text"] else 0
            if title_same or canonical_same or text_ratio >= 0.92:
                similar_pairs.append(
                    {
                        "url_1": a,
                        "url_2": b,
                        "title_same": title_same,
                        "canonical_same": canonical_same,
                        "text_similarity": round(text_ratio, 3),
                    }
                )

    chain_count = sum(1 for row in rows if row["issue"] == "Цепочка редиректов")
    loop_count = sum(1 for row in rows if "Петля" in str(row["issue"]) or "много" in str(row["issue"]))
    possible_duplicates = sum(1 for row in rows if row["issue"] == "Возможный дубль без редиректа") + len(similar_pairs)

    if chain_count:
        warnings.append(f"Найдены цепочки редиректов: {chain_count}")
    if loop_count:
        warnings.append(f"Найдены петли/слишком длинные редиректы: {loop_count}")
    if possible_duplicates:
        warnings.append(f"Есть признаки технических дублей: {possible_duplicates}")

    return {
        "checked_url": primary_url,
        "rows": rows,
        "chains": chains,
        "similar_pairs": similar_pairs,
        "warnings": warnings,
        "summary": {
            "variants_checked": len(rows),
            "redirect_chains": chain_count,
            "redirect_loops": loop_count,
            "possible_duplicates": possible_duplicates,
        },
    }


# ------------------------------ HTML / pages -------------------------------


def text_or_empty(node) -> str:
    if not node:
        return ""
    return " ".join(node.get_text(" ", strip=True).split())


def analyze_html(html: str) -> Dict[str, object]:
    soup = BeautifulSoup(html, "lxml")
    warnings: List[str] = []

    title_node = soup.find("title")
    title = text_or_empty(title_node)

    desc_node = soup.find("meta", attrs={"name": re.compile(r"^description$", re.I)})
    description = desc_node.get("content", "").strip() if desc_node else ""

    h1_nodes = soup.find_all("h1")
    h1_text = " | ".join([text_or_empty(h1) for h1 in h1_nodes[:3]])

    canonical_node = soup.find("link", attrs={"rel": lambda value: value and "canonical" in value})
    canonical = canonical_node.get("href", "").strip() if canonical_node else ""

    robots_node = soup.find("meta", attrs={"name": re.compile(r"^robots$", re.I)})
    meta_robots = robots_node.get("content", "").strip() if robots_node else ""

    if not title:
        warnings.append("Нет title")
    elif len(title) < 20:
        warnings.append("Title слишком короткий")
    elif len(title) > 70:
        warnings.append("Title длиннее 70 символов")

    if not description:
        warnings.append("Нет meta description")
    elif len(description) < 50:
        warnings.append("Description слишком короткий")
    elif len(description) > 170:
        warnings.append("Description длиннее 170 символов")

    if len(h1_nodes) == 0:
        warnings.append("Нет H1")
    elif len(h1_nodes) > 1:
        warnings.append("На странице больше одного H1")

    if not canonical:
        warnings.append("Нет canonical")

    if meta_robots and "noindex" in meta_robots.lower():
        warnings.append("Страница содержит meta robots noindex")

    html_tag = soup.find("html")
    if html_tag and not html_tag.get("lang"):
        warnings.append("У html не указан lang")

    viewport = soup.find("meta", attrs={"name": re.compile(r"^viewport$", re.I)})
    if not viewport:
        warnings.append("Нет meta viewport")

    if html.lower().count("<html") > 1:
        warnings.append("В HTML найдено несколько тегов <html>")
    if html.lower().count("<body") > 1:
        warnings.append("В HTML найдено несколько тегов <body>")

    ids: Dict[str, int] = {}
    for tag in soup.find_all(attrs={"id": True}):
        ids[tag["id"]] = ids.get(tag["id"], 0) + 1
    duplicate_ids = [key for key, value in ids.items() if value > 1]
    if duplicate_ids:
        warnings.append(f"Есть дубли id: {', '.join(duplicate_ids[:5])}")

    return {
        "title": title,
        "title_len": len(title),
        "description": description,
        "description_len": len(description),
        "h1_count": len(h1_nodes),
        "h1_text": h1_text,
        "canonical": canonical,
        "meta_robots": meta_robots,
        "html_warnings": warnings,
    }


def check_page(
    client: httpx.Client,
    url: str,
    robot_parser: Optional[urllib.robotparser.RobotFileParser],
) -> PageResult:
    response, error = fetch(client, url, follow_redirects=True, timeout=20)

    blocked_googlebot = None
    blocked_yandexbot = None
    if robot_parser:
        try:
            blocked_googlebot = not robot_parser.can_fetch("Googlebot", url)
            blocked_yandexbot = not robot_parser.can_fetch("YandexBot", url)
        except Exception:
            blocked_googlebot = None
            blocked_yandexbot = None

    if error or response is None:
        return PageResult(
            url=url,
            status_code=None,
            final_url=None,
            redirect_count=0,
            blocked_googlebot=blocked_googlebot,
            blocked_yandexbot=blocked_yandexbot,
            title="",
            title_len=0,
            description="",
            description_len=0,
            h1_count=0,
            h1_text="",
            canonical="",
            meta_robots="",
            html_warnings=["Страницу не удалось получить"],
            error=error,
        )

    content_type = response.headers.get("content-type", "").lower()
    html_data = {
        "title": "",
        "title_len": 0,
        "description": "",
        "description_len": 0,
        "h1_count": 0,
        "h1_text": "",
        "canonical": "",
        "meta_robots": "",
        "html_warnings": [],
    }

    if response.status_code == 200 and ("html" in content_type or response.text.lstrip().lower().startswith("<!doctype html") or "<html" in response.text[:1000].lower()):
        html_data = analyze_html(response.text)
    elif response.status_code == 200:
        html_data["html_warnings"] = [f"Контент не похож на HTML: {content_type or 'content-type не указан'}"]

    if blocked_googlebot:
        html_data["html_warnings"].append("URL из sitemap закрыт для Googlebot в robots.txt")
    if blocked_yandexbot:
        html_data["html_warnings"].append("URL из sitemap закрыт для YandexBot в robots.txt")

    return PageResult(
        url=url,
        status_code=response.status_code,
        final_url=str(response.url),
        redirect_count=len(response.history),
        blocked_googlebot=blocked_googlebot,
        blocked_yandexbot=blocked_yandexbot,
        title=str(html_data["title"]),
        title_len=int(html_data["title_len"]),
        description=str(html_data["description"]),
        description_len=int(html_data["description_len"]),
        h1_count=int(html_data["h1_count"]),
        h1_text=str(html_data["h1_text"]),
        canonical=str(html_data["canonical"]),
        meta_robots=str(html_data["meta_robots"]),
        html_warnings=list(html_data["html_warnings"]),
    )


def check_server_behavior(client: httpx.Client, base_url: str) -> List[Dict[str, object]]:
    checks: List[Dict[str, object]] = []

    parsed = urllib.parse.urlparse(base_url)
    https_url = f"https://{parsed.netloc}"
    http_url = f"http://{parsed.netloc}"

    for label, url in [
        ("HTTPS-версия", https_url),
        ("HTTP → HTTPS", http_url),
        ("404-страница", base_url.rstrip("/") + "/seo-file-auditor-test-404"),
    ]:
        response, error = fetch(client, url, follow_redirects=False, timeout=10)
        checks.append(
            {
                "check": label,
                "url": url,
                "status_code": response.status_code if response else None,
                "location": response.headers.get("location", "") if response else "",
                "result": "Ошибка запроса" if error else "OK",
                "comment": error or "",
            }
        )

    for path in SENSITIVE_PATHS:
        url = base_url.rstrip("/") + path
        response, error = fetch(client, url, follow_redirects=False, timeout=10)
        status = response.status_code if response else None
        if error:
            result = "Ошибка запроса"
            comment = error
        elif status in {401, 403, 404}:
            result = "OK"
            comment = "Файл не доступен публично"
        else:
            result = "Проверить"
            comment = "Служебный файл может быть доступен публично"
        checks.append(
            {
                "check": f"Доступ к {path}",
                "url": url,
                "status_code": status,
                "location": response.headers.get("location", "") if response else "",
                "result": result,
                "comment": comment,
            }
        )

    return checks


# ------------------------------ Full site MVP ------------------------------


def run_audit(raw_url: str, max_urls: int = 50, delay_sec: float = 0.1) -> Dict[str, object]:
    base_url = normalize_base_url(raw_url)

    with httpx.Client(headers=DEFAULT_HEADERS, timeout=20) as client:
        robots = check_robots(client, base_url)
        robot_parser = build_robot_parser(robots, client)
        sitemap_candidates = discover_sitemaps(client, base_url, robots)
        sitemap_urls, sitemap_results = collect_sitemap_urls(client, sitemap_candidates, max_urls=max_urls)

        page_results: List[PageResult] = []
        for url in sitemap_urls:
            page_results.append(check_page(client, url, robot_parser))
            if delay_sec > 0:
                time.sleep(delay_sec)

        behavior = check_server_behavior(client, base_url)

    score = calculate_score(robots, sitemap_results, page_results, behavior)

    return {
        "base_url": base_url,
        "score": score,
        "robots": asdict(robots),
        "sitemaps_discovered": sitemap_candidates,
        "sitemaps": [asdict(item) for item in sitemap_results],
        "pages": [asdict(item) for item in page_results],
        "behavior": behavior,
        "summary": build_summary(robots, sitemap_results, page_results, behavior),
    }


def calculate_score(
    robots: RobotsResult,
    sitemaps: List[SitemapResult],
    pages: List[PageResult],
    behavior: List[Dict[str, object]],
) -> int:
    score = 100

    if not robots.exists:
        score -= 20
    score -= min(len(robots.warnings) * 4, 20)

    if not sitemaps:
        score -= 20
    for sitemap in sitemaps:
        if sitemap.status_code != 200:
            score -= 8
        score -= min(len(sitemap.warnings) * 3, 12)

    for page in pages:
        if page.status_code is None or page.status_code >= 400:
            score -= 4
        elif page.status_code in REDIRECT_STATUSES or page.redirect_count > 0:
            score -= 2
        score -= min(len(page.html_warnings), 5)

    for item in behavior:
        if item.get("result") == "Проверить":
            score -= 5

    return max(0, min(100, score))


def build_summary(
    robots: RobotsResult,
    sitemaps: List[SitemapResult],
    pages: List[PageResult],
    behavior: List[Dict[str, object]],
) -> Dict[str, object]:
    critical: List[str] = []
    warnings: List[str] = []

    if not robots.exists:
        critical.append("robots.txt не найден или недоступен")
    warnings.extend([f"robots.txt: {warning}" for warning in robots.warnings])

    if not sitemaps:
        critical.append("Sitemap не найден")

    for sitemap in sitemaps:
        for warning in sitemap.warnings:
            warnings.append(f"sitemap: {warning}")

    for page in pages:
        if page.status_code is None:
            critical.append(f"URL не удалось получить: {page.url}")
        elif page.status_code >= 400:
            critical.append(f"URL отдаёт {page.status_code}: {page.url}")
        for warning in page.html_warnings:
            if "noindex" in warning.lower() or "закрыт" in warning.lower():
                critical.append(f"{warning}: {page.url}")
            else:
                warnings.append(f"{warning}: {page.url}")

    for item in behavior:
        if item.get("result") == "Проверить":
            critical.append(f"{item.get('check')}: {item.get('comment')}")

    return {
        "critical_count": len(critical),
        "warning_count": len(warnings),
        "critical": critical[:50],
        "warnings": warnings[:100],
        "pages_checked": len(pages),
        "sitemaps_checked": len(sitemaps),
    }


def pages_to_csv(pages: List[Dict[str, object]]) -> str:
    output = io.StringIO()
    fieldnames = [
        "url",
        "status_code",
        "final_url",
        "redirect_count",
        "blocked_googlebot",
        "blocked_yandexbot",
        "title",
        "title_len",
        "description",
        "description_len",
        "h1_count",
        "h1_text",
        "canonical",
        "meta_robots",
        "html_warnings",
        "error",
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for page in pages:
        row = dict(page)
        warnings = row.get("html_warnings")
        if isinstance(warnings, list):
            row["html_warnings"] = " | ".join(warnings)
        writer.writerow(row)
    return output.getvalue()
