from __future__ import annotations

import html
from difflib import SequenceMatcher
from typing import Dict, List, Sequence

import pandas as pd
import streamlit as st

from seo_checker import (
    analyze_htaccess_text,
    analyze_robots_text,
    analyze_sitemap_text,
    analyze_technical_duplicates,
    check_robots_url_list,
    check_urls_status,
    decode_upload,
    load_robots_from_url,
    load_sitemap_from_url,
    pages_to_csv,
    run_audit,
)


st.set_page_config(
    page_title="SEO File Auditor",
    page_icon="🔎",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ----------------------------- UI helpers -----------------------------


def inject_css() -> None:
    st.markdown(
        """
        <style>
        .block-container {
            padding-top: 1.5rem;
            padding-bottom: 2rem;
            max-width: 1400px;
        }
        .app-subtitle {
            color: #6b7280;
            font-size: 0.98rem;
            margin-top: -0.25rem;
            margin-bottom: 1rem;
        }
        .hero-box, .info-box, .issue-box, .table-box {
            border: 1px solid rgba(120, 120, 120, 0.18);
            border-radius: 18px;
            padding: 1rem 1.1rem;
            background: linear-gradient(180deg, rgba(255,255,255,0.98), rgba(249,250,251,0.96));
            margin-bottom: 0.9rem;
        }
        .metric-card {
            border: 1px solid rgba(120, 120, 120, 0.18);
            border-radius: 18px;
            padding: 1rem 1.05rem;
            background: linear-gradient(180deg, rgba(255,255,255,0.98), rgba(248,250,252,0.96));
            min-height: 112px;
            box-shadow: 0 1px 2px rgba(0,0,0,0.02);
        }
        .metric-label {
            font-size: 0.85rem;
            color: #6b7280;
            margin-bottom: 0.35rem;
        }
        .metric-value {
            font-size: 1.85rem;
            font-weight: 700;
            line-height: 1.1;
            color: #111827;
        }
        .metric-note {
            font-size: 0.83rem;
            color: #6b7280;
            margin-top: 0.45rem;
        }
        .status-pill {
            display: inline-block;
            padding: 0.28rem 0.7rem;
            border-radius: 999px;
            font-size: 0.8rem;
            font-weight: 600;
            margin-bottom: 0.55rem;
        }
        .pill-ok { background: #ecfdf3; color: #027a48; }
        .pill-warn { background: #fffaeb; color: #b54708; }
        .pill-bad { background: #fef3f2; color: #b42318; }
        .section-title {
            font-size: 1.15rem;
            font-weight: 700;
            margin-bottom: 0.55rem;
            color: #111827;
        }
        .muted {
            color: #6b7280;
            font-size: 0.92rem;
        }
        .sidebar-help {
            color: #6b7280;
            font-size: 0.88rem;
            line-height: 1.45;
        }

        .url-diff-wrap {
            overflow-x: auto;
            border: 1px solid rgba(120, 120, 120, 0.18);
            border-radius: 16px;
            margin-top: 0.75rem;
            margin-bottom: 0.75rem;
        }
        .url-diff-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.88rem;
        }
        .url-diff-table th {
            text-align: left;
            padding: 0.75rem 0.8rem;
            background: #f8fafc;
            color: #374151;
            border-bottom: 1px solid rgba(120, 120, 120, 0.18);
            white-space: nowrap;
        }
        .url-diff-table td {
            padding: 0.7rem 0.8rem;
            border-bottom: 1px solid rgba(120, 120, 120, 0.12);
            vertical-align: top;
        }
        .url-diff-table tr:last-child td {
            border-bottom: none;
        }
        .url-cell {
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', monospace;
            word-break: break-all;
            line-height: 1.45;
            min-width: 300px;
        }
        .diff-change {
            background: #fff3bf;
            color: #7a4b00;
            border-radius: 5px;
            padding: 0.05rem 0.12rem;
            font-weight: 700;
        }
        .diff-empty {
            color: #9ca3af;
        }
        .issue-badge {
            display: inline-block;
            padding: 0.2rem 0.55rem;
            border-radius: 999px;
            font-size: 0.78rem;
            font-weight: 700;
            white-space: nowrap;
        }
        .issue-ok { background: #ecfdf3; color: #027a48; }
        .issue-warn { background: #fffaeb; color: #b54708; }
        .issue-bad { background: #fef3f2; color: #b42318; }
        </style>
        """,
        unsafe_allow_html=True,
    )


def df_to_csv(df: pd.DataFrame) -> bytes:
    return df.to_csv(index=False).encode("utf-8-sig")


def html_escape(value: object) -> str:
    return html.escape("" if value is None else str(value))


def highlight_url_diff(left: object, right: object) -> tuple[str, str]:
    """Return two HTML-safe URL strings with different fragments highlighted."""
    left_s = "" if left is None else str(left)
    right_s = "" if right is None else str(right)
    if left_s == right_s:
        safe = html_escape(left_s) or "<span class='diff-empty'>—</span>"
        return safe, safe

    matcher = SequenceMatcher(None, left_s, right_s)
    left_parts: List[str] = []
    right_parts: List[str] = []

    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        left_chunk = html_escape(left_s[i1:i2])
        right_chunk = html_escape(right_s[j1:j2])
        if tag == "equal":
            left_parts.append(left_chunk)
            right_parts.append(right_chunk)
        elif tag == "delete":
            left_parts.append(f"<span class='diff-change'>{left_chunk}</span>")
        elif tag == "insert":
            right_parts.append(f"<span class='diff-change'>{right_chunk}</span>")
        else:
            left_parts.append(f"<span class='diff-change'>{left_chunk}</span>")
            right_parts.append(f"<span class='diff-change'>{right_chunk}</span>")

    left_html = "".join(left_parts) or "<span class='diff-empty'>—</span>"
    right_html = "".join(right_parts) or "<span class='diff-empty'>—</span>"
    return left_html, right_html


def issue_badge(issue: object) -> str:
    issue_text = html_escape(issue or "OK")
    issue_lower = str(issue or "").lower()
    if issue_lower == "ok":
        cls = "issue-ok"
    elif "петля" in issue_lower or "много" in issue_lower or "ошибка" in issue_lower or "статус" in issue_lower:
        cls = "issue-bad"
    else:
        cls = "issue-warn"
    return f"<span class='issue-badge {cls}'>{issue_text}</span>"


def render_duplicate_url_diff_table(rows: List[Dict[str, object]], *, limit: int = 200) -> None:
    """Render technical duplicate rows with highlighted URL differences."""
    visible_rows = rows[:limit]
    table_rows: List[str] = []
    for row in visible_rows:
        start_html, final_html = highlight_url_diff(row.get("start_url"), row.get("final_url"))
        table_rows.append(
            "<tr>"
            f"<td class='url-cell'>{start_html}</td>"
            f"<td class='url-cell'>{final_html}</td>"
            f"<td>{html_escape(row.get('final_status') or '—')}</td>"
            f"<td>{html_escape(row.get('redirect_count') or 0)}</td>"
            f"<td>{html_escape(row.get('status_chain') or '—')}</td>"
            f"<td>{issue_badge(row.get('issue'))}</td>"
            f"<td>{html_escape(row.get('recommendation') or '')}</td>"
            "</tr>"
        )

    if not table_rows:
        st.info("Результаты пока не получены")
        return

    if len(rows) > limit:
        st.caption(f"Показаны первые {limit} строк из {len(rows)}. Полный отчёт доступен в CSV.")

    html_table = (
        "<div class='url-diff-wrap'><table class='url-diff-table'>"
        "<thead><tr>"
        "<th>Стартовый URL</th>"
        "<th>Финальный URL</th>"
        "<th>Статус</th>"
        "<th>Редиректы</th>"
        "<th>Цепочка</th>"
        "<th>Проблема</th>"
        "<th>Рекомендация</th>"
        "</tr></thead><tbody>"
        + "".join(table_rows)
        + "</tbody></table></div>"
    )
    st.markdown(html_table, unsafe_allow_html=True)
    st.caption("Жёлтым подсвечены фрагменты, которыми стартовый и финальный URL отличаются в конкретной строке.")


def render_similar_pair_diff_table(rows: List[Dict[str, object]], *, limit: int = 200) -> None:
    visible_rows = rows[:limit]
    table_rows: List[str] = []
    for row in visible_rows:
        url_1_html, url_2_html = highlight_url_diff(row.get("url_1"), row.get("url_2"))
        table_rows.append(
            "<tr>"
            f"<td class='url-cell'>{url_1_html}</td>"
            f"<td class='url-cell'>{url_2_html}</td>"
            f"<td>{html_escape(row.get('title_same'))}</td>"
            f"<td>{html_escape(row.get('canonical_same'))}</td>"
            f"<td>{html_escape(row.get('text_similarity'))}</td>"
            "</tr>"
        )

    if not table_rows:
        st.info("Подозрительно похожие финальные страницы не найдены")
        return

    html_table = (
        "<div class='url-diff-wrap'><table class='url-diff-table'>"
        "<thead><tr>"
        "<th>URL 1</th>"
        "<th>URL 2</th>"
        "<th>Title совпадает</th>"
        "<th>Canonical совпадает</th>"
        "<th>Сходство текста</th>"
        "</tr></thead><tbody>"
        + "".join(table_rows)
        + "</tbody></table></div>"
    )
    st.markdown(html_table, unsafe_allow_html=True)
    st.caption("Жёлтым подсвечены отличающиеся части URL в паре похожих страниц.")


def status_kind_from_counts(critical: int = 0, warnings: int = 0) -> str:
    if critical > 0:
        return "bad"
    if warnings > 0:
        return "warn"
    return "ok"


def score_status(score: int) -> tuple[str, str, str]:
    if score >= 85:
        return "Отлично", "ok", "Сайт в хорошем состоянии, найдены только точечные замечания."
    if score >= 70:
        return "Нормально", "warn", "Есть заметные замечания, но критических рисков немного."
    return "Нужно исправлять", "bad", "Найдено много проблем, стоит начать с критичных пунктов."


def render_metric_cards(items: Sequence[Dict[str, str]]) -> None:
    cols = st.columns(len(items))
    for col, item in zip(cols, items):
        with col:
            note = item.get("note", "")
            st.markdown(
                f"""
                <div class="metric-card">
                    <div class="metric-label">{item.get('label', '')}</div>
                    <div class="metric-value">{item.get('value', '')}</div>
                    <div class="metric-note">{note}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )


def render_section_header(title: str, text: str = "") -> None:
    st.markdown(f"<div class='section-title'>{title}</div>", unsafe_allow_html=True)
    if text:
        st.markdown(f"<div class='muted'>{text}</div>", unsafe_allow_html=True)


def render_status_box(title: str, body: str, kind: str = "ok") -> None:
    label_map = {"ok": "В порядке", "warn": "Есть замечания", "bad": "Критично"}
    st.markdown(
        f"""
        <div class="info-box">
            <div class="status-pill pill-{kind}">{label_map.get(kind, 'Статус')}</div>
            <div class="section-title">{title}</div>
            <div class="muted">{body}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_issue_list(title: str, items: List[str], level: str = "warning", empty_text: str = "Замечаний не найдено") -> None:
    render_section_header(title)
    if not items:
        st.success(empty_text)
        return
    for item in items:
        if level == "error":
            st.error(item)
        elif level == "info":
            st.info(item)
        else:
            st.warning(item)


def normalize_bool(value) -> str:
    if value is True:
        return "Да"
    if value is False:
        return "Нет"
    return "—"


def build_quick_actions(critical: List[str], warnings: List[str], limit: int = 6) -> List[str]:
    items: List[str] = []
    for item in critical:
        items.append(item)
        if len(items) >= limit:
            return items
    for item in warnings:
        items.append(item)
        if len(items) >= limit:
            return items
    return items


def summarize_robots(robots: Dict[str, object]) -> Dict[str, object]:
    warnings = list(robots.get("warnings") or [])
    status_code = robots.get("status_code")
    groups = robots.get("groups") or []
    disallow_root = any("/" in str(group.get("disallow", "")) for group in groups if "*" in str(group.get("user_agents", "")))
    critical = []
    if not robots.get("exists"):
        critical.append("Файл robots.txt не найден или недоступен.")
    if disallow_root:
        critical.append("Для User-agent: * найдено правило, которое может закрывать сайт целиком.")
    status = status_kind_from_counts(len(critical), len(warnings))
    body = f"Статус ответа: {status_code or '—'}. Найдено sitemap: {len(robots.get('sitemaps') or [])}. Групп правил: {len(groups)}."
    return {"critical": critical, "warnings": warnings, "status": status, "body": body}


def summarize_sitemap(data: Dict[str, object]) -> Dict[str, object]:
    warnings = list(data.get("warnings") or [])
    critical = []
    if data.get("status_code") not in (None, 200):
        critical.append(f"Sitemap отдаёт статус {data.get('status_code')}, ожидается 200.")
    if data.get("type") in {"invalid", "error", "unknown"}:
        critical.append("Файл sitemap не распознан корректно.")
    if not data.get("urls_found") and not data.get("nested_found"):
        critical.append("В sitemap не найдено URL или вложенных sitemap.")
    status = status_kind_from_counts(len(critical), len(warnings))
    body = (
        f"Тип: {data.get('type') or '—'}. URL: {data.get('urls_found') or 0}. "
        f"Вложенных sitemap: {data.get('nested_found') or 0}."
    )
    return {"critical": critical, "warnings": warnings, "status": status, "body": body}


def summarize_htaccess(data: Dict[str, object]) -> Dict[str, object]:
    warnings = list(data.get("warnings") or [])
    positives = list(data.get("positives") or [])
    critical = []
    if not data.get("raw_text"):
        critical.append("Файл .htaccess пустой или не загружен.")
    status = status_kind_from_counts(len(critical), len(warnings))
    body = f"Позитивных признаков: {len(positives)}. Замечаний: {len(warnings)}. Строк: {data.get('lines_total') or 0}."
    return {"critical": critical, "warnings": warnings, "positives": positives, "status": status, "body": body}


def summarize_duplicates(data: Dict[str, object]) -> Dict[str, object]:
    summary = data.get("summary") or {}
    warnings = list(data.get("warnings") or [])
    critical = []
    if summary.get("redirect_loops", 0) > 0:
        critical.append("Найдены длинные или зацикленные цепочки редиректов.")
    if summary.get("possible_duplicates", 0) > 0:
        critical.append("Есть URL, которые могут создавать технические дубли.")
    status = status_kind_from_counts(len(critical), len(warnings))
    body = (
        f"Проверено вариантов: {summary.get('variants_checked', 0)}. "
        f"Цепочек редиректов: {summary.get('redirect_chains', 0)}. "
        f"Возможных дублей: {summary.get('possible_duplicates', 0)}."
    )
    return {"critical": critical, "warnings": warnings, "status": status, "body": body}


def prepare_pages_df(pages: List[Dict[str, object]]) -> pd.DataFrame:
    df = pd.DataFrame(pages)
    if df.empty:
        return df
    df = df.copy()
    df["html_warnings"] = df["html_warnings"].apply(lambda x: " | ".join(x) if isinstance(x, list) else x)
    df["blocked_googlebot"] = df["blocked_googlebot"].apply(normalize_bool)
    df["blocked_yandexbot"] = df["blocked_yandexbot"].apply(normalize_bool)
    df = df.rename(
        columns={
            "url": "URL",
            "status_code": "Статус",
            "final_url": "Финальный URL",
            "redirect_count": "Редиректы",
            "blocked_googlebot": "Закрыт Googlebot",
            "blocked_yandexbot": "Закрыт YandexBot",
            "title": "Title",
            "title_len": "Длина Title",
            "description": "Description",
            "description_len": "Длина Description",
            "h1_count": "H1, шт.",
            "h1_text": "H1",
            "canonical": "Canonical",
            "meta_robots": "Meta robots",
            "html_warnings": "Замечания",
            "error": "Ошибка",
        }
    )
    return df


def prepare_behavior_df(rows: List[Dict[str, object]]) -> pd.DataFrame:
    df = pd.DataFrame(rows)
    if df.empty:
        return df
    return df.rename(
        columns={
            "check": "Проверка",
            "url": "URL",
            "status_code": "Статус",
            "location": "Location",
            "result": "Результат",
            "comment": "Комментарий",
        }
    )


def render_download(df: pd.DataFrame, label: str, filename: str, key: str) -> None:
    st.download_button(
        label,
        data=df_to_csv(df),
        file_name=filename,
        mime="text/csv",
        key=key,
    )


# ----------------------------- Page renderers -----------------------------


def render_main_audit(max_urls_default: int, delay_default: float) -> None:
    st.title("SEO File Auditor")
    st.markdown(
        "<div class='app-subtitle'>Общая проверка сайта: robots.txt, sitemap.xml, URL из sitemap, базовые SEO-теги и поведение сервера.</div>",
        unsafe_allow_html=True,
    )

    with st.container():
        col1, col2 = st.columns([3, 1])
        url = col1.text_input("Домен или URL сайта", placeholder="https://example.com", key="main_site_url")
        run = col2.button("Проверить сайт", type="primary", use_container_width=True, disabled=not url.strip(), key="main_run")

    if run:
        with st.spinner("Проверяю сайт..."):
            try:
                result = run_audit(url, max_urls=max_urls_default, delay_sec=delay_default)
                st.session_state["audit_result"] = result
            except Exception as exc:
                st.error(f"Ошибка проверки: {exc}")

    result = st.session_state.get("audit_result")
    if not result:
        render_status_box(
            "Как использовать",
            "Введите домен и запустите проверку. Отчёт покажет приоритетные ошибки, файлы robots/sitemap, анализ страниц и базовую проверку серверных настроек.",
            kind="ok",
        )
        return

    score = int(result.get("score", 0))
    summary = result.get("summary") or {}
    score_label, score_kind, score_text = score_status(score)

    st.markdown("---")
    render_metric_cards(
        [
            {"label": "Итоговая оценка", "value": f"{score}/100", "note": score_label},
            {"label": "Критичные ошибки", "value": str(summary.get("critical_count", 0)), "note": "Исправлять в первую очередь"},
            {"label": "Предупреждения", "value": str(summary.get("warning_count", 0)), "note": "Требуют внимания"},
            {"label": "Проверено URL", "value": str(summary.get("pages_checked", 0)), "note": "URL из sitemap"},
        ]
    )

    left, right = st.columns([1.2, 1])
    with left:
        render_status_box("Быстрый вывод по сайту", score_text, kind=score_kind)
    with right:
        quick_actions = build_quick_actions(list(summary.get("critical") or []), list(summary.get("warnings") or []), limit=5)
        render_issue_list("Что проверить в первую очередь", quick_actions, level="warning", empty_text="Критичных задач не найдено")

    tab_overview, tab_files, tab_pages, tab_server, tab_export = st.tabs(
        ["Обзор", "Файлы", "Страницы", "Сервер", "Экспорт"]
    )

    with tab_overview:
        render_issue_list(
            "Критичные ошибки",
            list(summary.get("critical") or []),
            level="error",
            empty_text="Критичных ошибок не найдено.",
        )
        render_issue_list(
            "Предупреждения",
            list(summary.get("warnings") or []),
            level="warning",
            empty_text="Предупреждений не найдено.",
        )

    with tab_files:
        robots_summary = summarize_robots(result.get("robots") or {})
        sitemaps_discovered = result.get("sitemaps_discovered") or []
        sitemap_rows = result.get("sitemaps") or []

        col1, col2 = st.columns(2)
        with col1:
            render_status_box("robots.txt", robots_summary["body"], kind=robots_summary["status"])
            render_issue_list("Замечания по robots.txt", robots_summary["warnings"], level="warning")
        with col2:
            if sitemap_rows:
                total_warnings = sum(len(item.get("warnings") or []) for item in sitemap_rows)
                kind = status_kind_from_counts(0, total_warnings)
                render_status_box(
                    "Sitemap",
                    f"Найдено файлов: {len(sitemap_rows)}. Обнаружено по robots/common paths: {len(sitemaps_discovered)}.",
                    kind=kind,
                )
            else:
                render_status_box("Sitemap", "Файл sitemap не найден автоматически.", kind="bad")
            if sitemaps_discovered:
                st.dataframe(pd.DataFrame({"Найденные sitemap": sitemaps_discovered}), use_container_width=True)
            else:
                st.warning("Sitemap не найден")

        if sitemap_rows:
            df_sitemaps = pd.DataFrame(sitemap_rows).rename(
                columns={
                    "sitemap_url": "Sitemap URL",
                    "status_code": "Статус",
                    "type": "Тип",
                    "urls_found": "URL найдено",
                    "urls_checked": "URL проверено",
                    "nested_sitemaps": "Вложенные sitemap",
                    "warnings": "Замечания",
                    "error": "Ошибка",
                }
            )
            df_sitemaps["Замечания"] = df_sitemaps["Замечания"].apply(lambda x: " | ".join(x) if isinstance(x, list) else x)
            df_sitemaps["Вложенные sitemap"] = df_sitemaps["Вложенные sitemap"].apply(lambda x: " | ".join(x) if isinstance(x, list) else x)
            st.dataframe(df_sitemaps, use_container_width=True)

    with tab_pages:
        pages = result.get("pages") or []
        if not pages:
            st.warning("Нет URL для проверки. Возможно, sitemap не найден или пустой.")
        else:
            status_ok = sum(1 for page in pages if page.get("status_code") == 200)
            redirects = sum(1 for page in pages if (page.get("redirect_count") or 0) > 0)
            blocked = sum(1 for page in pages if page.get("blocked_googlebot") or page.get("blocked_yandexbot"))
            page_warnings = sum(1 for page in pages if page.get("html_warnings"))
            render_metric_cards(
                [
                    {"label": "URL со статусом 200", "value": str(status_ok), "note": "Из проверенных страниц"},
                    {"label": "URL с редиректами", "value": str(redirects), "note": "Есть хотя бы один переход"},
                    {"label": "Закрытые URL", "value": str(blocked), "note": "По robots.txt"},
                    {"label": "Страницы с замечаниями", "value": str(page_warnings), "note": "HTML и мета-теги"},
                ]
            )
            df_pages = prepare_pages_df(pages)
            st.dataframe(df_pages, use_container_width=True)

    with tab_server:
        behavior = result.get("behavior") or []
        if not behavior:
            st.info("Нет данных по серверным проверкам.")
        else:
            checks_to_review = [row for row in behavior if row.get("result") == "Проверить"]
            if checks_to_review:
                render_issue_list(
                    "Что требует внимания",
                    [f"{row.get('check')}: {row.get('comment')}" for row in checks_to_review],
                    level="warning",
                    empty_text="Критичных замечаний нет",
                )
            st.dataframe(prepare_behavior_df(behavior), use_container_width=True)

    with tab_export:
        st.markdown("### Экспорт отчётов")
        pages = result.get("pages") or []
        if pages:
            pages_csv = pages_to_csv(pages)
            st.download_button(
                label="Скачать отчёт по страницам CSV",
                data=pages_csv.encode("utf-8-sig"),
                file_name="seo_pages_report.csv",
                mime="text/csv",
                key="main_export_pages_csv",
            )
        if result.get("sitemaps"):
            sitemap_df = pd.DataFrame(result.get("sitemaps") or [])
            render_download(sitemap_df, "Скачать отчёт по sitemap CSV", "seo_sitemaps_report.csv", "main_export_sitemap_csv")
        if result.get("behavior"):
            behavior_df = prepare_behavior_df(result.get("behavior") or [])
            render_download(behavior_df, "Скачать серверные проверки CSV", "seo_server_checks.csv", "main_export_server_csv")
        st.caption("Файлы CSV можно открыть в Excel, Google Sheets или Numbers.")


def render_robots_lab() -> None:
    st.title("robots.txt")
    st.markdown(
        "<div class='app-subtitle'>Точечная проверка robots.txt: загрузка файла, анализ директив и массовая проверка URL по правилам.</div>",
        unsafe_allow_html=True,
    )

    source_mode = st.radio(
        "Источник robots.txt",
        ["Ссылка на файл", "Загрузить файл", "Вставить текст"],
        horizontal=True,
        key="robots_source_mode",
    )
    robots_base_url = st.text_input(
        "Базовый домен для относительных Sitemap, если файл загружен вручную",
        placeholder="https://example.com",
        key="robots_base_url",
    )

    if source_mode == "Ссылка на файл":
        robots_url = st.text_input("URL robots.txt", placeholder="https://example.com/robots.txt", key="robots_url_input")
        if st.button("Проверить robots.txt", type="primary", disabled=not robots_url.strip(), key="robots_url_run"):
            with st.spinner("Загружаю и анализирую robots.txt..."):
                st.session_state["robots_lab_result"] = load_robots_from_url(robots_url).__dict__
    elif source_mode == "Загрузить файл":
        uploaded_robots = st.file_uploader("Загрузить robots.txt", key="robots_upload")
        if st.button("Анализировать файл", type="primary", disabled=uploaded_robots is None, key="robots_file_run"):
            text = decode_upload(uploaded_robots)
            st.session_state["robots_lab_result"] = analyze_robots_text(text, source_label=uploaded_robots.name, base_url=robots_base_url.strip()).__dict__
    else:
        robots_text = st.text_area("Содержимое robots.txt", height=260, key="robots_text_input")
        if st.button("Анализировать текст", type="primary", disabled=not robots_text.strip(), key="robots_text_run"):
            st.session_state["robots_lab_result"] = analyze_robots_text(robots_text, source_label="manual robots.txt", base_url=robots_base_url.strip()).__dict__

    robots_data = st.session_state.get("robots_lab_result")
    if not robots_data:
        render_status_box(
            "Как использовать",
            "Можно указать ссылку на файл, загрузить robots.txt с компьютера или вставить текст вручную. После анализа ниже появится проверка списка URL по директивам файла.",
            kind="ok",
        )
        return

    summary = summarize_robots(robots_data)
    render_metric_cards(
        [
            {"label": "HTTP-статус", "value": str(robots_data.get("status_code") or "—"), "note": "Код ответа файла"},
            {"label": "Размер файла", "value": f"{robots_data.get('size_bytes', 0)} Б", "note": "Объём robots.txt"},
            {"label": "Sitemap", "value": str(len(robots_data.get("sitemaps") or [])), "note": "Найдено в файле"},
            {"label": "Директивы", "value": str(robots_data.get("rules_total") or 0), "note": "Всего правил"},
        ]
    )

    left, right = st.columns([1, 1])
    with left:
        render_status_box("Вывод по robots.txt", summary["body"], kind=summary["status"])
        render_issue_list("Критичные моменты", summary["critical"], level="error", empty_text="Критичных проблем не найдено")
    with right:
        render_issue_list("Замечания и рекомендации", summary["warnings"], level="warning")

    tab_overview, tab_rules, tab_check, tab_source = st.tabs(["Обзор", "Правила", "Проверка URL", "Исходник"])

    with tab_overview:
        sitemaps = robots_data.get("sitemaps") or []
        groups = robots_data.get("groups") or []
        st.markdown("#### Sitemap из robots.txt")
        if sitemaps:
            df_sitemaps = pd.DataFrame({"Sitemap URL": sitemaps})
            st.dataframe(df_sitemaps, use_container_width=True)
            render_download(df_sitemaps, "Скачать Sitemap CSV", "robots_sitemaps.csv", "robots_sitemaps_csv")
        else:
            st.warning("В robots.txt не указан Sitemap")

        st.markdown("#### Группы правил")
        if groups:
            df_groups = pd.DataFrame(groups).rename(
                columns={
                    "user_agents": "User-agent",
                    "allow_count": "Allow, шт.",
                    "disallow_count": "Disallow, шт.",
                    "allow": "Allow",
                    "disallow": "Disallow",
                    "crawl_delay": "Crawl-delay",
                    "clean_param": "Clean-param",
                    "other": "Другие директивы",
                }
            )
            st.dataframe(df_groups, use_container_width=True)
            render_download(df_groups, "Скачать группы robots CSV", "robots_groups.csv", "robots_groups_csv")
        else:
            st.warning("Группы User-agent не найдены")

    with tab_rules:
        directives = robots_data.get("directives") or []
        if directives:
            df_directives = pd.DataFrame(directives).rename(
                columns={"line": "Строка", "directive": "Директива", "value": "Значение"}
            )
            st.dataframe(df_directives, use_container_width=True)
            render_download(df_directives, "Скачать директивы CSV", "robots_directives.csv", "robots_directives_csv")
        else:
            st.info("Директивы не найдены")

    with tab_check:
        st.markdown("#### Проверка списка URL по директивам robots.txt")
        check_urls_text = st.text_area(
            "URL для проверки — по одному на строку",
            height=180,
            placeholder="https://example.com/\nhttps://example.com/catalog/\nhttps://example.com/admin/",
            key="robots_check_urls",
        )
        selected_agents = st.multiselect(
            "User-agent",
            ["Googlebot", "YandexBot", "*"],
            default=["Googlebot", "YandexBot"],
            key="robots_check_agents",
        )
        if st.button("Проверить URL", disabled=not check_urls_text.strip() or not selected_agents, key="robots_check_urls_run"):
            st.session_state["robots_url_check_result"] = check_robots_url_list(robots_data, check_urls_text, selected_agents)

        rows = st.session_state.get("robots_url_check_result")
        if rows:
            df = pd.DataFrame(rows)
            allowed_col = None
            if "allowed" in df.columns:
                allowed_col = "allowed"
                open_count = int((df[allowed_col] == True).sum())
                closed_count = int((df[allowed_col] == False).sum())
                unknown_count = int(df[allowed_col].isna().sum())
                render_metric_cards(
                    [
                        {"label": "Открыта", "value": str(open_count), "note": "URL разрешены"},
                        {"label": "Закрыта", "value": str(closed_count), "note": "URL запрещены"},
                        {"label": "Не определено", "value": str(unknown_count), "note": "Не удалось распознать"},
                    ]
                )
            rename_map = {
                "url": "URL",
                "user_agent": "User-agent",
                "allowed": "Открыта",
                "matched_rule": "Сработавшее правило",
                "matched_group": "Группа правил",
                "comment": "Комментарий",
            }
            df = df.rename(columns=rename_map)
            if "Открыта" in df.columns:
                df["Открыта"] = df["Открыта"].apply(normalize_bool)
            st.dataframe(df, use_container_width=True)
            render_download(df, "Скачать проверку URL CSV", "robots_url_access_check.csv", "robots_url_check_csv")

    with tab_source:
        st.code(str(robots_data.get("raw_text") or ""), language="text")


def render_sitemap_lab() -> None:
    st.title("sitemap.xml")
    st.markdown(
        "<div class='app-subtitle'>Точечная проверка sitemap: загрузка файла, анализ XML-структуры и проверка статус-кодов URL.</div>",
        unsafe_allow_html=True,
    )

    source_mode = st.radio(
        "Источник sitemap",
        ["Ссылка на файл", "Загрузить файл", "Вставить XML"],
        horizontal=True,
        key="sitemap_source_mode",
    )

    if source_mode == "Ссылка на файл":
        sitemap_url = st.text_input("URL sitemap", placeholder="https://example.com/sitemap.xml", key="sitemap_url_input")
        if st.button("Проверить sitemap", type="primary", disabled=not sitemap_url.strip(), key="sitemap_url_run"):
            with st.spinner("Загружаю и анализирую sitemap..."):
                st.session_state["sitemap_lab_result"] = load_sitemap_from_url(sitemap_url)
    elif source_mode == "Загрузить файл":
        uploaded_sitemap = st.file_uploader("Загрузить sitemap.xml", key="sitemap_upload")
        if st.button("Анализировать файл", type="primary", disabled=uploaded_sitemap is None, key="sitemap_file_run"):
            text = decode_upload(uploaded_sitemap)
            st.session_state["sitemap_lab_result"] = analyze_sitemap_text(text, source_label=uploaded_sitemap.name)
    else:
        sitemap_text = st.text_area("Содержимое sitemap.xml", height=260, key="sitemap_text_input")
        if st.button("Анализировать XML", type="primary", disabled=not sitemap_text.strip(), key="sitemap_text_run"):
            st.session_state["sitemap_lab_result"] = analyze_sitemap_text(sitemap_text, source_label="manual sitemap")

    sitemap_data = st.session_state.get("sitemap_lab_result")
    if not sitemap_data:
        render_status_box(
            "Как использовать",
            "Можно указать ссылку на sitemap, загрузить XML-файл или вставить содержимое вручную. После анализа сервис покажет структуру файла, URL и найденные проблемы.",
            kind="ok",
        )
        return

    summary = summarize_sitemap(sitemap_data)
    render_metric_cards(
        [
            {"label": "HTTP-статус", "value": str(sitemap_data.get("status_code") or "—"), "note": "Код ответа файла"},
            {"label": "Тип файла", "value": str(sitemap_data.get("type") or "—"), "note": "urlset / sitemap_index"},
            {"label": "URL найдено", "value": str(sitemap_data.get("urls_found") or 0), "note": "Внутри sitemap"},
            {"label": "Вложенных sitemap", "value": str(sitemap_data.get("nested_found") or 0), "note": "Если это sitemap index"},
        ]
    )

    left, right = st.columns([1, 1])
    with left:
        render_status_box("Вывод по sitemap", summary["body"], kind=summary["status"])
        render_issue_list("Критичные моменты", summary["critical"], level="error", empty_text="Критичных проблем не найдено")
    with right:
        render_issue_list("Замечания и рекомендации", summary["warnings"], level="warning")

    tab_overview, tab_status, tab_source = st.tabs(["Обзор", "Проверка URL", "Исходник"])

    with tab_overview:
        urls = sitemap_data.get("urls") or []
        nested = sitemap_data.get("nested_sitemaps") or []
        if urls:
            df_urls = pd.DataFrame(urls)
            st.markdown("#### URL из sitemap")
            st.dataframe(df_urls, use_container_width=True)
            render_download(df_urls, "Скачать URL из sitemap CSV", "sitemap_urls.csv", "sitemap_urls_csv")
        else:
            st.info("URL в sitemap не найдены")

        if nested:
            df_nested = pd.DataFrame(nested)
            st.markdown("#### Вложенные sitemap")
            st.dataframe(df_nested, use_container_width=True)
            render_download(df_nested, "Скачать вложенные sitemap CSV", "sitemap_index.csv", "sitemap_nested_csv")

    with tab_status:
        sitemap_urls = [item.get("loc", "") for item in sitemap_data.get("urls", []) if item.get("loc")]
        if not sitemap_urls:
            st.info("В этом sitemap нет URL для проверки статус-кодов.")
        else:
            col1, col2 = st.columns(2)
            sitemap_max_urls = col1.slider(
                "Сколько URL проверить",
                min_value=1,
                max_value=min(1000, len(sitemap_urls)),
                value=min(50, len(sitemap_urls)),
                step=1,
                key="sitemap_status_max",
            )
            sitemap_delay = col2.slider(
                "Пауза между запросами, сек.",
                min_value=0.0,
                max_value=2.0,
                value=0.05,
                step=0.05,
                key="sitemap_status_delay",
            )
            if st.button("Проверить статус-коды URL", key="sitemap_status_run"):
                with st.spinner("Проверяю URL из sitemap..."):
                    st.session_state["sitemap_status_rows"] = check_urls_status(sitemap_urls, max_urls=sitemap_max_urls, delay_sec=sitemap_delay)
            rows = st.session_state.get("sitemap_status_rows")
            if rows:
                ok_count = sum(1 for row in rows if row.get("result") == "OK")
                redirect_count = sum(1 for row in rows if row.get("result") == "Редирект")
                error_count = sum(1 for row in rows if row.get("result") == "Ошибка")
                render_metric_cards(
                    [
                        {"label": "OK", "value": str(ok_count), "note": "Статус 200"},
                        {"label": "Редиректы", "value": str(redirect_count), "note": "Есть переходы"},
                        {"label": "Ошибки", "value": str(error_count), "note": "URL требуют проверки"},
                    ]
                )
                df = pd.DataFrame(rows).rename(
                    columns={
                        "url": "URL",
                        "status_code": "Статус",
                        "final_url": "Финальный URL",
                        "redirect_count": "Редиректы",
                        "result": "Результат",
                        "comment": "Комментарий",
                    }
                )
                st.dataframe(df, use_container_width=True)
                render_download(df, "Скачать статус-коды CSV", "sitemap_url_statuses.csv", "sitemap_status_csv")

    with tab_source:
        st.code(str(sitemap_data.get("raw_text") or ""), language="xml")


def render_htaccess_lab() -> None:
    st.title(".htaccess")
    st.markdown(
        "<div class='app-subtitle'>Анализ файла .htaccess по содержимому: редиректы, защита служебных файлов, кэширование, сжатие и потенциальные конфликты.</div>",
        unsafe_allow_html=True,
    )

    source_mode = st.radio("Источник .htaccess", ["Загрузить файл", "Вставить текст"], horizontal=True, key="ht_mode")
    if source_mode == "Загрузить файл":
        uploaded_ht = st.file_uploader("Загрузить .htaccess", key="ht_upload")
        if st.button("Анализировать файл", type="primary", disabled=uploaded_ht is None, key="ht_file_run"):
            st.session_state["ht_result"] = analyze_htaccess_text(decode_upload(uploaded_ht))
    else:
        ht_text = st.text_area("Содержимое .htaccess", height=320, key="ht_text_input")
        if st.button("Анализировать текст", type="primary", disabled=not ht_text.strip(), key="ht_text_run"):
            st.session_state["ht_result"] = analyze_htaccess_text(ht_text)

    ht_result = st.session_state.get("ht_result")
    if not ht_result:
        render_status_box(
            "Как использовать",
            "Загрузите файл .htaccess или вставьте его содержимое. Сервис оценит редиректы, базовую безопасность, кэширование и другие важные директивы.",
            kind="ok",
        )
        return

    summary = summarize_htaccess(ht_result)
    render_metric_cards(
        [
            {"label": "Строк в файле", "value": str(ht_result.get("lines_total") or 0), "note": "Без комментариев и пустых строк"},
            {"label": "Размер файла", "value": f"{ht_result.get('size_bytes', 0)} Б", "note": "Общий объём"},
            {"label": "Позитивные признаки", "value": str(len(ht_result.get("positives") or [])), "note": "Что настроено хорошо"},
            {"label": "Замечания", "value": str(len(ht_result.get("warnings") or [])), "note": "Что стоит проверить"},
        ]
    )

    left, right = st.columns([1, 1])
    with left:
        render_status_box("Вывод по .htaccess", summary["body"], kind=summary["status"])
        if ht_result.get("note"):
            st.info(ht_result.get("note"))
        render_issue_list("Критичные моменты", summary["critical"], level="error", empty_text="Критичных проблем не найдено")
    with right:
        positives = summary.get("positives") or []
        render_issue_list("Что настроено хорошо", positives, level="info", empty_text="Позитивных признаков пока не найдено")
        render_issue_list("Замечания и рекомендации", summary["warnings"], level="warning")

    tab_rules, tab_counters, tab_source = st.tabs(["Разбор правил", "Счётчики", "Исходник"])

    with tab_rules:
        rules = ht_result.get("rules") or []
        if rules:
            df_rules = pd.DataFrame(rules).rename(
                columns={
                    "line": "Строка",
                    "directive": "Директива",
                    "value": "Значение",
                    "level": "Уровень",
                    "comment": "Комментарий",
                }
            )
            st.dataframe(df_rules, use_container_width=True)
            render_download(df_rules, "Скачать разбор .htaccess CSV", "htaccess_report.csv", "ht_csv")
        else:
            st.info("Разобранные правила не найдены")

    with tab_counters:
        counters = ht_result.get("counters") or {}
        if counters:
            df_counters = pd.DataFrame([counters])
            st.dataframe(df_counters, use_container_width=True)
        else:
            st.info("Нет счётчиков директив")

    with tab_source:
        st.code(str(ht_result.get("raw_text") or ""), language="apache")


def render_duplicates_lab() -> None:
    st.title("Технические дубли")
    st.markdown(
        "<div class='app-subtitle'>Проверка вариантов URL, редиректов и возможных технических дублей: http/https, www/non-www, index.*, слэш, параметры и дополнительные URL.</div>",
        unsafe_allow_html=True,
    )

    dup_url = st.text_input("URL сайта или страницы", placeholder="https://example.com/", key="dup_url")
    extra_urls = st.text_area(
        "Дополнительные URL для проверки — необязательно",
        height=120,
        placeholder="https://example.com/old-page\nhttp://example.com/catalog",
        key="dup_extra_urls",
    )
    dup_delay = st.slider("Пауза между запросами, сек.", min_value=0.0, max_value=2.0, value=0.05, step=0.05, key="dup_delay")
    highlight_diffs = st.checkbox(
        "Подсвечивать отличия URL в строках отчёта",
        value=True,
        key="dup_highlight_diffs",
        help="Подсветка сравнивает стартовый URL с финальным URL и выделяет отличающиеся фрагменты. Так проще увидеть, что изменилось: протокол, www, слэш, index.php, параметры и т. д.",
    )

    if st.button("Проверить технические дубли", type="primary", disabled=not dup_url.strip(), key="dup_run"):
        with st.spinner("Проверяю варианты URL и цепочки редиректов..."):
            try:
                st.session_state["dup_result"] = analyze_technical_duplicates(dup_url, extra_urls, delay_sec=dup_delay)
            except Exception as exc:
                st.error(f"Ошибка проверки: {exc}")

    dup_result = st.session_state.get("dup_result")
    if not dup_result:
        render_status_box(
            "Как использовать",
            "Укажите основной URL сайта или страницы. При необходимости добавьте дополнительные адреса. Сервис проверит редиректы, длинные цепочки и возможные технические дубли.",
            kind="ok",
        )
        return

    summary = summarize_duplicates(dup_result)
    base_summary = dup_result.get("summary") or {}
    render_metric_cards(
        [
            {"label": "Проверено вариантов", "value": str(base_summary.get("variants_checked", 0)), "note": "Стартовые URL"},
            {"label": "Цепочки редиректов", "value": str(base_summary.get("redirect_chains", 0)), "note": "2+ перехода"},
            {"label": "Петли / длинные цепочки", "value": str(base_summary.get("redirect_loops", 0)), "note": "Требуют исправления"},
            {"label": "Возможные дубли", "value": str(base_summary.get("possible_duplicates", 0)), "note": "Одинаковые или очень близкие URL"},
        ]
    )

    left, right = st.columns([1, 1])
    with left:
        render_status_box("Вывод по дублям", summary["body"], kind=summary["status"])
        render_issue_list("Критичные моменты", summary["critical"], level="error", empty_text="Критичных проблем не найдено")
    with right:
        render_issue_list("Замечания и рекомендации", summary["warnings"], level="warning", empty_text="Явных признаков дублей не найдено")

    tab_table, tab_pairs, tab_chains = st.tabs(["Результаты", "Похожие страницы", "Цепочки редиректов"])

    with tab_table:
        rows = dup_result.get("rows") or []
        if rows:
            df_rows = pd.DataFrame(rows).rename(
                columns={
                    "start_url": "Стартовый URL",
                    "final_url": "Финальный URL",
                    "final_status": "Статус",
                    "status_chain": "Цепочка статусов",
                    "redirect_count": "Редиректы",
                    "issue": "Проблема",
                    "recommendation": "Рекомендация",
                }
            )
            if highlight_diffs:
                render_duplicate_url_diff_table(rows)
                with st.expander("Обычная таблица без подсветки"):
                    st.dataframe(df_rows, use_container_width=True)
            else:
                st.dataframe(df_rows, use_container_width=True)
            render_download(df_rows, "Скачать отчёт по дублям CSV", "technical_duplicates_report.csv", "dup_csv")
        else:
            st.info("Результаты пока не получены")

    with tab_pairs:
        similar_pairs = dup_result.get("similar_pairs") or []
        if similar_pairs:
            df_pairs = pd.DataFrame(similar_pairs)
            if highlight_diffs:
                render_similar_pair_diff_table(similar_pairs)
                with st.expander("Обычная таблица без подсветки"):
                    st.dataframe(df_pairs, use_container_width=True)
            else:
                st.dataframe(df_pairs, use_container_width=True)
            render_download(df_pairs, "Скачать похожие пары CSV", "duplicate_content_pairs.csv", "dup_pairs_csv")
        else:
            st.info("Подозрительно похожие финальные страницы не найдены")

    with tab_chains:
        chains = dup_result.get("chains") or []
        if not chains:
            st.info("Цепочки редиректов не получены")
        else:
            for chain in chains:
                with st.expander(chain.get("start_url") or "Цепочка"):
                    hops = chain.get("hops") or []
                    if hops:
                        st.dataframe(pd.DataFrame(hops), use_container_width=True)
                    else:
                        st.caption("Цепочка не получена")


# ----------------------------- Sidebar layout -----------------------------


inject_css()

with st.sidebar:
    st.markdown("## SEO File Auditor")
    st.markdown("<div class='sidebar-help'>Технический SEO-инструмент для локальной работы: общая проверка сайта и точечный анализ отдельных файлов.</div>", unsafe_allow_html=True)
    st.divider()
    section = st.radio(
        "Раздел",
        ["Главная проверка", "robots.txt", "sitemap.xml", ".htaccess", "Технические дубли"],
        label_visibility="collapsed",
    )
    st.divider()
    if section == "Главная проверка":
        st.markdown("### Настройки проверки")
        max_urls = st.slider("URL из sitemap", min_value=5, max_value=300, value=50, step=5)
        delay_sec = st.slider("Пауза между запросами, сек.", min_value=0.0, max_value=2.0, value=0.1, step=0.1)
        st.caption("Для больших сайтов лучше начинать с 50–100 URL.")
    else:
        max_urls = 50
        delay_sec = 0.1
        st.markdown("### Подсказка")
        tips = {
            "robots.txt": "Проверяй не только файл, но и список URL: так быстрее понять, какие страницы реально открыты или закрыты.",
            "sitemap.xml": "Для больших карт сайта сначала проверь структуру файла, а потом уже статус-коды URL.",
            ".htaccess": "Файл нельзя получить публично с сайта, поэтому его нужно загрузить вручную или вставить текст.",
            "Технические дубли": "Полезно запускать после правок редиректов, каноникализации и миграций на HTTPS.",
        }
        st.caption(tips.get(section, ""))


if section == "Главная проверка":
    render_main_audit(max_urls, delay_sec)
elif section == "robots.txt":
    render_robots_lab()
elif section == "sitemap.xml":
    render_sitemap_lab()
elif section == ".htaccess":
    render_htaccess_lab()
else:
    render_duplicates_lab()
