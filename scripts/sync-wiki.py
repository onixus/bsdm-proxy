#!/usr/bin/env python3
"""Build a curated GitHub Wiki from canonical repository documentation."""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote, urlparse

ROOT = Path(__file__).resolve().parents[1]
DOCS_ROOT = ROOT / "docs"
REPOSITORY_URL = "https://github.com/onixus/bsdm-proxy"
WIKI_URL = f"{REPOSITORY_URL}/wiki"
GENERATED_MARKER = (
    "<!-- Generated from the main repository. "
    "Edit the canonical docs file, not this Wiki page. -->"
)
LINK_RE = re.compile(r"(!?\[[^\]]*]\()([^)]+)(\))")


@dataclass(frozen=True)
class Page:
    source: str
    target: str
    section: str
    label: str
    summary: str


PAGES: tuple[Page, ...] = (
    Page("docs/README.md", "Documentation-Index.md", "Project", "Полный индекс документации", "Все канонические документы по разделам и ролям."),
    Page("docs/project-status.md", "Project-Status.md", "Project", "Статус проекта", "Зрелость функций и известные ограничения."),
    Page("docs/roadmap.md", "Roadmap.md", "Project", "Roadmap", "Планы развития, не подтверждение готовности функций."),
    Page("docs/maintenance.md", "Documentation-Maintenance.md", "Project", "Поддержка документации", "Источник истины, проверки и правила Wiki sync."),

    Page("docs/getting-started/deployment.md", "Installation-Guide.md", "Getting started", "Развёртывание", "Compose, native package и Kubernetes."),
    Page("docs/getting-started/pilot-deployment.md", "Pilot-100-Users.md", "Getting started", "Пилот на 100 пользователей", "Hybrid core, selective MITM, sizing и приёмка."),
    Page("docs/getting-started/pilot-auth.md", "Pilot-Authentication.md", "Getting started", "Pilot authentication", "Basic lab flow и границы OIDC."),
    Page("docs/getting-started/pilot-dns.md", "Pilot-DNS-Sinkhole.md", "Getting started", "Pilot DNS sinkhole", "DNS first hop, smoke test и метрики."),
    Page("docs/getting-started/pilot-alerts.md", "Pilot-Alerts.md", "Getting started", "Pilot alerts", "Alert-worker rule pack и decision-source UX."),
    Page("docs/getting-started/pilot-ml.md", "Pilot-ML.md", "Getting started", "Pilot ML", "Одна ML-модель, write-back и smoke test."),
    Page("docs/getting-started/pilot-agent.md", "Pilot-Agent.md", "Getting started", "Pilot agent", "Phase C agent spike и lab-приёмка."),
    Page("docs/getting-started/pilot-agent-fleet.md", "Pilot-Agent-Fleet.md", "Getting started", "Agent fleet", "MDM/GPO/Jamf packaging scaffolding."),
    Page("docs/getting-started/lite-mode.md", "Lite-Mode.md", "Getting started", "Lite mode", "Proxy и SQLite без Kafka/ClickHouse."),
    Page("docs/getting-started/troubleshooting.md", "Troubleshooting-and-FAQ.md", "Getting started", "Troubleshooting", "Типовые ошибки запуска и диагностика."),

    Page("docs/architecture/overview.md", "Architecture-Overview.md", "Architecture & design", "Архитектура", "Компоненты, request path и data flow."),
    Page("docs/architecture/agent-contract.md", "Agent-Contract.md", "Architecture & design", "Agent Contract", "Контракт взаимодействия локального агента."),
    Page("docs/architecture/capacity-planning.md", "Capacity-Planning.md", "Architecture & design", "Capacity planning", "Формулы, пилотный профиль и масштабирование."),
    Page("docs/architecture/performance.md", "Performance-Tuning.md", "Architecture & design", "Performance tuning", "Bench-профили и production tuning."),
    Page("docs/architecture/hierarchical-caching.md", "Hierarchical-Caching.md", "Architecture & design", "Hierarchical caching", "L1/L2, ICP/HTCP и peer selection."),
    Page("docs/architecture/structure.md", "Codebase-Structure.md", "Architecture & design", "Структура репозитория", "Cargo workspace и инфраструктурные каталоги."),

    Page("docs/features/authentication.md", "Authentication.md", "Security & policy", "Authentication", "Basic/OIDC и beta enterprise backends."),
    Page("docs/features/acl-policy.md", "ACL-Policy.md", "Security & policy", "ACL", "Правила доступа, reload и persist."),
    Page("docs/features/categorization.md", "Domain-Categorization.md", "Security & policy", "Categorization", "UT1, локальные и online threat feeds."),
    Page("docs/features/certificate-pinning.md", "Certificate-Pinning-Exceptions.md", "Security & policy", "Certificate pinning", "Управляемые MITM bypass-исключения."),
    Page("docs/features/threat-intel-collector.md", "Threat-Intelligence-Collector.md", "Security & policy", "TI collector", "Сбор IOC-фидов: плагины источников, расписание, метрики."),
    Page("docs/features/control-plane.md", "Control-Plane-API.md", "Security & policy", "Control plane API", "REST/gRPC endpoints и auth model."),
    Page("docs/features/admin-console-security.md", "Admin-Console-Security.md", "Security & policy", "Admin Console security", "Trust boundaries и mutation token gate."),
    Page("docs/features/dns-sinkhole.md", "DNS-Sinkhole.md", "Security & policy", "DNS sinkhole", "RPZ filtering, UDP, DoH и DoT."),
    Page("docs/features/semantic-cache.md", "AI-Semantic-Cache.md", "Security & policy", "Semantic cache", "Exact и vector near-hit cache."),
    Page("docs/features/wasm-plugins.md", "WASM-Plugins.md", "Security & policy", "WASM plugins", "Замороженный experimental extension path."),
    Page("docs/features/icap-inspection.md", "ICAP-Inspection.md", "Security & policy", "ICAP inspection", "Замороженный REQMOD/RESPMOD adapter."),
    Page("docs/features/acl-console.md", "ACL-Admin-Console.md", "Security & policy", "Политики в Admin Console", "Живой CRUD ACL на порту метрик."),
    Page("docs/threat-intelligence/Architecture.md", "Threat-Intelligence-Architecture.md", "Security & policy", "TI architecture", "Архитектура модуля threat intelligence: ingestion и enforcement."),
    Page("docs/threat-intelligence/Integration_with_BSDM.md", "Threat-Intelligence-Integration.md", "Security & policy", "TI integration", "Встраивание IOC-фидов в pipeline фильтрации."),
    Page("docs/threat-intelligence/DNS_RPZ_Platform_Plan.md", "DNS-RPZ-Platform-Plan.md", "Security & policy", "DNS RPZ platform (plan)", "Проектный план платформы DNS-блокировок по IOC-фидам."),
    Page("docs/threat-intelligence/RPZ_Deployment.md", "RPZ-Deployment-Plan.md", "Security & policy", "RPZ deployment (plan)", "План развёртывания DNS RPZ-блокировок."),
    Page("docs/threat-intelligence/Threat_Intelligence_Collector_Agent.md", "Threat-Intelligence-Collector-Agent.md", "Security & policy", "TI collector agent (spec)", "Спецификация агента сбора и нормализации phishing IOC."),
    Page("docs/threat-intelligence/AI_Agent_Backlog.md", "Threat-Intelligence-Agent-Backlog.md", "Security & policy", "TI agent backlog", "Бэклог автоматизации TI-пайплайна; не статус готовности."),
    Page("docs/threat-intelligence/Roadmap.md", "Threat-Intelligence-Roadmap.md", "Security & policy", "TI roadmap", "Планы развития TI-контура; не подтверждение готовности."),

    Page("docs/analytics/clickhouse-retrosearch.md", "ClickHouse-RetroSearch.md", "Analytics & detection", "ClickHouse retro-search", "Schema, ingest и Search API."),
    Page("docs/analytics/alerting.md", "Threat-Alerting.md", "Analytics & detection", "Threat alerting", "Alert-worker и SIEM webhook."),
    Page("docs/analytics/ml-security.md", "ML-Security.md", "Analytics & detection", "ML security", "Feature store, models и threat-score write-back."),

    Page("docs/ops-and-dev/configuration.md", "Configuration.md", "Operations", "Конфигурация", "Runtime environment variables и defaults."),
    Page("docs/ops-and-dev/control-plane-security.md", "Control-Plane-Security.md", "Operations", "Control plane security", "Tokens, bind addresses и network policy."),
    Page("docs/ops-and-dev/logging.md", "Logging-and-Metrics.md", "Operations", "Логи и метрики", "Tracing, Prometheus и диагностика."),
    Page("docs/ops-and-dev/backup-restore.md", "Backup-and-Restore.md", "Operations", "Backup & restore", "ClickHouse и MITM CA rollback drill."),
    Page("docs/ops-and-dev/ca-lifecycle.md", "CA-Lifecycle.md", "Operations", "CA lifecycle", "Выпуск, ротация и отзыв MITM CA."),
    Page("docs/ops-and-dev/load-test-selective-mitm.md", "Load-Test-Selective-MITM.md", "Operations", "Hybrid load test", "Selective MITM, DNS и auth workload."),
    Page("docs/ops-and-dev/load-test-results/README.md", "Load-Test-Results.md", "Operations", "Load-test results", "Правила хранения и интерпретации отчётов."),
    Page("docs/ops-and-dev/benchmarks.md", "Benchmarks.md", "Operations", "Benchmarks", "HTTP Archive методика и исторические результаты."),
    Page("docs/ops-and-dev/k8s-architecture.md", "Kubernetes-Deployment.md", "Operations", "Kubernetes", "Helm и разделение data/analytics plane."),
    Page("docs/ops-and-dev/development.md", "Development-Guide.md", "Operations", "Разработка", "Build, test и release workflow."),
    Page("docs/ops-and-dev/licensing.md", "Licensing.md", "Operations", "Лицензирование", "Third-party components и audit notes."),

    Page("docs/adr/0001-tiered-sharded-l1-cache.md", "ADR-0001-Tiered-Sharded-L1-Cache.md", "ADRs", "ADR 0001: Tiered sharded L1", "Архитектура L1 cache."),
    Page("docs/adr/0002-clickhouse-analytics.md", "ADR-0002-ClickHouse-Analytics.md", "ADRs", "ADR 0002: ClickHouse analytics", "Выбор analytics store."),
    Page("docs/adr/0003-ml-worker-feature-store.md", "ADR-0003-ML-Worker-Feature-Store.md", "ADRs", "ADR 0003: ML feature store", "ML worker и feature tables."),
    Page("docs/adr/0004-dns-sinkhole-sidecar.md", "ADR-0004-DNS-Sinkhole-Sidecar.md", "ADRs", "ADR 0004: DNS sidecar", "Отдельный DNS first hop."),
    Page("docs/adr/0005-local-policy-agent-vs-tunnel-first.md", "ADR-0005-Local-Policy-Agent-vs-Tunnel-First.md", "ADRs", "ADR 0005: Local policy agent", "Agent vs tunnel-first architecture."),
    Page("docs/adr/0006-single-operator-console.md", "ADR-0006-Single-Operator-Console.md", "ADRs", "ADR 0006: Single operator console", "Единая поддерживаемая консоль оператора."),
)

LOAD_TEST_RESULTS_PREFIX = "docs/ops-and-dev/load-test-results/"


def is_excluded_doc(source: str) -> bool:
    """Keep machine-generated run snapshots in Git, not as standalone Wiki pages."""

    return (
        source.startswith(LOAD_TEST_RESULTS_PREFIX)
        and source != f"{LOAD_TEST_RESULTS_PREFIX}README.md"
    )

SECTION_HUBS = {
    "Getting started": (
        "Getting-Started.md",
        "Начало работы и пилот",
        "Порядок развёртывания, приёмки и расширения пилота.",
    ),
    "Architecture & design": (
        "Architecture-and-Design.md",
        "Архитектура и дизайн",
        "Фактическая архитектура, capacity planning и контракты компонентов.",
    ),
    "Security & policy": (
        "Security-and-Policy.md",
        "Безопасность и политики",
        "Механизмы enforcement и их эксплуатационные ограничения.",
    ),
    "Analytics & detection": (
        "Analytics-and-Detection.md",
        "Аналитика и detection",
        "ClickHouse, alerting и ML-контур.",
    ),
    "Operations": (
        "Operations.md",
        "Эксплуатация",
        "Конфигурация, наблюдаемость, backup, Kubernetes и разработка.",
    ),
    "ADRs": (
        "ADR-Index.md",
        "Architecture Decision Records",
        "Зафиксированные архитектурные решения проекта.",
    ),
    # Landing place for docs picked up automatically (see derived_pages). Without
    # a hub of their own such pages would render but nothing would link to them.
    "Прочее": (
        "Other-Documentation.md",
        "Прочие документы",
        "Документы без курируемой записи в PAGES; раздел назначен автоматически.",
    ),
}


def release_pages() -> tuple[Page, ...]:
    pages: list[Page] = []
    for source in sorted((DOCS_ROOT / "releases").glob("*.md")):
        rel = source.relative_to(ROOT).as_posix()
        version = source.stem.removeprefix("v")
        pages.append(
            Page(
                rel,
                f"Release-{version}.md",
                "Releases",
                f"Release {source.stem}",
                "Исторические release notes; не использовать как текущий runbook.",
            )
        )
    return tuple(pages)


# Which hub a derived page lands in, keyed by its first directory under docs/.
# Every value must be a key of SECTION_HUBS, otherwise the page renders but no
# hub links to it. Anything not listed falls back to "Project".
DERIVED_SECTIONS = {
    "getting-started": "Getting started",
    "architecture": "Architecture & design",
    "features": "Security & policy",
    "threat-intelligence": "Security & policy",
    "analytics": "Analytics & detection",
    "ops-and-dev": "Operations",
    "adr": "ADRs",
}

DERIVED_SUMMARY = "Автоматически включённый документ; добавьте курируемое описание в PAGES."


def derived_title(source: Path) -> str:
    """First Markdown H1, falling back to a readable form of the file name."""

    for line in source.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith("# "):
            return stripped[2:].strip()
    return source.stem.replace("_", " ").replace("-", " ").strip()


def derived_target(rel: str) -> str:
    """Wiki file name built from the whole path under docs/, so it cannot collide."""

    parts = Path(rel).relative_to("docs").with_suffix("").parts
    tokens: list[str] = []
    for part in parts:
        for token in re.split(r"[\s_-]+", part):
            if token:
                tokens.append(token[:1].upper() + token[1:])
    return "-".join(tokens) + ".md"


def derived_pages(covered: set[str]) -> tuple[Page, ...]:
    """Cover every remaining doc so a new file cannot fail the coverage gate.

    Curated entries in PAGES are always preferred — they carry a hand-written
    label and summary. This exists so that dropping a Markdown file into docs/
    (including straight onto main, which is how the threat-intelligence docs
    arrived) publishes it to the Wiki instead of turning the docs gate red until
    somebody edits this file by hand.
    """

    pages: list[Page] = []
    for path in sorted(DOCS_ROOT.rglob("*.md")):
        rel = path.relative_to(ROOT).as_posix()
        if rel in covered or is_excluded_doc(rel):
            continue
        parts = Path(rel).relative_to("docs").parts
        top = parts[0] if len(parts) > 1 else ""
        pages.append(
            Page(
                rel,
                derived_target(rel),
                DERIVED_SECTIONS.get(top, "Прочее"),
                derived_title(path),
                DERIVED_SUMMARY,
            )
        )
    return tuple(pages)


def catalog() -> tuple[Page, ...]:
    curated = PAGES + release_pages()
    return curated + derived_pages({page.source for page in curated})


def version() -> str:
    manifest = tomllib.loads((ROOT / "proxy/Cargo.toml").read_text(encoding="utf-8"))
    return str(manifest["package"]["version"])


def split_target(raw: str) -> tuple[str, str]:
    target = raw.strip().strip("<>")
    if " " in target:
        target = target.split(" ", 1)[0]
    if "#" in target:
        path, anchor = target.split("#", 1)
        return unquote(path), f"#{anchor}"
    return unquote(target), ""


def validate_catalog(pages: tuple[Page, ...]) -> None:
    sources = [page.source for page in pages]
    targets = [page.target for page in pages]
    duplicate_sources = sorted({item for item in sources if sources.count(item) > 1})
    duplicate_targets = sorted({item for item in targets if targets.count(item) > 1})
    if duplicate_sources or duplicate_targets:
        raise ValueError(
            f"duplicate Wiki mapping: sources={duplicate_sources}, targets={duplicate_targets}"
        )

    missing_sources = sorted(source for source in sources if not (ROOT / source).is_file())
    if missing_sources:
        raise ValueError(f"canonical pages missing: {', '.join(missing_sources)}")

    all_docs = {
        path.relative_to(ROOT).as_posix()
        for path in DOCS_ROOT.rglob("*.md")
    }
    excluded_docs = {source for source in all_docs if is_excluded_doc(source)}
    unmapped = sorted(all_docs - set(sources) - excluded_docs)
    if unmapped:
        raise ValueError(
            f"Wiki coverage mismatch: unmapped={unmapped}"
        )


def transform_links(source_rel: str, content: str, pages: tuple[Page, ...]) -> str:
    source = ROOT / source_rel
    source_to_target = {page.source: page.target for page in pages}

    def replace(match: re.Match[str]) -> str:
        prefix, raw, suffix = match.groups()
        path_part, anchor = split_target(raw)
        if not path_part or urlparse(path_part).scheme:
            return match.group(0)

        resolved = (source.parent / path_part).resolve()
        try:
            repo_rel = resolved.relative_to(ROOT).as_posix()
        except ValueError:
            return match.group(0)

        if repo_rel in source_to_target:
            target = source_to_target[repo_rel].removesuffix(".md") + anchor
        elif resolved.is_dir():
            target = f"{REPOSITORY_URL}/tree/main/{repo_rel}{anchor}"
        elif resolved.exists():
            target = f"{REPOSITORY_URL}/blob/main/{repo_rel}{anchor}"
        else:
            target = raw
        return f"{prefix}{target}{suffix}"

    return LINK_RE.sub(replace, content)


def section_hub(
    section: str,
    title: str,
    intro: str,
    pages: tuple[Page, ...],
) -> str:
    rows = [f"| [{page.label}]({page.target.removesuffix('.md')}) | {page.summary} |" for page in pages if page.section == section]
    return "\n".join(
        [
            f"# {title}",
            "",
            intro,
            "",
            "| Страница | Назначение |",
            "|---|---|",
            *rows,
            "",
            "Перед эксплуатацией сверяйте зрелость функций с [Project status](Project-Status).",
            "",
        ]
    )


def release_hub(pages: tuple[Page, ...]) -> str:
    releases = [page for page in pages if page.section == "Releases"]
    releases.sort(
        key=lambda page: tuple(int(part) for part in re.findall(r"\d+", page.label)),
        reverse=True,
    )
    rows = [f"| [{page.label}]({page.target.removesuffix('.md')}) | {page.summary} |" for page in releases]
    return "\n".join(
        [
            "# История релизов",
            "",
            f"Текущая версия workspace: **`{version()}`**.",
            "",
            "> Release notes описывают состояние конкретного релиза. Для текущего",
            "> deployment используйте [Getting started](Getting-Started) и",
            "> [Project status](Project-Status).",
            "",
            "| Релиз | Назначение |",
            "|---|---|",
            *rows,
            "",
        ]
    )


def home() -> str:
    return f"""# BSDM-Proxy Wiki

Актуальная эксплуатационная база знаний для BSDM-Proxy **`{version()}`**.
Канонические тексты находятся в основном репозитории; Wiki предоставляет
структурированную навигацию и обновляется автоматически.

## Быстрый выбор

| Задача | Начать отсюда |
|---|---|
| Развернуть пилот | [Пилот на 100 пользователей](Pilot-100-Users) |
| Проверить зрелость функции | [Project status](Project-Status) |
| Понять архитектуру | [Architecture & design](Architecture-and-Design) |
| Настроить политики | [Security & policy](Security-and-Policy) |
| Подключить аналитику | [Analytics & detection](Analytics-and-Detection) |
| Эксплуатировать платформу | [Operations](Operations) |
| Найти любой документ | [Полный индекс](Documentation-Index) |

## Референсный пилот

| Параметр | Значение |
|---|---:|
| Пользователи | до 100 |
| Рекомендуемый хост | 12 vCPU / 24 GiB RAM / 200 GB NVMe |
| Сеть | 1 Gbit/s |
| Retention | до 5 суток |
| Не входит | DLP, reverse proxy, ICAP, ClamAV, HA |

Профиль является инженерной отправной точкой и требует собственного load test.
Подробности и критерии приёмки: [Pilot-100-Users](Pilot-100-Users).

## Рекомендуемый порядок

1. Прочитать [Project status](Project-Status) и ограничения функций.
2. Выполнить [пилотный runbook](Pilot-100-Users).
3. Закрыть [control-plane security](Control-Plane-Security) и CA lifecycle.
4. Проверить [backup/restore](Backup-and-Restore) и нагрузочный профиль.
5. Только после измерений переходить к HA или расширению модулей.

## Разделы

- [Начало работы и пилот](Getting-Started)
- [Архитектура и дизайн](Architecture-and-Design)
- [Безопасность и политики](Security-and-Policy)
- [Аналитика и detection](Analytics-and-Detection)
- [Эксплуатация](Operations)
- [Architecture Decision Records](ADR-Index)
- [История релизов](Release-History)

> Wiki — представление канонической документации, а не отдельный источник истины.
> Изменения вносятся в `docs/` и публикуются генератором.
"""


def sidebar() -> str:
    return """# BSDM-Proxy

* [Главная](Home)
* [Статус проекта](Project-Status)
* [Полный индекс](Documentation-Index)

## Пилот
* [Начало работы](Getting-Started)
* [100 пользователей](Pilot-100-Users)
* [Установка](Installation-Guide)
* [Troubleshooting](Troubleshooting-and-FAQ)

## Архитектура
* [Обзор раздела](Architecture-and-Design)
* [Архитектура](Architecture-Overview)
* [Capacity planning](Capacity-Planning)
* [Agent contract](Agent-Contract)
* [ADR index](ADR-Index)

## Безопасность
* [Обзор раздела](Security-and-Policy)
* [Authentication](Authentication)
* [ACL](ACL-Policy)
* [Certificate pinning](Certificate-Pinning-Exceptions)
* [Control plane security](Control-Plane-Security)

## Аналитика
* [Обзор раздела](Analytics-and-Detection)
* [ClickHouse](ClickHouse-RetroSearch)
* [Threat alerting](Threat-Alerting)
* [ML security](ML-Security)

## Эксплуатация
* [Обзор раздела](Operations)
* [Configuration](Configuration)
* [Logging & metrics](Logging-and-Metrics)
* [Backup & restore](Backup-and-Restore)
* [CA lifecycle](CA-Lifecycle)
* [Kubernetes](Kubernetes-Deployment)

## Проект
* [Roadmap](Roadmap)
* [Релизы](Release-History)
* [Разработка](Development-Guide)
* [Поддержка Wiki](Documentation-Maintenance)
* [Прочие документы](Other-Documentation)
"""


def footer() -> str:
    return (
        f"BSDM-Proxy `{version()}` · "
        f"[Canonical docs]({REPOSITORY_URL}/tree/main/docs) · "
        f"[Wiki home]({WIKI_URL}) · Generated pages should not be edited directly.\n"
    )


def with_marker(content: str) -> str:
    return f"{GENERATED_MARKER}\n\n{content.rstrip()}\n"


def build_pages() -> dict[str, str]:
    pages = catalog()
    validate_catalog(pages)

    rendered = {
        page.target: with_marker(
            transform_links(
                page.source,
                (ROOT / page.source).read_text(encoding="utf-8"),
                pages,
            )
        )
        for page in pages
    }
    rendered["Home.md"] = with_marker(home())
    for section, (target, title, intro) in SECTION_HUBS.items():
        rendered[target] = with_marker(section_hub(section, title, intro, pages))
    rendered["Release-History.md"] = with_marker(release_hub(pages))
    rendered["_Sidebar.md"] = with_marker(sidebar())
    rendered["_Footer.md"] = with_marker(footer())
    validate_wiki_links(rendered)
    return rendered


def validate_wiki_links(rendered: dict[str, str]) -> None:
    page_slugs = {Path(name).stem for name in rendered}
    broken: list[str] = []
    for page_name, content in rendered.items():
        for line_number, line in enumerate(content.splitlines(), start=1):
            for match in LINK_RE.finditer(line):
                raw = match.group(2)
                path_part, _ = split_target(raw)
                if not path_part or urlparse(path_part).scheme:
                    continue
                slug = path_part.removesuffix(".md")
                if slug not in page_slugs:
                    broken.append(f"{page_name}:{line_number}: {raw}")
    if broken:
        raise ValueError("broken generated Wiki links:\n  " + "\n  ".join(broken))


def check_wiki(wiki: Path, expected: dict[str, str]) -> list[str]:
    drift: list[str] = []
    for name, content in expected.items():
        path = wiki / name
        if not path.exists():
            drift.append(f"missing: {name}")
        elif path.read_text(encoding="utf-8") != content:
            drift.append(f"outdated: {name}")

    for path in wiki.glob("*.md"):
        if path.name in expected:
            continue
        current = path.read_text(encoding="utf-8")
        if current.startswith(GENERATED_MARKER):
            drift.append(f"stale generated page: {path.name}")
    return drift


def write_wiki(wiki: Path, expected: dict[str, str]) -> tuple[int, int]:
    updated = 0
    removed = 0
    for path in wiki.glob("*.md"):
        if path.name in expected:
            continue
        current = path.read_text(encoding="utf-8")
        if current.startswith(GENERATED_MARKER):
            path.unlink()
            removed += 1

    for name, content in expected.items():
        path = wiki / name
        if not path.exists() or path.read_text(encoding="utf-8") != content:
            path.write_text(content, encoding="utf-8")
            updated += 1
    return updated, removed


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wiki", nargs="?", help="path to the cloned GitHub Wiki")
    parser.add_argument(
        "--validate",
        action="store_true",
        help="validate source coverage and generated links without writing",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail if the cloned Wiki differs from generated output",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        expected = build_pages()
    except ValueError as error:
        print(error, file=sys.stderr)
        return 1

    if args.validate and not args.wiki:
        print(f"Wiki catalog OK: {len(expected)} generated pages")
        return 0
    if not args.wiki:
        print("wiki path is required unless --validate is used", file=sys.stderr)
        return 2

    wiki = Path(args.wiki).resolve()
    if not wiki.is_dir():
        print(f"wiki directory not found: {wiki}", file=sys.stderr)
        return 2

    if args.check:
        drift = check_wiki(wiki, expected)
        if drift:
            print("Wiki drift detected:\n  " + "\n  ".join(drift), file=sys.stderr)
            return 1
        print(f"Wiki is current: {len(expected)} generated pages")
        return 0

    updated, removed = write_wiki(wiki, expected)
    print(
        f"Wiki generated: {len(expected)} pages "
        f"({updated} updated, {removed} stale removed)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
