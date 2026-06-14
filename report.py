"""
탐지 결과 및 패치 결과 보고서 출력 / JSON 저장
"""
from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path

sys.stdout.reconfigure(encoding='utf-8')

from rich.console import Console
from rich.table import Table
from rich import box
from rich.text import Text

from detectors.base import Finding
from patchers.apply import PatchResult

console = Console()

_CATEGORY_ICON = {
    "sleep":      "⏱ ",
    "vm":         "🖥 ",
    "userinput":  "🖱 ",
    "antidebug":  "🔍",
    "autoit":     "🤖",
    "integrity":  "🔒",
    "dotnet":     "🟣",
}
_CATEGORY_COLOR = {
    "sleep":      "yellow",
    "vm":         "cyan",
    "userinput":  "green",
    "antidebug":  "magenta",
    "autoit":     "bright_yellow",
    "integrity":  "bright_red",
    "dotnet":     "bright_magenta",
}


# ── 탐지 결과 테이블 ──────────────────────────────────────────────
def print_findings(findings: list[Finding], target: str) -> None:
    patchable   = [f for f in findings if f.is_patchable]
    unpatchable = [f for f in findings if not f.is_patchable]

    console.rule(f"[bold white]🔬 탐지 결과 — {Path(target).name}")
    console.print(
        f"  총 {len(findings)}건 탐지 "
        f"([green]{len(patchable)} 패치 가능[/green] / "
        f"[dim]{len(unpatchable)} 수동 확인[/dim])"
    )
    console.print()

    # 탐지된 카테고리를 순서대로 출력 (등록 순서 유지)
    _ORDER = ["sleep", "vm", "userinput", "antidebug", "autoit", "integrity", "dotnet"]
    present = {f.category for f in findings}
    categories = [c for c in _ORDER if c in present] + sorted(present - set(_ORDER))
    for cat in categories:
        group = [f for f in findings if f.category == cat]
        if not group:
            continue

        icon  = _CATEGORY_ICON.get(cat, "•")
        color = _CATEGORY_COLOR.get(cat, "white")

        tbl = Table(
            title=f"{icon} {cat.upper()}",
            box=box.SIMPLE_HEAVY,
            title_style=f"bold {color}",
            header_style="bold white",
            show_lines=False,
        )
        tbl.add_column("VA",          style="bright_blue", width=12, no_wrap=True)
        tbl.add_column("기법",        style=color,         width=28, no_wrap=True)
        tbl.add_column("설명",        style="white",       ratio=1)
        tbl.add_column("패치",        style="green",       width=6,  justify="center")

        for f in group:
            patch_mark = Text("✔", style="green") if f.is_patchable else Text("—", style="dim")
            tbl.add_row(
                f"0x{f.va:08X}",
                f.technique,
                f.description,
                patch_mark,
            )

        console.print(tbl)

    if unpatchable:
        console.print(
            "[dim]* 패치 미적용 항목은 수동 분석이 필요합니다 "
            "(VM 문자열, 조건부 점프 미발견 등)[/dim]"
        )
    console.print()


# ── 패치 결과 테이블 ──────────────────────────────────────────────
def print_patch_results(results: list[PatchResult], dry_run: bool) -> None:
    prefix = "[DRY RUN] " if dry_run else ""
    applied  = [r for r in results if r.status == "applied"]
    skipped  = [r for r in results if r.status == "skipped"]
    errors   = [r for r in results if r.status == "error"]

    console.rule(f"[bold white]{prefix}📝 패치 결과")
    console.print(
        f"  적용: [green]{len(applied)}[/green]  "
        f"스킵: [yellow]{len(skipped)}[/yellow]  "
        f"오류: [red]{len(errors)}[/red]"
    )
    console.print()

    if applied:
        tbl = Table(box=box.SIMPLE, header_style="bold green", show_lines=False)
        tbl.add_column("파일 오프셋",  style="bright_blue", width=14, no_wrap=True)
        tbl.add_column("카테고리",     width=12)
        tbl.add_column("기법",         width=28)
        tbl.add_column("패치 내용",    style="green")
        for r in applied:
            tbl.add_row(
                f"0x{r.action.file_offset:X}",
                r.finding.category,
                r.finding.technique,
                r.reason,
            )
        console.print(tbl)

    if skipped:
        console.print("[yellow]─ 스킵된 패치[/yellow]")
        for r in skipped:
            console.print(f"  [dim]0x{r.action.file_offset:X}  {r.reason}[/dim]")

    if errors:
        console.print("[red]─ 오류[/red]")
        for r in errors:
            console.print(f"  [red]0x{r.action.file_offset:X}  {r.reason}[/red]")

    console.print()


# ── JSON 저장 ─────────────────────────────────────────────────────
def save_json_report(
    target: str,
    findings: list[Finding],
    patch_results: list[PatchResult] | None,
    output_path: str,
) -> None:
    report = {
        "generated": datetime.now().isoformat(),
        "target": target,
        "summary": {
            "total_findings": len(findings),
            "patchable": sum(1 for f in findings if f.is_patchable),
            "patch_applied": sum(1 for r in (patch_results or []) if r.status == "applied"),
            "patch_skipped": sum(1 for r in (patch_results or []) if r.status == "skipped"),
        },
        "findings": [
            {
                "category":     f.category,
                "technique":    f.technique,
                "va":           hex(f.va),
                "file_offset":  hex(f.file_offset),
                "description":  f.description,
                "patchable":    f.is_patchable,
                "patch_actions": [
                    {
                        "file_offset":     hex(a.file_offset),
                        "original_bytes":  a.original_bytes.hex(),
                        "new_bytes":       a.new_bytes.hex(),
                        "description":     a.description,
                    }
                    for a in f.patch_actions
                ],
            }
            for f in findings
        ],
        "patch_results": [
            {
                "file_offset": hex(r.action.file_offset),
                "status":      r.status,
                "reason":      r.reason,
            }
            for r in (patch_results or [])
        ],
    }

    with open(output_path, "w", encoding="utf-8") as fp:
        json.dump(report, fp, ensure_ascii=False, indent=2)

    console.print(f"[green]📁 JSON 보고서 저장됨:[/green] {output_path}")
