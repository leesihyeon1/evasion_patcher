"""
evasion_patcher — 샌드박스 회피 기법 정적 패처

사용 예시
---------
  # 분석만 (패치 미적용)
  python patcher.py sample.exe --dry-run

  # 전체 패치 후 report.json 저장
  python patcher.py sample.exe --output patched.exe --report report.json

  # 특정 카테고리만
  python patcher.py sample.exe --categories sleep antidebug

  # Frida 런타임 훅 실행
  python hooker/run_frida.py --spawn sample.exe
"""
from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path

sys.stdout.reconfigure(encoding='utf-8')
sys.stderr.reconfigure(encoding='utf-8')

from rich.console import Console

from core.pe_utils import PEFile
from core.disasm import make_cs
from core.dotnet_utils import is_dotnet
from detectors.sleep_detector import SleepDetector
from detectors.vm_detector import VMDetector
from detectors.userinput_detector import UserInputDetector
from detectors.antidebug_detector import AntiDebugDetector
from detectors.autoit_detector import AutoItDetector
from detectors.integrity_detector import IntegrityDetector
from detectors.dotnet_detector import DotNetDetector
from patchers.apply import apply_patches
from report import print_findings, print_patch_results, save_json_report

console = Console()

_ALL_CATEGORIES = ["sleep", "vm", "userinput", "antidebug", "autoit", "integrity", "dotnet"]

_DETECTOR_MAP = {
    "sleep":     SleepDetector,
    "vm":        VMDetector,
    "userinput": UserInputDetector,
    "antidebug": AntiDebugDetector,
    "autoit":    AutoItDetector,
    "integrity": IntegrityDetector,
    "dotnet":    DotNetDetector,
}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="patcher.py",
        description="Windows EXE 샌드박스 회피 기법 탐지 & 정적 패치",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
예시:
  python patcher.py sample.exe --dry-run
  python patcher.py sample.exe --output patched.exe --report report.json
  python patcher.py sample.exe --categories sleep antidebug
  python patcher.py sample.exe --output patched.exe --no-report
""",
    )
    p.add_argument("input",
                   help="분석할 PE(EXE) 파일 경로")
    p.add_argument("--output", "-o", metavar="PATH",
                   help="패치된 EXE 저장 경로 (미지정 시 <input>_patched.exe)")
    p.add_argument("--report", "-r", metavar="PATH",
                   help="JSON 보고서 저장 경로 (기본: <input>_report.json)")
    p.add_argument("--no-report", action="store_true",
                   help="JSON 보고서 저장 안 함")
    p.add_argument("--dry-run", action="store_true",
                   help="탐지만 수행, 파일 수정 없음")
    p.add_argument("--categories", "-c", nargs="+",
                   choices=_ALL_CATEGORIES, default=_ALL_CATEGORIES,
                   metavar="CAT",
                   help=f"탐지 카테고리 지정 (기본: 전체) — {_ALL_CATEGORIES}")
    return p


def main() -> None:
    args = build_parser().parse_args()

    # ── 입력 파일 확인 ────────────────────────────────────────────
    input_path = Path(args.input)
    if not input_path.exists():
        console.print(f"[red][!] 파일 없음: {input_path}[/red]")
        sys.exit(1)

    # ── 출력 경로 결정 ─────────────────────────────────────────────
    report_dir = input_path.parent / "REPORT"
    output_path = Path(args.output) if args.output else (
        report_dir / (input_path.stem + "_patched" + input_path.suffix)
    )
    report_path = Path(args.report) if args.report else (
        report_dir / (input_path.stem + "_report.json")
    )

    console.rule(f"[bold white]🔬 evasion_patcher — {input_path.name}")
    console.print(f"  대상  : {input_path}")
    if not args.dry_run:
        console.print(f"  출력  : {output_path}")
    console.print(f"  보고서: {report_path}")
    console.print(f"  카테고리: {args.categories}")
    console.print()

    # ── PE 로드 ───────────────────────────────────────────────────
    console.print("[*] PE 파일 로드 중...")
    try:
        pe = PEFile(str(input_path))
    except Exception as e:
        console.print(f"[red][!] PE 파싱 실패: {e}[/red]")
        sys.exit(1)

    arch = "x64" if pe.is_64bit else "x86"
    dotnet = is_dotnet(pe.data)
    dotnet_tag = "  [.NET CLR 감지]" if dotnet else ""
    console.print(f"  아키텍처: {arch}  ImageBase: 0x{pe.image_base:08X}{dotnet_tag}")
    cs = make_cs(pe.is_64bit)
    console.print()

    # ── 탐지 ─────────────────────────────────────────────────────
    console.print("[*] 회피 기법 탐지 중...")
    findings = []
    for cat in args.categories:
        cls = _DETECTOR_MAP[cat]
        det = cls(pe, cs)
        found = det.detect()
        console.print(f"  {cat:<10} {len(found):3d}건 탐지")
        findings.extend(found)
    console.print()

    print_findings(findings, str(input_path))

    if not findings:
        console.print("[green]회피 기법이 탐지되지 않았습니다.[/green]")
        sys.exit(0)

    # ── 패치 ─────────────────────────────────────────────────────
    patchable = [f for f in findings if f.is_patchable]
    if not patchable:
        console.print("[yellow]패치 가능한 항목이 없습니다.[/yellow]")
        patch_results = []
    else:
        mode = "DRY RUN" if args.dry_run else "적용"
        console.print(f"[*] 패치 {mode} 중... ({len(patchable)}건 대상)")
        patch_results = apply_patches(pe, findings, dry_run=args.dry_run)
        print_patch_results(patch_results, args.dry_run)

    # ── 저장 ─────────────────────────────────────────────────────
    if not args.dry_run and patchable:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        pe.update_checksum()
        console.print(f"  [+] PE 체크섬 재계산 완료 (0x{pe.compute_checksum():08X})")
        pe.save(str(output_path))

    if not args.no_report:
        report_path.parent.mkdir(parents=True, exist_ok=True)
        save_json_report(
            str(input_path),
            findings,
            patch_results if patchable else None,
            str(report_path),
        )

    applied = sum(1 for r in patch_results if r.status == "applied")
    console.rule("[bold white]완료")
    console.print(
        f"  탐지 {len(findings)}건 | 패치 {applied}건 적용"
        + (" [DRY RUN — 파일 미수정]" if args.dry_run else "")
    )


if __name__ == "__main__":
    main()
