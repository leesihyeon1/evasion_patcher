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
from core.dotnet_utils import (
    is_dotnet, _find_metadata_streams, _parse_member_ref_tokens,
    find_us_string_tokens, find_ldstr_refs, find_call_sites_il,
    get_embedded_resource_strings,
)
from core.disasm import (
    scan_wide_pattern, find_call_sites, find_prev_cond_jump, find_va_refs_in_code,
)
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


_DOTNET_DIAG_TARGETS = [
    ("MessageBox",  "Show"),
    ("MessageBox",  "ShowDialog"),
    ("Environment", "Exit"),
    ("Application", "Exit"),
]
_DOTNET_DIAG_STRINGS = [
    "File corrupted", "manipulated", "cracked",
    "debugger has been found", "unload it from memory",
    "windbg.exe", "x64dbg.exe",
]


def _print_dotnet_diag(pe, cs) -> None:
    """dotnet 0건 시 자동 진단 — 탐지 실패 원인 출력."""
    import struct as _s
    pe_data = pe.data
    console.rule("[dim].NET 진단[/dim]")

    streams = _find_metadata_streams(pe_data)
    if not streams:
        console.print("  [red]메타데이터 스트림 파싱 실패[/red]")
        return

    console.print(f"  스트림: {list(streams.keys())}")

    # ── #US 힙 문자열 탐색 ─────────────────────────────────────
    us_result = streams.get('#US')
    if us_result:
        _, us_data = us_result
        console.print(f"  #US 힙: {len(us_data)}B")
        for s in _DOTNET_DIAG_STRINGS:
            toks = find_us_string_tokens(us_data, s)
            if toks:
                for tok in toks:
                    refs = find_ldstr_refs(pe_data, tok)
                    console.print(
                        f"  [green]#US '{s}' 토큰={hex(tok)}  "
                        f"ldstr참조={[hex(r) for r in refs]}[/green]"
                    )
            else:
                console.print(f"  [dim]#US '{s}' → 없음[/dim]")
    else:
        console.print("  [dim]#US 힙 없음[/dim]")

    # ── #Strings / MemberRef 탐색 ─────────────────────────────
    tilde   = streams.get('#~',       (0, b''))[1]
    strings = streams.get('#Strings', (0, b''))[1]
    if not tilde:
        console.print("  [red]#~ 스트림 없음[/red]")
        return

    heap_sizes = tilde[6]
    console.print(
        f"  #~ HeapSizes=0x{heap_sizes:02X}  "
        f"Strings={'4B' if heap_sizes&1 else '2B'}  "
        f"GUID={'4B' if heap_sizes&2 else '2B'}  "
        f"Blob={'4B' if heap_sizes&4 else '2B'}"
    )

    # #Strings 직접 탐색
    for name in [b"MessageBox", b"Environment", b"Application", b"Show", b"Exit"]:
        idx = strings.find(name + b'\x00')
        status = f"@ 0x{idx:X}" if idx >= 0 else "없음"
        color = "green" if idx >= 0 else "dim"
        console.print(f"  [dim]#Strings '{name.decode()}':[/dim] [{color}]{status}[/{color}]")

    # MemberRef 파싱
    try:
        results = _parse_member_ref_tokens(tilde, strings, _DOTNET_DIAG_TARGETS)
        if results:
            for tok, name in results:
                sites = find_call_sites_il(pe_data, tok)
                console.print(
                    f"  [green]MemberRef {name} 토큰=0x{tok:08X}  "
                    f"call사이트={[hex(c) for c in sites]}[/green]"
                )
        else:
            console.print("  [yellow]MemberRef: MessageBox/Environment 참조 없음[/yellow]")
    except Exception as e:
        console.print(f"  [red]MemberRef 파싱 오류: {e}[/red]")

    # ── 내장 리소스(.resources) 스캔 ──────────────────────────────
    console.print()
    console.print("  [dim]── 내장 리소스(.resources) 스캔 ──[/dim]")
    try:
        res_pairs = get_embedded_resource_strings(pe_data)
        if res_pairs:
            console.print(f"  [green]리소스 문자열 {len(res_pairs)}개 발견[/green]")
            _ERROR_PAT = [
                b"corrupt", b"manipulat", b"cracked", b"tampered",
                b"debugger", b"windbg", b"ollydbg", b"x64dbg", b"x32dbg",
                b"processhacker", b"cheatengine",
            ]
            for k, v in res_pairs:
                vl = v.lower().encode('utf-8', errors='ignore')
                is_hit = any(p in vl for p in _ERROR_PAT)
                if is_hit:
                    console.print(f"  [yellow]  [탐지] key='{k}'  value='{v[:60]}'[/yellow]")
                else:
                    console.print(f"  [dim]  key='{k}'  value='{v[:60]}'[/dim]")
        else:
            console.print("  [dim]내장 리소스 없음 또는 0xBEEFCACE magic 미발견[/dim]")
    except Exception as e:
        console.print(f"  [red]리소스 스캔 오류: {e}[/red]")

    # ── UTF-16LE 전체 스캔 ────────────────────────────────────────
    console.print()
    console.print("  [dim]── 전체 섹션 UTF-16LE 스캔 ──[/dim]")
    _WIDE_TARGETS = [
        b"corrupt", b"manipulat", b"debugger has been",
        b"unload it", b"file corrupted", b"cracked",
    ]
    code_sections = pe.get_code_sections()
    try:
        for sec_off, sec_rva, sec_va, sec_data in pe.get_all_sections():
            sec_name_bytes = b''
            for s in pe.pe.sections:
                if s.PointerToRawData == sec_off:
                    sec_name_bytes = s.Name.rstrip(b'\x00')
                    break
            sec_name = sec_name_bytes.decode('ascii', errors='replace')
            for pat in _WIDE_TARGETS:
                hits = scan_wide_pattern(sec_data, sec_off, pat)
                for hit_off in hits:
                    hit_rva = hit_off - sec_off + sec_rva
                    hit_va  = pe.image_base + hit_rva
                    refs = find_va_refs_in_code(
                        hit_va, code_sections, pe.is_64bit, pe.image_base
                    )
                    ref_str = [f"0x{r[1]:X}" for r in refs]
                    color = "green" if refs else "yellow"
                    console.print(
                        f"  [{color}]UTF-16LE '{pat.decode()}' @ "
                        f"파일=0x{hit_off:X}  VA=0x{hit_va:X}  섹션={sec_name}  "
                        f"VA참조={ref_str if ref_str else '없음'}[/{color}]"
                    )
    except Exception as e:
        console.print(f"  [red]UTF-16LE 스캔 오류: {e}[/red]")

    # ── user32.dll IAT 임포트 및 MessageBox 콜사이트 ──────────────
    console.print()
    console.print("  [dim]── user32.dll IAT / MessageBox 콜사이트 ──[/dim]")
    try:
        imports = pe.get_imports()
        u32 = imports.get("user32.dll", {})
        if not u32:
            console.print("  [yellow]user32.dll 임포트 없음[/yellow]")
        else:
            console.print(f"  user32.dll 임포트: {list(u32.keys())[:20]}")
        for api in ("MessageBoxA", "MessageBoxW", "MessageBoxExA", "MessageBoxExW"):
            iat_va = u32.get(api)
            if iat_va is None:
                console.print(f"  [dim]{api}: IAT 없음[/dim]")
                continue
            sites = []
            for sec_off, sec_rva, sec_va, sec_data in code_sections:
                sites += find_call_sites(
                    sec_data, sec_off, sec_rva,
                    iat_va, pe.is_64bit, pe.image_base,
                )
            console.print(
                f"  [green]{api} IAT=0x{iat_va:X}  "
                f"콜사이트({len(sites)}): "
                f"{[f'0x{c[1]:X}' for c in sites[:8]]}[/green]"
            )
            for call_off, call_va in sites[:8]:
                jump = find_prev_cond_jump(cs, pe.data, call_off, call_va, max_bytes=512)
                if jump:
                    j_off, j_va, j_bytes = jump
                    console.print(
                        f"    [yellow]← Jcc @ 0x{j_va:X} "
                        f"({j_bytes.hex()}) offset=0x{j_off:X}[/yellow]"
                    )
                else:
                    console.print(f"    [dim]← 이전 Jcc 없음 (512B 이내)[/dim]")
    except Exception as e:
        console.print(f"  [red]IAT 분석 오류: {e}[/red]")

    console.print()


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
        if found:
            console.print(f"  [green]{cat:<10} {len(found):3d}건 탐지[/green]")
        elif cat == "dotnet" and not dotnet:
            console.print(f"  [dim]{cat:<10}   0건 (CLR 헤더 없음 — 스킵)[/dim]")
        else:
            console.print(f"  [dim]{cat:<10}   0건[/dim]")
        findings.extend(found)

    # dotnet 카테고리 실행 후 0건이면 원인 진단 자동 출력
    if "dotnet" in args.categories and dotnet:
        if not any(f.category == "dotnet" for f in findings):
            _print_dotnet_diag(pe, cs)
    else:
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
