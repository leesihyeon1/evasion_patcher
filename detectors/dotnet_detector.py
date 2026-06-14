"""
.NET 관리 코드 자가 무결성 / 안티디버그 탐지

탐지 대상
---------
1. IntegrityString  — "File corrupted"/"manipulated" 등 오류 메시지 참조 이전 IL 조건 분기
2. AntiDebugString  — "debugger has been found" 등 디버거 탐지 메시지 이전 IL 조건 분기
3. ToolNameString   — "windbg.exe"/"x64dbg.exe" 등 툴 이름 참조 이전 IL 조건 분기

탐지 원리
---------
ldstr IL 명령어(0x72 + 4-byte token) → #US 힙 토큰으로 대상 문자열 특정
→ 해당 ldstr 앞 64바이트 내 IL 조건 분기(brfalse/brtrue 등) 탐색
→ NOP(0x00) 대체

비네이티브 PE의 경우 get_us_heap()이 None을 반환하므로 비-.NET 파일에서 자동 스킵됨.
"""
from __future__ import annotations

from core.dotnet_utils import (
    get_us_heap,
    find_us_string_tokens,
    find_ldstr_refs,
    find_call_sites_il,
    find_method_call_tokens,
    find_prev_il_branch,
    _IL_NOP,
)
from .base import BaseDetector, Finding, PatchAction

# MessageBox / Environment.Exit 계열 메서드 — 오류 경로 콜사이트 탐지 대상
_ERROR_CALL_TARGETS: list[tuple[str, str]] = [
    ("MessageBox",   "Show"),
    ("MessageBox",   "ShowDialog"),
    ("Environment",  "Exit"),
    ("Application",  "Exit"),
]

# (검색 문자열, 기법 이름) 목록 — 우선순위 높은 순서로 배치
_STRINGS: list[tuple[str, str]] = [
    ("File corrupted",          "IntegrityString"),
    ("manipulated",             "IntegrityString"),
    ("cracked",                 "IntegrityString"),
    ("tampered",                "IntegrityString"),
    ("debugger has been found", "AntiDebugString"),
    ("unload it from memory",   "AntiDebugString"),
    ("debugger is running",     "AntiDebugString"),
    ("detected a debugger",     "AntiDebugString"),
    ("windbg.exe",              "ToolNameString"),
    ("ollydbg.exe",             "ToolNameString"),
    ("x64dbg.exe",              "ToolNameString"),
    ("x32dbg.exe",              "ToolNameString"),
    ("processhacker",           "ToolNameString"),
    ("immunitydebugger",        "ToolNameString"),
    ("cheatengine",             "ToolNameString"),
    ("ida64.exe",               "ToolNameString"),
]


class DotNetDetector(BaseDetector):
    CATEGORY = "dotnet"

    def detect(self) -> list[Finding]:
        seen: set[int] = set()
        findings: list[Finding] = []

        findings.extend(self._detect_ldstr_strings(seen))
        findings.extend(self._detect_messagebox_calls(seen))

        return findings

    # ── 1. #US 힙 문자열 역참조 이전 IL 분기 ─────────────────────
    def _detect_ldstr_strings(self, seen: set[int]) -> list[Finding]:
        """ldstr 명령어로 오류 문자열을 로드하는 패턴 탐지."""
        us_result = get_us_heap(self.pe.data)
        if us_result is None:
            return []

        _, us_data = us_result
        findings: list[Finding] = []

        for search, technique in _STRINGS:
            for token in find_us_string_tokens(us_data, search):
                for ldstr_off in find_ldstr_refs(self.pe.data, token):
                    branch = find_prev_il_branch(self.pe.data, ldstr_off)
                    if branch is None:
                        continue
                    b_off, b_bytes = branch
                    if b_off in seen:
                        continue
                    seen.add(b_off)
                    nop_bytes = bytes([_IL_NOP] * len(b_bytes))
                    findings.append(Finding(
                        category="dotnet",
                        technique=technique,
                        va=ldstr_off,
                        file_offset=b_off,
                        description=(
                            f"[.NET] '{search}' ldstr @ 0x{ldstr_off:X}"
                            f" → IL Jcc @ 0x{b_off:X} NOP ({len(b_bytes)}B)"
                        ),
                        patch_actions=[PatchAction(
                            file_offset=b_off,
                            original_bytes=b_bytes,
                            new_bytes=nop_bytes,
                            description=f"[.NET IL] '{search}' 조건 분기 NOP",
                        )],
                    ))
        return findings

    # ── 2. MessageBox.Show / Environment.Exit 콜사이트 이전 IL 분기
    def _detect_messagebox_calls(self, seen: set[int]) -> list[Finding]:
        """
        MemberRef 테이블에서 MessageBox.Show / Environment.Exit 토큰을 찾아
        해당 call 명령어 이전 IL 조건 분기를 NOP.

        PowerRat처럼 문자열이 아닌 열거형 정수 비교로 오류 경로를 결정하는
        패턴에서 직접 오류 팝업/종료 호출을 탐지해 분기를 차단.
        """
        tokens = find_method_call_tokens(self.pe.data, _ERROR_CALL_TARGETS)
        if not tokens:
            return []

        findings: list[Finding] = []
        for token, display_name in tokens:
            for call_off in find_call_sites_il(self.pe.data, token):
                branch = find_prev_il_branch(
                    self.pe.data, call_off, max_lookback=128
                )
                if branch is None:
                    continue
                b_off, b_bytes = branch
                if b_off in seen:
                    continue
                seen.add(b_off)
                nop_bytes = bytes([_IL_NOP] * len(b_bytes))
                findings.append(Finding(
                    category="dotnet",
                    technique="ManagedAntiAnalysis",
                    va=call_off,
                    file_offset=b_off,
                    description=(
                        f"[.NET] {display_name} call @ 0x{call_off:X}"
                        f" → IL Jcc @ 0x{b_off:X} NOP ({len(b_bytes)}B)"
                    ),
                    patch_actions=[PatchAction(
                        file_offset=b_off,
                        original_bytes=b_bytes,
                        new_bytes=nop_bytes,
                        description=f"[.NET IL] {display_name} 이전 조건 분기 NOP",
                    )],
                ))
        return findings
