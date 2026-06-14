"""
안티디버깅 기법 탐지

탐지 대상
---------
- IsDebuggerPresent            — 기본 디버거 탐지
- CheckRemoteDebuggerPresent   — 원격 디버거 탐지
- NtQueryInformationProcess    — ProcessDebugPort(7) / ProcessDebugFlags(31) 확인
- OutputDebugStringA/W         — 타이밍 측정 방식 안티디버그
- FindWindowA/W                — OllyDbg·x64dbg 윈도우 이름 탐색
- GetWindowTextA/W             — 디버거 윈도우 제목 확인

패치 전략
---------
- 각 API 호출 직후 조건부 점프 NOP
- IsDebuggerPresent는 추가로 호출 자체를 XOR EAX,EAX + NOP으로 교체
  (반환값 0 보장)
"""
from __future__ import annotations

from core.disasm import (
    find_call_sites, find_next_cond_jump, find_prev_cond_jump,
    find_va_refs_in_code, nop_cond_jump, scan_ascii_pattern, str_boundary_start,
)
from .base import BaseDetector, Finding, PatchAction

_TARGET_APIS: dict[str, list[str]] = {
    "kernel32.dll": [
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent",
        "OutputDebugStringA",
        "OutputDebugStringW",
        "FindWindowA",
        "FindWindowW",
        "GetWindowTextA",
        "GetWindowTextW",
        "CreateToolhelp32Snapshot",   # 프로세스 목록 열거 기반 디버거 탐지
        "Process32FirstW",
        "Process32NextW",
        "Process32First",
        "Process32Next",
    ],
    "ntdll.dll": [
        "NtQueryInformationProcess",
        "ZwQueryInformationProcess",
        "NtSetInformationThread",     # ThreadHideFromDebugger — 스레드 은닉 → NOP
        "ZwSetInformationThread",
    ],
    "user32.dll": [
        "EnumWindows",                # 윈도우 열거 기반 디버거 탐지
    ],
}

# 디버거/분석 툴 프로세스 이름 — 프로세스 열거 비교 대상
_DEBUGGER_TOOL_NAMES: list[bytes] = [
    b"windbg.exe",
    b"ollydbg.exe",
    b"x64dbg.exe",
    b"x32dbg.exe",
    b"ida64.exe",
    b"ida.exe",
    b"procexp.exe",
    b"procmon.exe",
    b"wireshark.exe",
    b"fiddler.exe",
    b"processhacker.exe",
    b"immunitydebugger.exe",
    b"cheatengine",
]

# IsDebuggerPresent 호출(FF 15 xx xx xx xx = 6 bytes)을
# XOR EAX,EAX(33 C0) + NOP*4 로 교체 → EAX=0(비디버그) 강제
_ZERO_EAX_PATCH = b"\x33\xC0" + b"\x90" * 4   # 6 bytes

# NtSetInformationThread(ThreadHideFromDebugger) → 호출 자체를 NOP
# 6 bytes call → NOP*6
_NOP6 = b"\x90" * 6

# NOP 처리만 할 API (반환값 분기 없음, 호출 자체를 무력화)
_NOP_CALL_APIS = frozenset({
    "NtSetInformationThread",
    "ZwSetInformationThread",
})


class AntiDebugDetector(BaseDetector):
    CATEGORY = "antidebug"

    def detect(self) -> list[Finding]:
        findings: list[Finding] = []
        imports = self.pe.get_imports()

        for dll, apis in _TARGET_APIS.items():
            dll_imports = imports.get(dll, {})
            for api in apis:
                iat_va = dll_imports.get(api)
                if iat_va is None:
                    continue

                for sec_off, sec_rva, sec_va, sec_data in self.pe.get_code_sections():
                    for call_off, call_va in find_call_sites(
                        sec_data, sec_off, sec_rva,
                        iat_va, self.pe.is_64bit, self.pe.image_base,
                    ):
                        findings.append(
                            self._make_finding(api, call_off, call_va)
                        )

        findings.extend(self._detect_tool_strings())
        return findings

    def _make_finding(self, api: str, call_off: int, call_va: int) -> Finding:
        call_size = 6
        patch_actions: list[PatchAction] = []

        # NtSetInformationThread 등: 호출 자체를 NOP (ThreadHideFromDebugger 무력화)
        if api in _NOP_CALL_APIS:
            orig_call = self.pe.read_bytes(call_off, call_size)
            patch_actions.append(PatchAction(
                file_offset=call_off,
                original_bytes=orig_call,
                new_bytes=_NOP6,
                description=f"{api} CALL → NOP (ThreadHideFromDebugger 무력화)",
            ))
            return Finding(
                category="antidebug",
                technique=api,
                va=call_va,
                file_offset=call_off,
                description=f"{api} @ 0x{call_va:08X} → CALL NOP",
                patch_actions=patch_actions,
            )

        # IsDebuggerPresent: 호출 자체를 XOR EAX,EAX로 교체
        if api == "IsDebuggerPresent":
            orig_call = self.pe.read_bytes(call_off, call_size)
            patch_actions.append(PatchAction(
                file_offset=call_off,
                original_bytes=orig_call,
                new_bytes=_ZERO_EAX_PATCH,
                description="IsDebuggerPresent CALL → XOR EAX,EAX + NOP (EAX=0 강제)",
            ))

        # 이후 조건부 점프 NOP (공통)
        jump = find_next_cond_jump(
            self.cs, self.pe.data,
            call_off + call_size, call_va + call_size,
        )

        desc_jump = "(조건부 점프 미발견)"
        if jump is not None:
            j_off, j_va, j_bytes = jump
            desc_jump = f"→ Jcc @ 0x{j_va:08X} NOP"
            patch_actions.append(PatchAction(
                file_offset=j_off,
                original_bytes=j_bytes,
                new_bytes=nop_cond_jump(j_bytes),
                description=f"안티디버그 {api} 이후 분기 NOP",
            ))

        return Finding(
            category="antidebug",
            technique=api,
            va=call_va,
            file_offset=call_off,
            description=f"{api} @ 0x{call_va:08X} {desc_jump}",
            patch_actions=patch_actions,
        )

    def _detect_tool_strings(self) -> list[Finding]:
        """
        디버거/분석 툴 이름 문자열 역참조 이전 Jcc를 NOP 처리.
        CreateToolhelp32Snapshot 기반 프로세스 열거 루프 내 비교 분기 대상.
        """
        findings: list[Finding] = []
        code_sections = self.pe.get_code_sections()
        seen_jcc_offsets: set[int] = set()

        for tool_name in _DEBUGGER_TOOL_NAMES:
            for sec_off, sec_rva, sec_va, sec_data in self.pe.get_all_sections():
                for match_file_off in scan_ascii_pattern(sec_data, sec_off, tool_name):
                    local = match_file_off - sec_off
                    actual_local = str_boundary_start(sec_data, local)
                    str_file_off = sec_off + actual_local
                    str_rva = self.pe.offset_to_rva(str_file_off)
                    if str_rva is None:
                        continue
                    str_va = self.pe.image_base + str_rva

                    for ref_off, ref_va in find_va_refs_in_code(
                        str_va, code_sections,
                        self.pe.is_64bit, self.pe.image_base,
                    ):
                        jump = find_prev_cond_jump(
                            self.cs, self.pe.data, ref_off, ref_va,
                        )
                        if jump and jump[0] in seen_jcc_offsets:
                            continue
                        if jump is None:
                            continue
                        j_off, j_va, j_bytes = jump
                        seen_jcc_offsets.add(j_off)
                        findings.append(Finding(
                            category="antidebug",
                            technique="ToolNameString",
                            va=ref_va,
                            file_offset=ref_off,
                            description=(
                                f"'{tool_name.decode()}' 문자열 참조 "
                                f"@ 0x{ref_va:08X} → Jcc 0x{j_va:08X} NOP"
                            ),
                            patch_actions=[PatchAction(
                                file_offset=j_off,
                                original_bytes=j_bytes,
                                new_bytes=nop_cond_jump(j_bytes),
                                description=f"'{tool_name.decode()}' 비교 분기 NOP",
                            )],
                        ))
        return findings
