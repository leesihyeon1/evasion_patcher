"""
AutoIt 컴파일 EXE 탐지 및 샌드박스 회피 패치

AutoIt 컴파일 EXE 구조
-----------------------
  PE 헤더 + 코드 섹션 — AutoIt3 런타임 인터프리터 (x86/x64 네이티브)
  리소스 섹션 (.rsrc) — 암호화된 .au3 스크립트 + 매직 AU3!EAxx

AutoIt 버전별 매직
------------------
  AU3!EA06  AutoIt v3.3.14.x
  AU3!EA05  AutoIt v3.3.8–3.3.12
  AU3!EA04  AutoIt v3.3.6.x
  AU3!EA03  AutoIt v3.3.4 이하

탐지 대상
---------
1. AutoIt 빌드 식별     — AU3! 매직 / "AutoIt" 버전 문자열
2. RDTSC (0F 31)        — 스텁 내 타이밍 체크
3. CPUID (0F A2)        — 스텁 내 하이퍼바이저 체크
4. Sleep 류 API         — 긴 인자 패치 (>5000 ms)
5. GetTickCount 류      — 이후 조건부 점프 NOP
6. AntiDebug API        — IsDebuggerPresent·NtQueryInformationProcess Jcc NOP
7. VM 탐지 API          — RegOpenKeyEx·CreateFile·GetModuleHandle Jcc NOP
8. 스크립트 레벨 문자열 — 회피 키워드 스캔 (보고서 전용)

패치 전략
---------
- 스텁 코드 패치는 기존 탐지기(sleep/vm/antidebug)와 동일한 바이트 패치 방식
- 스크립트 레벨은 암호화로 인해 직접 패치 불가 → 탐지 보고만
"""
from __future__ import annotations

import struct

from core.disasm import (
    find_call_sites,
    find_next_cond_jump,
    find_sleep_arg_before_call,
    scan_two_byte_pattern,
    scan_ascii_pattern,
    nop_cond_jump,
)
from .base import BaseDetector, Finding, PatchAction

# ── AutoIt 식별 매직 ──────────────────────────────────────────────────
_AU3_MAGICS: list[tuple[bytes, str]] = [
    (b"AU3!EA06", "AutoIt v3.3.14.x (EA06)"),
    (b"AU3!EA05", "AutoIt v3.3.8–3.3.12 (EA05)"),
    (b"AU3!EA04", "AutoIt v3.3.6 (EA04)"),
    (b"AU3!EA03", "AutoIt v3.3.4 이하 (EA03)"),
]

# PE 버전 문자열 기반 보조 탐지
_AU3_PE_STRINGS: list[bytes] = [
    b"AutoIt v3",
    b"AutoIt3",
    b"This is a compiled AutoIt script.",
    b"AutoIt Error",
]

# ── 스텁 내 탐지 대상 패턴 ───────────────────────────────────────────
_RDTSC = b"\x0f\x31"
_CPUID = b"\x0f\xa2"

_SLEEP_THRESHOLD_MS = 5_000

_TIMING_APIS = {
    "kernel32.dll": ["Sleep", "SleepEx", "GetTickCount", "GetTickCount64"],
    "ntdll.dll":    ["NtDelayExecution", "ZwDelayExecution"],
    "winmm.dll":    ["timeGetTime"],
}

_ANTIDEBUG_APIS = {
    "kernel32.dll": ["IsDebuggerPresent", "CheckRemoteDebuggerPresent"],
    "ntdll.dll":    ["NtQueryInformationProcess"],
}

_VM_APIS = {
    "kernel32.dll": ["GetModuleHandleA", "GetModuleHandleW",
                     "CreateFileA", "CreateFileW"],
    "advapi32.dll": ["RegOpenKeyExA", "RegOpenKeyExW",
                     "RegQueryValueExA", "RegQueryValueExW"],
}

# ── AutoIt 스크립트 레벨 회피 키워드 (대소문자 무시, 보고서 전용) ────
_SCRIPT_KEYWORDS: list[tuple[bytes, str]] = [
    (b"IsDebuggerPresent",       "AntiDebug — IsDebuggerPresent API 문자열"),
    (b"CheckRemoteDebugger",     "AntiDebug — CheckRemoteDebuggerPresent 문자열"),
    (b"NtQueryInformationProc",  "AntiDebug — NtQueryInformationProcess 문자열"),
    (b"VirtualBox",              "VM 탐지 — VirtualBox 문자열"),
    (b"vmware",                  "VM 탐지 — VMware 문자열"),
    (b"Sandboxie",               "VM 탐지 — Sandboxie 문자열"),
    (b"vboxservice",             "VM 탐지 — VBox 서비스 프로세스 문자열"),
    (b"vmtoolsd",                "VM 탐지 — VMware Tools 프로세스 문자열"),
    (b"vboxtray",                "VM 탐지 — VBoxTray 프로세스 문자열"),
    (b"wireshark",               "VM 탐지 — Wireshark 탐지 문자열"),
    (b"@COMPUTERNAME",           "AutoIt 매크로 — 컴퓨터 이름 확인"),
    (b"@USERNAME",               "AutoIt 매크로 — 사용자 이름 확인"),
    (b"@LOGONDOMAIN",            "AutoIt 매크로 — 도메인 확인"),
    (b"PROCESSEXISTS",           "AutoIt 함수 — 프로세스 존재 확인"),
    (b"REGREAD",                 "AutoIt 함수 — 레지스트리 읽기"),
    (b"ENVGET",                  "AutoIt 함수 — 환경변수 읽기 (샌드박스 탐지)"),
]


def _detect_autoit(data: bytes) -> tuple[bool, str]:
    """
    바이너리에서 AutoIt 빌드 여부와 버전 문자열을 반환.

    Returns
    -------
    (is_autoit, version_description)
    """
    for magic, version in _AU3_MAGICS:
        if magic in data:
            return True, version

    data_lower = data.lower()
    for s in _AU3_PE_STRINGS:
        if s.lower() in data_lower:
            return True, "AutoIt v3 (버전 매직 미발견, 문자열 기반 탐지)"

    return False, ""


class AutoItDetector(BaseDetector):
    """
    AutoIt 컴파일 EXE 전용 회피 기법 탐지기.

    AutoIt 빌드가 아니면 detect() 가 빈 리스트를 반환하므로
    일반 PE에 함께 적용해도 안전하다.
    """
    CATEGORY = "autoit"

    def detect(self) -> list[Finding]:
        findings: list[Finding] = []

        # ── 0) AutoIt 빌드 확인 ────────────────────────────────────
        is_autoit, au3_version = _detect_autoit(bytes(self.pe.data))
        if not is_autoit:
            return []

        findings.append(Finding(
            category="autoit",
            technique="AU3_IDENT",
            va=0,
            file_offset=0,
            description=f"AutoIt 컴파일 EXE 탐지: {au3_version} — 스텁 패치 시작",
        ))

        imports = self.pe.get_imports()

        # ── 1) RDTSC → NOP NOP ────────────────────────────────────
        for sec_off, sec_rva, sec_va, sec_data in self.pe.get_code_sections():
            for file_off, abs_va in scan_two_byte_pattern(
                sec_data, sec_off, sec_rva, self.pe.image_base, _RDTSC
            ):
                orig = self.pe.read_bytes(file_off, 2)
                findings.append(Finding(
                    category="autoit",
                    technique="RDTSC",
                    va=abs_va,
                    file_offset=file_off,
                    description=f"[AutoIt 스텁] RDTSC 타이밍 체크 @ 0x{abs_va:08X}",
                    patch_actions=[PatchAction(
                        file_offset=file_off,
                        original_bytes=orig,
                        new_bytes=b"\x90\x90",
                        description="AutoIt 스텁 RDTSC → NOP NOP",
                    )],
                ))

        # ── 2) CPUID → NOP NOP ────────────────────────────────────
        for sec_off, sec_rva, sec_va, sec_data in self.pe.get_code_sections():
            for file_off, abs_va in scan_two_byte_pattern(
                sec_data, sec_off, sec_rva, self.pe.image_base, _CPUID
            ):
                orig = self.pe.read_bytes(file_off, 2)
                findings.append(Finding(
                    category="autoit",
                    technique="CPUID",
                    va=abs_va,
                    file_offset=file_off,
                    description=f"[AutoIt 스텁] CPUID 하이퍼바이저 체크 @ 0x{abs_va:08X}",
                    patch_actions=[PatchAction(
                        file_offset=file_off,
                        original_bytes=orig,
                        new_bytes=b"\x90\x90",
                        description="AutoIt 스텁 CPUID → NOP NOP",
                    )],
                ))

        # ── 3) Sleep류 API ─────────────────────────────────────────
        for dll, apis in _TIMING_APIS.items():
            dll_imports = imports.get(dll, {})
            for api in apis:
                iat_va = dll_imports.get(api)
                if iat_va is None:
                    continue
                is_sleep = api in (
                    "Sleep", "SleepEx", "NtDelayExecution", "ZwDelayExecution"
                )
                for sec_off, sec_rva, sec_va, sec_data in self.pe.get_code_sections():
                    for call_off, call_va in find_call_sites(
                        sec_data, sec_off, sec_rva,
                        iat_va, self.pe.is_64bit, self.pe.image_base,
                    ):
                        if is_sleep:
                            findings.extend(
                                self._patch_sleep_arg(api, call_off, call_va)
                            )
                        else:
                            findings.extend(
                                self._nop_after_call("sleep_tick", api, call_off, call_va)
                            )

        # ── 4) AntiDebug API → Jcc NOP ────────────────────────────
        for dll, apis in _ANTIDEBUG_APIS.items():
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
                        findings.extend(
                            self._nop_after_call("antidebug", api, call_off, call_va)
                        )

        # ── 5) VM 탐지 API → Jcc NOP ──────────────────────────────
        for dll, apis in _VM_APIS.items():
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
                        findings.extend(
                            self._nop_after_call("vm_api", api, call_off, call_va)
                        )

        # ── 6) 전체 바이너리 — 스크립트 레벨 키워드 스캔 ─────────
        raw_lower = bytes(self.pe.data).lower()
        for pattern, label in _SCRIPT_KEYWORDS:
            pat_lower = pattern.lower()
            pos = 0
            while True:
                idx = raw_lower.find(pat_lower, pos)
                if idx == -1:
                    break
                findings.append(Finding(
                    category="autoit",
                    technique="SCRIPT_STRING",
                    va=0,
                    file_offset=idx,
                    description=(
                        f"[AutoIt 스크립트 문자열] {label} "
                        f"@ 파일오프셋 0x{idx:X} (수동 확인 권장)"
                    ),
                    # patch_actions 없음 — 암호화 스크립트 직접 패치 불가
                ))
                pos = idx + len(pattern)

        return findings

    # ── 패치 헬퍼 ─────────────────────────────────────────────────────

    def _patch_sleep_arg(
        self, api: str, call_off: int, call_va: int
    ) -> list[Finding]:
        result = find_sleep_arg_before_call(
            self.cs, self.pe.data, call_off, call_va, self.pe.is_64bit
        )
        if result is None:
            return []
        arg_off, arg_val, orig_bytes = result
        if arg_val <= _SLEEP_THRESHOLD_MS:
            return []

        new_bytes = bytearray(orig_bytes)
        val_bytes = struct.pack("<I", arg_val & 0xFFFF_FFFF)
        idx = orig_bytes.find(val_bytes)
        if idx == -1:
            idx = orig_bytes.find(bytes([arg_val & 0xFF]))
            if idx == -1:
                return []
            new_bytes[idx] = 0x01
        else:
            new_bytes[idx:idx + 4] = b"\x01\x00\x00\x00"

        return [Finding(
            category="autoit",
            technique=api,
            va=call_va,
            file_offset=call_off,
            description=(
                f"[AutoIt 스텁] {api}({arg_val:,} ms) @ 0x{call_va:08X} — 인자 패치"
            ),
            patch_actions=[PatchAction(
                file_offset=arg_off,
                original_bytes=orig_bytes,
                new_bytes=bytes(new_bytes),
                description=f"AutoIt {api} 인자 {arg_val:,} ms → 1 ms",
            )],
        )]

    def _nop_after_call(
        self, technique: str, api: str, call_off: int, call_va: int
    ) -> list[Finding]:
        call_size = 6  # FF 15 xx xx xx xx
        jump = find_next_cond_jump(
            self.cs, self.pe.data,
            call_off + call_size,
            call_va  + call_size,
        )
        if jump is None:
            return [Finding(
                category="autoit",
                technique=technique,
                va=call_va,
                file_offset=call_off,
                description=(
                    f"[AutoIt 스텁] {api} @ 0x{call_va:08X} (조건부 점프 미발견)"
                ),
            )]
        j_off, j_va, j_bytes = jump
        return [Finding(
            category="autoit",
            technique=technique,
            va=call_va,
            file_offset=call_off,
            description=(
                f"[AutoIt 스텁] {api} @ 0x{call_va:08X} → Jcc @ 0x{j_va:08X} NOP"
            ),
            patch_actions=[PatchAction(
                file_offset=j_off,
                original_bytes=j_bytes,
                new_bytes=nop_cond_jump(j_bytes),
                description=f"AutoIt {api} 이후 탐지 분기 NOP",
            )],
        )]
