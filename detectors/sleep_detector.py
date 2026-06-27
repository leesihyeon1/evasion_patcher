"""
Sleep / 타이밍 기반 샌드박스 회피 탐지

탐지 대상
---------
1. RDTSC (0F 31)          — 실행 시간 측정 후 sandbox 판단
2. Sleep(N > threshold)   — 긴 sleep으로 sandbox timeout 유도
3. SleepEx                — 동일
4. GetTickCount / GetTickCount64  — 경과 시간 비교
5. NtDelayExecution       — 저수준 Sleep
6. timeGetTime            — WinMM 타이밍

패치 전략
---------
- RDTSC           → NOP NOP (0F 31 → 90 90)
- Sleep 큰 인자   → 인자를 1로 교체 (PUSH 600000 → PUSH 1)
- GetTickCount 류 → 반환 후 조건부 점프 NOP
"""
from __future__ import annotations

import struct

from capstone.x86 import X86_OP_IMM, X86_OP_REG, X86_REG_EAX

from core.disasm import (
    find_call_sites,
    find_next_cond_jump,
    find_sleep_arg_before_call,
    scan_two_byte_pattern,
    nop_cond_jump,
)
from .base import BaseDetector, Finding, PatchAction

# 이 값(ms) 초과 Sleep 인자만 패치
_SLEEP_THRESHOLD_MS = 5_000

_RDTSC  = b"\x0f\x31"


def _rdtsc_is_timing_check(cs, pe_data: bytearray, file_off: int, va: int) -> bool:
    """
    RDTSC 이후 64B 내에 타이밍 체크 패턴이 있는지 확인.
    - sub eax, [mem] / sub eax, reg  → 타이밍 델타 계산
    - cmp eax, imm  (eax 비교)       → 임계값 비교
    - ja / jg / jb / jl              → 타이밍 기반 분기
    → 하나라도 있으면 타이밍 체크로 판단.
    """
    fwd_chunk = bytes(pe_data[file_off + 2: file_off + 2 + 80])
    for insn in cs.disasm(fwd_chunk, va + 2):
        m = insn.mnemonic.lower()
        ops = insn.operands

        # sub eax, ... → 타이밍 델타 계산
        if m == "sub" and ops and ops[0].type == X86_OP_REG and ops[0].reg == X86_REG_EAX:
            return True
        # cmp eax, imm → 임계값 비교
        if m == "cmp" and ops and ops[0].type == X86_OP_REG and ops[0].reg == X86_REG_EAX:
            return True
        # 무조건 점프는 여기서 끝
        if m == "jmp" or m in ("ret", "retn", "call"):
            break
    return False
_TIMING_APIS = {
    "kernel32.dll": ["Sleep", "SleepEx", "GetTickCount", "GetTickCount64"],
    "ntdll.dll":    ["NtDelayExecution", "ZwDelayExecution"],
    "winmm.dll":    ["timeGetTime"],
}


class SleepDetector(BaseDetector):
    CATEGORY = "sleep"

    def detect(self) -> list[Finding]:
        findings: list[Finding] = []
        imports = self.pe.get_imports()

        # ── 1) RDTSC 패턴 스캔 ──────────────────────────────────
        _rdtsc_patch = 0
        _rdtsc_skip  = 0
        for sec_off, sec_rva, sec_va, sec_data in self.pe.get_code_sections():
            for file_off, abs_va in scan_two_byte_pattern(
                sec_data, sec_off, sec_rva, self.pe.image_base, _RDTSC
            ):
                is_timing = _rdtsc_is_timing_check(
                    self.cs, self.pe.data, file_off, abs_va
                )
                if is_timing:
                    _rdtsc_patch += 1
                else:
                    _rdtsc_skip += 1
                orig = self.pe.read_bytes(file_off, 2)
                findings.append(Finding(
                    category="sleep",
                    technique="RDTSC",
                    va=abs_va,
                    file_offset=file_off,
                    description=(
                        f"RDTSC 타이밍 체크 @ 0x{abs_va:08X}"
                        if is_timing else
                        f"RDTSC @ 0x{abs_va:08X} — 타이밍 패턴 없음 (제외)"
                    ),
                    patch_actions=[PatchAction(
                        file_offset=file_off,
                        original_bytes=orig,
                        new_bytes=b"\x90\x90",
                        description="RDTSC → NOP NOP",
                    )] if is_timing else [],
                ))
        print(f"  [RDTSC 분석] 패치대상={_rdtsc_patch}건 / 제외(비타이밍)={_rdtsc_skip}건")

        # ── 2) Sleep / SleepEx — 인자 패치 ──────────────────────
        for dll, apis in _TIMING_APIS.items():
            dll_imports = imports.get(dll, {})
            for api in apis:
                iat_va = dll_imports.get(api)
                if iat_va is None:
                    continue

                is_sleep = api in ("Sleep", "SleepEx", "NtDelayExecution", "ZwDelayExecution")

                for sec_off, sec_rva, sec_va, sec_data in self.pe.get_code_sections():
                    for call_off, call_va in find_call_sites(
                        sec_data, sec_off, sec_rva,
                        iat_va, self.pe.is_64bit, self.pe.image_base
                    ):
                        if is_sleep:
                            findings.extend(self._patch_sleep_arg(
                                api, call_off, call_va
                            ))
                        else:
                            # GetTickCount 류 → 이후 조건부 점프 NOP
                            findings.extend(self._nop_after_call(
                                api, call_off, call_va
                            ))

        return findings

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
            return []  # 짧은 sleep은 패치 불필요

        # 인자 바이트를 1로 교체
        # PUSH imm8(6A)/imm32(68) or MOV reg, imm
        new_bytes = bytearray(orig_bytes)
        # imm 값을 1로 설정: 인자 값을 바이트 내에서 찾아 교체
        val_bytes = struct.pack("<I", arg_val & 0xFFFFFFFF)
        idx = orig_bytes.find(val_bytes)
        if idx == -1:
            # imm8 단일 바이트인 경우
            idx = orig_bytes.find(bytes([arg_val & 0xFF]))
            if idx == -1:
                return []
            new_bytes[idx] = 0x01
        else:
            new_bytes[idx:idx+4] = b"\x01\x00\x00\x00"

        return [Finding(
            category="sleep",
            technique=api,
            va=call_va,
            file_offset=call_off,
            description=f"{api}({arg_val:,} ms) 호출 @ 0x{call_va:08X} — 인자 패치",
            patch_actions=[PatchAction(
                file_offset=arg_off,
                original_bytes=orig_bytes,
                new_bytes=bytes(new_bytes),
                description=f"{api} 인자 {arg_val:,}ms → 1ms",
            )],
        )]

    def _nop_after_call(
        self, api: str, call_off: int, call_va: int
    ) -> list[Finding]:
        """GetTickCount 류: 호출 후 조건부 점프 NOP"""
        call_size = 6  # FF 15 XX XX XX XX
        jump = find_next_cond_jump(
            self.cs, self.pe.data,
            call_off + call_size,
            call_va + call_size,
        )
        if jump is None:
            return [Finding(
                category="sleep",
                technique=api,
                va=call_va,
                file_offset=call_off,
                description=f"{api} 호출 @ 0x{call_va:08X} (조건부 점프 미발견)",
            )]

        j_off, j_va, j_bytes = jump
        return [Finding(
            category="sleep",
            technique=api,
            va=call_va,
            file_offset=call_off,
            description=f"{api} 호출 @ 0x{call_va:08X} → 이후 Jcc @ 0x{j_va:08X} NOP",
            patch_actions=[PatchAction(
                file_offset=j_off,
                original_bytes=j_bytes,
                new_bytes=nop_cond_jump(j_bytes),
                description=f"{api} 타이밍 체크 조건부 점프 NOP",
            )],
        )]
