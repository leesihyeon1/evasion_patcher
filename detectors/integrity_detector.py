"""
자가 무결성 검사(Self-Integrity Check) 탐지 및 우회

탐지 대상
---------
1. PE_Checksum       — OptionalHeader.CheckSum 저장값 vs 실제 계산값 불일치
2. SelfHash_GetModuleHandle — GetModuleHandleA/W(NULL) 콜사이트 (자가 베이스 조회)
3. CryptHash         — CryptCreateHash / CryptHashData / CryptGetHashParam
4. IntegrityString   — "corrupt"/"manipulat"/"cracked" 등 오류 문자열 역참조 이전 Jcc

패치 전략
---------
- 조건부 점프(Jcc) NOP
- PE 체크섬 필드 초기화 → patcher.py 저장 직전 update_checksum() 으로 재계산
"""
from __future__ import annotations

import struct

from capstone.x86 import X86_OP_IMM, X86_OP_REG, X86_REG_ECX, X86_REG_RCX

from core.disasm import (
    find_call_sites,
    find_next_cond_jump,
    find_prev_cond_jump,
    find_va_refs_in_code,
    nop_cond_jump,
    scan_ascii_pattern,
    str_boundary_start,
)
from .base import BaseDetector, Finding, PatchAction


_ERROR_STRINGS: list[bytes] = [
    b"corrupt",
    b"manipulat",
    b"cracked",
    b"tampered",
    b"infected",
    b"debugger has been found",
    b"unload it from memory",
    b"debugger is running",
    b"detected a debugger",
]

_CRYPT_APIS: list[str] = [
    "CryptCreateHash",
    "CryptHashData",
    "CryptGetHashParam",
]

_MODULE_APIS: list[str] = [
    "GetModuleHandleA",
    "GetModuleHandleW",
]


class IntegrityDetector(BaseDetector):
    CATEGORY = "integrity"

    def detect(self) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._detect_checksum())
        findings.extend(self._detect_getmodulehandle())
        findings.extend(self._detect_crypt_hash())
        findings.extend(self._detect_error_strings())
        return findings

    # ── 1. PE 체크섬 불일치 ────────────────────────────────────────
    def _detect_checksum(self) -> list[Finding]:
        chksum_off = self.pe.get_checksum_offset()
        stored = struct.unpack_from('<I', bytes(self.pe.data), chksum_off)[0]
        if stored == 0:
            return []
        computed = self.pe.compute_checksum()
        if stored == computed:
            return []
        return [Finding(
            category="integrity",
            technique="PE_Checksum",
            va=chksum_off,
            file_offset=chksum_off,
            description=(
                f"PE 체크섬 불일치 (stored=0x{stored:08X}, "
                f"computed=0x{computed:08X}) — 저장 후 재계산 예정"
            ),
            patch_actions=[PatchAction(
                file_offset=chksum_off,
                original_bytes=struct.pack('<I', stored),
                new_bytes=b'\x00\x00\x00\x00',
                description="OptionalHeader.CheckSum → 0 (저장 직전 update_checksum()으로 재계산)",
            )],
        )]

    # ── 2. GetModuleHandle(NULL) 자가 베이스 조회 ──────────────────
    def _detect_getmodulehandle(self) -> list[Finding]:
        findings: list[Finding] = []
        imports = self.pe.get_imports()
        dll_imp = imports.get("kernel32.dll", {})

        for api in _MODULE_APIS:
            iat_va = dll_imp.get(api)
            if iat_va is None:
                continue
            for sec_off, sec_rva, sec_va, sec_data in self.pe.get_code_sections():
                for call_off, call_va in find_call_sites(
                    sec_data, sec_off, sec_rva,
                    iat_va, self.pe.is_64bit, self.pe.image_base,
                ):
                    if not self._is_null_arg(call_off, call_va):
                        continue
                    jump = find_next_cond_jump(
                        self.cs, self.pe.data,
                        call_off + 6, call_va + 6,
                    )
                    actions, desc = self._jcc_patch(jump, f"{api}(NULL) 자가 해시 분기")
                    findings.append(Finding(
                        category="integrity",
                        technique=f"SelfHash_{api}",
                        va=call_va,
                        file_offset=call_off,
                        description=f"{api}(NULL) @ 0x{call_va:08X} {desc}",
                        patch_actions=actions,
                    ))
        return findings

    # ── 3. Crypt API 기반 해시 무결성 ─────────────────────────────
    def _detect_crypt_hash(self) -> list[Finding]:
        findings: list[Finding] = []
        imports = self.pe.get_imports()
        dll_imp = imports.get("advapi32.dll", {})

        for api in _CRYPT_APIS:
            iat_va = dll_imp.get(api)
            if iat_va is None:
                continue
            for sec_off, sec_rva, sec_va, sec_data in self.pe.get_code_sections():
                for call_off, call_va in find_call_sites(
                    sec_data, sec_off, sec_rva,
                    iat_va, self.pe.is_64bit, self.pe.image_base,
                ):
                    jump = find_next_cond_jump(
                        self.cs, self.pe.data,
                        call_off + 6, call_va + 6,
                    )
                    actions, desc = self._jcc_patch(jump, f"{api} 해시 검증 분기")
                    findings.append(Finding(
                        category="integrity",
                        technique=f"CryptHash_{api}",
                        va=call_va,
                        file_offset=call_off,
                        description=f"{api} @ 0x{call_va:08X} {desc}",
                        patch_actions=actions,
                    ))
        return findings

    # ── 4. 오류 문자열 역참조 이전 Jcc ────────────────────────────
    def _detect_error_strings(self) -> list[Finding]:
        findings: list[Finding] = []
        code_sections = self.pe.get_code_sections()
        seen_jcc_offsets: set[int] = set()

        for pattern in _ERROR_STRINGS:
            for sec_off, sec_rva, sec_va, sec_data in self.pe.get_all_sections():
                for match_file_off in scan_ascii_pattern(sec_data, sec_off, pattern):
                    # 패턴이 문자열 중간을 가리킬 수 있으므로 실제 시작 역탐색
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
                        actions, desc = self._jcc_patch(
                            jump,
                            f"'{pattern.decode()}' 오류 문자열 참조 이전 분기",
                        )
                        if jump:
                            seen_jcc_offsets.add(jump[0])
                        findings.append(Finding(
                            category="integrity",
                            technique="IntegrityString",
                            va=ref_va,
                            file_offset=ref_off,
                            description=(
                                f"'{pattern.decode()}' 문자열 참조 "
                                f"@ 0x{ref_va:08X} {desc}"
                            ),
                            patch_actions=actions,
                        ))
        return findings

    # ── 내부 헬퍼 ─────────────────────────────────────────────────
    def _jcc_patch(
        self,
        jump: tuple | None,
        label: str,
    ) -> tuple[list[PatchAction], str]:
        if jump is None:
            return [], "(조건부 점프 미발견)"
        j_off, j_va, j_bytes = jump
        return (
            [PatchAction(
                file_offset=j_off,
                original_bytes=j_bytes,
                new_bytes=nop_cond_jump(j_bytes),
                description=f"{label} NOP",
            )],
            f"Jcc @ 0x{j_va:08X} → NOP",
        )

    def _is_null_arg(self, call_off: int, call_va: int) -> bool:
        """CALL 직전 인자가 NULL(0)인지 확인."""
        look_back = min(call_off, 32)
        start = call_off - look_back
        chunk = bytes(self.pe.data[start:call_off])
        insns = list(self.cs.disasm(chunk, call_va - look_back))
        if not insns:
            return False
        last = insns[-1]
        m = last.mnemonic.lower()
        ops = last.operands or []
        if not self.pe.is_64bit:
            return (m == "push" and ops
                    and ops[0].type == X86_OP_IMM and ops[0].imm == 0)
        if m == "xor" and len(ops) == 2:
            return ops[0].reg in (X86_REG_ECX, X86_REG_RCX)
        if m == "mov" and len(ops) == 2:
            return (ops[0].reg in (X86_REG_ECX, X86_REG_RCX)
                    and ops[1].type == X86_OP_IMM and ops[1].imm == 0)
        return False

