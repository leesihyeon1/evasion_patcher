"""
VM / 샌드박스 환경 탐지 기법 검출

탐지 대상
---------
1. CPUID (0F A2)          — 하이퍼바이저 비트(ECX bit31) 검사
2. VM 관련 문자열         — VMware·VBox·QEMU·Cuckoo 아티팩트 문자열
3. 레지스트리 API         — RegOpenKeyEx로 VM 전용 레지 키 확인
4. CreateFile \\\\.\\ 장치  — VMware HGFS, VBox pipe 확인
5. GetModuleHandle        — vmtoolsd·vboxservice 모듈 로드 여부 확인

패치 전략
---------
- CPUID            → NOP NOP (0F A2 → 90 90)
- 레지스트리/파일  → API 호출 직후 조건부 점프 NOP
                     (키/파일이 없으면 분기 → 그 분기를 무조건 실행)
- 문자열           → 보고서 기록 (자동 패치 대신 분석가 확인 권장)
"""
from __future__ import annotations

from capstone.x86 import (
    X86_OP_IMM, X86_OP_REG,
    X86_REG_EAX, X86_REG_RAX,
    X86_REG_ECX, X86_REG_RCX,
)

from core.disasm import (
    find_call_sites,
    find_next_cond_jump,
    scan_two_byte_pattern,
    scan_ascii_pattern,
    nop_cond_jump,
)
from .base import BaseDetector, Finding, PatchAction

_CPUID = b"\x0f\xa2"
_EAX_REGS = frozenset({X86_REG_EAX, X86_REG_RAX})
_ECX_REGS = frozenset({X86_REG_ECX, X86_REG_RCX})


def _find_eax_leaf(cs, pe_data: bytearray, file_off: int, va: int):
    """CPUID 직전 EAX에 로드된 리프 값(int)을 반환. 판단 불가 시 None."""
    look_back = min(file_off, 64)
    chunk_start = file_off - look_back
    chunk = bytes(pe_data[chunk_start:file_off])
    base_va = va - look_back
    insns = list(cs.disasm(chunk, base_va))

    for insn in reversed(insns):
        m = insn.mnemonic.lower()
        ops = insn.operands

        # MOV EAX/RAX, imm → 리프 확정
        if m == "mov" and len(ops) == 2:
            dst, src = ops
            if dst.type == X86_OP_REG and dst.reg in _EAX_REGS:
                if src.type == X86_OP_IMM:
                    return src.imm & 0xFFFFFFFF
                return None  # 동적 값 — 불명

        # XOR EAX, EAX → 리프 0
        if m == "xor" and len(ops) == 2:
            dst, src = ops
            if (dst.type == X86_OP_REG and dst.reg in _EAX_REGS
                    and src.type == X86_OP_REG and src.reg == dst.reg):
                return 0

        # CALL/RET → EAX가 리턴값일 수 있음 → 불명
        if m in ("call", "ret", "retn"):
            return None

        # regs_write로 EAX를 수정하는 다른 명령어 탐지
        # (add eax, x / pop eax / imul / etc.)  → 불명으로 중단
        if any(r in _EAX_REGS for r in insn.regs_write):
            return None

    return None


def _checks_hypervisor_bit(cs, pe_data: bytearray, file_off: int, va: int) -> bool:
    """CPUID 이후 64B 내 ECX bit31 검사 패턴 존재 여부."""
    fwd_chunk = bytes(pe_data[file_off + 2: file_off + 2 + 64])
    for insn in cs.disasm(fwd_chunk, va + 2):
        m = insn.mnemonic.lower()
        ops = insn.operands
        if m == "test" and len(ops) == 2:
            dst, src = ops
            if dst.type == X86_OP_REG and dst.reg in _ECX_REGS:
                if src.type == X86_OP_IMM and (src.imm & 0x80000000):
                    return True
        if m == "bt" and len(ops) == 2:
            if (ops[0].type == X86_OP_REG and ops[0].reg in _ECX_REGS
                    and ops[1].type == X86_OP_IMM and ops[1].imm == 31):
                return True
        if m == "shr" and len(ops) == 2:
            if (ops[0].type == X86_OP_REG and ops[0].reg in _ECX_REGS
                    and ops[1].type == X86_OP_IMM and ops[1].imm == 31):
                return True
        # 조건부 점프나 CALL 이후는 추적하지 않음
        if m == "call" or (m.startswith("j") and m != "jmp"):
            break
    return False


def _cpuid_is_vm_detection(cs, pe_data: bytearray, file_off: int, va: int) -> tuple[bool, str]:
    """
    CPUID가 VM 탐지 목적인지 판단.
    Returns (is_vm_detection, reason_str)
    """
    leaf = _find_eax_leaf(cs, pe_data, file_off, va)

    if leaf is None:
        # 리프를 추적하지 못했어도 ECX bit31 검사 패턴이 있으면 VM 탐지
        if _checks_hypervisor_bit(cs, pe_data, file_off, va):
            return True, "리프 불명이나 ECX bit31 검사 확인 → VM 탐지"
        return False, "리프 불명 — ECX bit31 검사 없음 (기능 탐지 가능성)"

    # 하이퍼바이저 전용 리프 (0x40000000-0x4FFFFFFF)
    if 0x40000000 <= leaf <= 0x4FFFFFFF:
        return True, f"하이퍼바이저 전용 리프 0x{leaf:08X}"

    # 리프 0: 벤더 문자열 / 최대 리프 → 기능 탐지 흐름
    if leaf == 0x00:
        return False, "리프 0 (벤더 ID 탐지 — 기능 검사용)"

    # 리프 1: ECX bit31(하이퍼바이저 비트) 검사 여부로 판단
    if leaf == 0x01:
        if _checks_hypervisor_bit(cs, pe_data, file_off, va):
            return True, "리프 1 + ECX bit31 검사 확인"
        return False, "리프 1 — ECX bit31 검사 없음 (기능 탐지용)"

    # 그 외 (2, 4, 7, 0x80000000 등) → 기능 탐지용으로 간주
    return False, f"리프 0x{leaf:08X} — 기능 탐지용으로 제외"

# VM/샌드박스 관련 아티팩트 문자열 (소문자)
_VM_STRINGS: list[tuple[str, str]] = [
    (b"vmware",              "VMware 문자열"),
    (b"virtualbox",         "VirtualBox 문자열"),
    (b"vbox",               "VBox 문자열"),
    (b"qemu",               "QEMU 문자열"),
    (b"cuckoo",             "Cuckoo 샌드박스 문자열"),
    (b"tria.ge",            "Triage 샌드박스 문자열"),
    (b"sandboxie",          "Sandboxie 문자열"),
    (b"wireshark",          "Wireshark 탐지 문자열"),
    (b"vboxservice",        "VBox 서비스 프로세스"),
    (b"vmtoolsd",           "VMware Tools 프로세스"),
    (b"vboxtray",           "VBox Tray 프로세스"),
    (b"software\\vmware",   "VMware 레지스트리 경로"),
    (b"software\\oracle\\virtualbox", "VBox 레지스트리 경로"),
    (b"\\\\.\\pipe\\triage", "Triage 파이프 경로"),
    (b"\\\\.\\vmci",        "VMware 장치 경로"),
    (b"\\\\.\\vboxguest",   "VBox 장치 경로"),
]

_REG_APIS = {
    "advapi32.dll": [
        "RegOpenKeyExA", "RegOpenKeyExW",
        "RegQueryValueExA", "RegQueryValueExW",
    ],
}

_FILE_APIS = {
    "kernel32.dll": ["CreateFileA", "CreateFileW"],
}

_MODULE_APIS = {
    "kernel32.dll": ["GetModuleHandleA", "GetModuleHandleW"],
}


class VMDetector(BaseDetector):
    CATEGORY = "vm"

    def detect(self) -> list[Finding]:
        findings: list[Finding] = []
        imports = self.pe.get_imports()

        # ── 1) CPUID ─────────────────────────────────────────────
        # 컨텍스트 분석으로 VM 탐지용 CPUID만 패치.
        # 기능 탐지용(SSE/AES/AVX 등) CPUID를 NOP으로 죽이면
        # 코드가 잘못된 분기를 타거나 크래시함.
        _cpuid_patch = 0
        _cpuid_skip  = 0
        for sec_off, sec_rva, sec_va, sec_data in self.pe.get_code_sections():
            for file_off, abs_va in scan_two_byte_pattern(
                sec_data, sec_off, sec_rva, self.pe.image_base, _CPUID
            ):
                is_vm, reason = _cpuid_is_vm_detection(
                    self.cs, self.pe.data, file_off, abs_va
                )
                if is_vm:
                    _cpuid_patch += 1
                else:
                    _cpuid_skip += 1
                orig = self.pe.read_bytes(file_off, 2)
                findings.append(Finding(
                    category="vm",
                    technique="CPUID",
                    va=abs_va,
                    file_offset=file_off,
                    description=f"CPUID @ 0x{abs_va:08X} — {reason}",
                    patch_actions=[PatchAction(
                        file_offset=file_off,
                        original_bytes=orig,
                        new_bytes=b"\x90\x90",
                        description="CPUID → NOP NOP",
                    )] if is_vm else [],
                ))
        print(f"  [CPUID 분석] 패치대상={_cpuid_patch}건 / 제외(기능탐지)={_cpuid_skip}건")

        # ── 2) VM 문자열 스캔 (보고서 전용) ─────────────────────
        for sec_off, sec_rva, sec_va, sec_data in self.pe.get_all_sections():
            for pattern_bytes, label in _VM_STRINGS:
                for file_off in scan_ascii_pattern(sec_data, sec_off, pattern_bytes):
                    findings.append(Finding(
                        category="vm",
                        technique="VM_STRING",
                        va=self.pe.image_base + sec_rva + (file_off - sec_off),
                        file_offset=file_off,
                        description=(
                            f"{label} 발견 @ 파일오프셋 0x{file_off:X} "
                            "(수동 확인 권장 — 자동 패치 미적용)"
                        ),
                        # patch_actions 없음 → patchable=False
                    ))

        # ── 3) 레지스트리 API → 이후 Jcc NOP ────────────────────
        for dll, apis in _REG_APIS.items():
            dll_imports = imports.get(dll, {})
            for api in apis:
                iat_va = dll_imports.get(api)
                if iat_va is None:
                    continue
                for sec_off, sec_rva, sec_va, sec_data in self.pe.get_code_sections():
                    for call_off, call_va in find_call_sites(
                        sec_data, sec_off, sec_rva,
                        iat_va, self.pe.is_64bit, self.pe.image_base
                    ):
                        findings.extend(
                            self._nop_after_call("vm_reg", api, call_off, call_va)
                        )

        # ── 4) CreateFile \\.\장치 → 이후 Jcc NOP ───────────────
        for dll, apis in _FILE_APIS.items():
            dll_imports = imports.get(dll, {})
            for api in apis:
                iat_va = dll_imports.get(api)
                if iat_va is None:
                    continue
                for sec_off, sec_rva, sec_va, sec_data in self.pe.get_code_sections():
                    for call_off, call_va in find_call_sites(
                        sec_data, sec_off, sec_rva,
                        iat_va, self.pe.is_64bit, self.pe.image_base
                    ):
                        findings.extend(
                            self._nop_after_call("vm_device", api, call_off, call_va)
                        )

        # ── 5) GetModuleHandle → 이후 Jcc NOP ───────────────────
        for dll, apis in _MODULE_APIS.items():
            dll_imports = imports.get(dll, {})
            for api in apis:
                iat_va = dll_imports.get(api)
                if iat_va is None:
                    continue
                for sec_off, sec_rva, sec_va, sec_data in self.pe.get_code_sections():
                    for call_off, call_va in find_call_sites(
                        sec_data, sec_off, sec_rva,
                        iat_va, self.pe.is_64bit, self.pe.image_base
                    ):
                        findings.extend(
                            self._nop_after_call("vm_module", api, call_off, call_va)
                        )

        return findings

    def _nop_after_call(
        self, technique: str, api: str, call_off: int, call_va: int
    ) -> list[Finding]:
        call_size = 6
        jump = find_next_cond_jump(
            self.cs, self.pe.data,
            call_off + call_size, call_va + call_size,
        )
        if jump is None:
            return [Finding(
                category="vm",
                technique=technique,
                va=call_va,
                file_offset=call_off,
                description=f"{api} @ 0x{call_va:08X} (조건부 점프 미발견)",
            )]

        j_off, j_va, j_bytes = jump
        return [Finding(
            category="vm",
            technique=technique,
            va=call_va,
            file_offset=call_off,
            description=f"{api} @ 0x{call_va:08X} → Jcc @ 0x{j_va:08X} NOP",
            patch_actions=[PatchAction(
                file_offset=j_off,
                original_bytes=j_bytes,
                new_bytes=nop_cond_jump(j_bytes),
                description=f"VM 탐지 {api} 이후 분기 NOP",
            )],
        )]
