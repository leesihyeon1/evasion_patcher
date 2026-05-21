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

from core.disasm import (
    find_call_sites,
    find_next_cond_jump,
    scan_two_byte_pattern,
    scan_ascii_pattern,
    nop_cond_jump,
)
from .base import BaseDetector, Finding, PatchAction

_CPUID = b"\x0f\xa2"

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
        for sec_off, sec_rva, sec_va, sec_data in self.pe.get_code_sections():
            for file_off, abs_va in scan_two_byte_pattern(
                sec_data, sec_off, sec_rva, self.pe.image_base, _CPUID
            ):
                orig = self.pe.read_bytes(file_off, 2)
                findings.append(Finding(
                    category="vm",
                    technique="CPUID",
                    va=abs_va,
                    file_offset=file_off,
                    description=(
                        f"CPUID 명령 @ 0x{abs_va:08X} "
                        "— 하이퍼바이저 비트(ECX bit31) 확인 가능성"
                    ),
                    patch_actions=[PatchAction(
                        file_offset=file_off,
                        original_bytes=orig,
                        new_bytes=b"\x90\x90",
                        description="CPUID → NOP NOP",
                    )],
                ))

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
