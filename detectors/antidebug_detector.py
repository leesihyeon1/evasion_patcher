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

from core.disasm import find_call_sites, find_next_cond_jump, nop_cond_jump
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
    ],
    "ntdll.dll": [
        "NtQueryInformationProcess",
        "ZwQueryInformationProcess",
    ],
}

# IsDebuggerPresent 호출(FF 15 xx xx xx xx = 6 bytes)을
# XOR EAX,EAX(33 C0) + NOP*4 로 교체 → EAX=0(비디버그) 강제
_ZERO_EAX_PATCH = b"\x33\xC0" + b"\x90" * 4   # 6 bytes


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

        return findings

    def _make_finding(self, api: str, call_off: int, call_va: int) -> Finding:
        call_size = 6
        patch_actions: list[PatchAction] = []

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
