"""
사용자 상호작용 체크 탐지

탐지 대상
---------
- GetCursorPos       — 마우스 움직임 없음 = 샌드박스
- GetAsyncKeyState   — 키 입력 없음 = 샌드박스
- GetSystemMetrics   — 화면 해상도가 너무 낮음 = 샌드박스
- GetForegroundWindow— 포그라운드 윈도우 없음 = 샌드박스
- GetLastInputInfo   — 마지막 입력 시간이 오래됨 = 샌드박스
- BlockInput         — 분석 방해용 입력 차단

패치 전략: 각 API 호출 직후 조건부 점프 NOP
"""
from __future__ import annotations

from core.disasm import find_call_sites, find_next_cond_jump, nop_cond_jump
from .base import BaseDetector, Finding, PatchAction

_TARGET_APIS: dict[str, list[str]] = {
    "user32.dll": [
        "GetCursorPos",
        "GetAsyncKeyState",
        "GetSystemMetrics",
        "GetForegroundWindow",
        "GetLastInputInfo",
        "BlockInput",
    ],
}


class UserInputDetector(BaseDetector):
    CATEGORY = "userinput"

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
                        findings.append(self._make_finding(api, call_off, call_va))

        return findings

    def _make_finding(self, api: str, call_off: int, call_va: int) -> Finding:
        call_size = 6
        jump = find_next_cond_jump(
            self.cs, self.pe.data,
            call_off + call_size, call_va + call_size,
        )

        if jump is None:
            return Finding(
                category="userinput",
                technique=api,
                va=call_va,
                file_offset=call_off,
                description=f"{api} @ 0x{call_va:08X} (조건부 점프 미발견)",
            )

        j_off, j_va, j_bytes = jump
        return Finding(
            category="userinput",
            technique=api,
            va=call_va,
            file_offset=call_off,
            description=f"{api} @ 0x{call_va:08X} → Jcc @ 0x{j_va:08X} NOP",
            patch_actions=[PatchAction(
                file_offset=j_off,
                original_bytes=j_bytes,
                new_bytes=nop_cond_jump(j_bytes),
                description=f"사용자 입력 체크 {api} 이후 분기 NOP",
            )],
        )
