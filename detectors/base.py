"""
Finding / PatchAction 데이터 클래스 및 BaseDetector ABC
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class PatchAction:
    """PE 바이너리에 적용할 단일 바이트 패치"""
    file_offset: int        # 파일 내 패치 위치
    original_bytes: bytes   # 패치 전 원본 (검증용)
    new_bytes: bytes        # 패치할 바이트
    description: str        # 패치 이유 (보고서용)

    def __post_init__(self) -> None:
        if len(self.original_bytes) != len(self.new_bytes):
            raise ValueError(
                f"original({len(self.original_bytes)}) != "
                f"new({len(self.new_bytes)}) bytes length"
            )


@dataclass
class Finding:
    """탐지된 회피 기법 한 건"""
    category: str           # sleep | vm | userinput | antidebug
    technique: str          # 세부 기법명
    va: int                 # 탐지 위치 절대 VA
    file_offset: int        # 탐지 위치 파일 오프셋
    description: str        # 설명 (보고서용)
    patch_actions: list[PatchAction] = field(default_factory=list)

    @property
    def is_patchable(self) -> bool:
        return len(self.patch_actions) > 0

    def va_hex(self) -> str:
        return f"0x{self.va:08X}"


class BaseDetector(ABC):
    """탐지기 공통 인터페이스"""

    CATEGORY: str = ""

    def __init__(self, pe, cs) -> None:
        self.pe  = pe   # core.pe_utils.PEFile
        self.cs  = cs   # capstone.Cs

    @abstractmethod
    def detect(self) -> list[Finding]:
        """탐지 실행 → Finding 목록 반환"""
        ...
