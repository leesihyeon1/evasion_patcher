"""
PatchAction 목록을 PE 바이너리에 적용

흐름
----
1. original_bytes 검증 — 실제 파일 바이트와 다르면 스킵 (잘못된 탐지 방지)
2. new_bytes 적용     — pe.patch_bytes()
3. 결과 집계          — applied / skipped / error 분류
"""
from __future__ import annotations

from dataclasses import dataclass

from core.pe_utils import PEFile
from detectors.base import Finding, PatchAction


@dataclass
class PatchResult:
    action: PatchAction
    finding: Finding
    status: str     # "applied" | "skipped" | "error"
    reason: str = ""


def apply_patches(
    pe: PEFile,
    findings: list[Finding],
    dry_run: bool = False,
) -> list[PatchResult]:
    """
    모든 Finding의 PatchAction을 순서대로 적용한다.

    Parameters
    ----------
    pe       : 패치 대상 PEFile (내부 bytearray 직접 수정)
    findings : 탐지기가 반환한 Finding 목록
    dry_run  : True이면 실제 쓰기 없이 검증만 수행

    Returns
    -------
    PatchResult 목록
    """
    results: list[PatchResult] = []
    # 같은 오프셋에 중복 적용 방지
    patched_offsets: set[int] = set()

    for finding in findings:
        for action in finding.patch_actions:
            result = _apply_one(pe, finding, action, dry_run, patched_offsets)
            results.append(result)
            if result.status == "applied" and not dry_run:
                for off in range(action.file_offset,
                                 action.file_offset + len(action.new_bytes)):
                    patched_offsets.add(off)

    return results


def _apply_one(
    pe: PEFile,
    finding: Finding,
    action: PatchAction,
    dry_run: bool,
    patched_offsets: set[int],
) -> PatchResult:
    off  = action.file_offset
    size = len(action.original_bytes)

    # ── 범위 검사 ──────────────────────────────────────────────
    if off < 0 or off + size > len(pe.data):
        return PatchResult(
            action=action, finding=finding,
            status="error",
            reason=f"오프셋 범위 초과 (0x{off:X} + {size}B > {len(pe.data)}B)",
        )

    # ── 중복 오프셋 검사 ────────────────────────────────────────
    overlap = patched_offsets & set(range(off, off + size))
    if overlap:
        return PatchResult(
            action=action, finding=finding,
            status="skipped",
            reason=f"이미 패치된 오프셋 겹침 {[hex(o) for o in sorted(overlap)]}",
        )

    # ── 원본 바이트 검증 ────────────────────────────────────────
    actual = pe.read_bytes(off, size)
    if actual != action.original_bytes:
        return PatchResult(
            action=action, finding=finding,
            status="skipped",
            reason=(
                f"원본 바이트 불일치 "
                f"(expected={action.original_bytes.hex()} "
                f"actual={actual.hex()})"
            ),
        )

    # ── 패치 적용 ───────────────────────────────────────────────
    if not dry_run:
        pe.patch_bytes(off, action.new_bytes)

    prefix = "[DRY] " if dry_run else ""
    return PatchResult(
        action=action, finding=finding,
        status="applied",
        reason=f"{prefix}0x{off:X}: {actual.hex()} → {action.new_bytes.hex()}",
    )


def summarize(results: list[PatchResult]) -> dict[str, int]:
    counts: dict[str, int] = {"applied": 0, "skipped": 0, "error": 0}
    for r in results:
        counts[r.status] += 1
    return counts
