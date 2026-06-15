"""
Capstone 기반 역어셈블 헬퍼

핵심 기능
---------
- IAT 간접 호출(FF 15) 콜사이트 탐색
- 콜사이트 이후 첫 번째 조건부 점프 탐색  (NOP 또는 플립 패치 대상)
- 콜사이트 이전 Push/MOV 인자 탐색       (Sleep 인자 패치 대상)
- RDTSC(0F 31) / CPUID(0F A2) 바이트 패턴 탐색
"""

from __future__ import annotations

import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
from capstone.x86 import (
    X86_OP_IMM, X86_OP_REG,
    X86_REG_ECX, X86_REG_RCX,
)


# ── Capstone 인스턴스 ─────────────────────────────────────────────
def make_cs(is_64bit: bool) -> Cs:
    mode = CS_MODE_64 if is_64bit else CS_MODE_32
    cs = Cs(CS_ARCH_X86, mode)
    cs.detail = True
    return cs


# ── 조건부 점프 opcode 집합 ───────────────────────────────────────
# Short Jcc: 70-7F (opcode 1 byte, rel 1 byte)  → 총 2 bytes
# Near  Jcc: 0F 80-8F (opcode 2 bytes, rel 4 bytes) → 총 6 bytes
_SHORT_JCC = set(range(0x70, 0x80))


def _nop(size: int) -> bytes:
    return b"\x90" * size


def flip_cond_jump(insn_bytes: bytes) -> bytes:
    """
    조건부 점프 opcode의 condition bit를 반전한 새 바이트열 반환.
    예) JZ(74) → JNZ(75),  JL(7C) → JGE(7D)
    """
    b = bytearray(insn_bytes)
    if b[0] in _SHORT_JCC:          # short Jcc
        b[0] ^= 1
    elif b[0] == 0x0F and 0x80 <= b[1] <= 0x8F:  # near Jcc
        b[1] ^= 1
    return bytes(b)


def nop_cond_jump(insn_bytes: bytes) -> bytes:
    """조건부 점프를 크기에 맞는 NOP으로 대체"""
    return _nop(len(insn_bytes))


# ── IAT 콜사이트 탐색 ─────────────────────────────────────────────
def find_call_sites(
    sec_data: bytes,
    sec_file_offset: int,
    sec_rva: int,
    iat_abs_va: int,
    is_64bit: bool,
    image_base: int,
) -> list[tuple[int, int]]:
    """
    섹션 데이터에서 특정 IAT 슬롯을 대상으로 하는
    간접 호출(FF 15 ...) 명령어를 모두 탐색한다.

    Parameters
    ----------
    sec_data       : 섹션 raw 바이트
    sec_file_offset: 파일 내 섹션 시작 오프셋
    sec_rva        : 섹션 VirtualAddress (RVA)
    iat_abs_va     : 대상 IAT 슬롯 절대 VA  (pefile imp.address)
    is_64bit       : x64 PE 여부
    image_base     : OPTIONAL_HEADER.ImageBase

    Returns
    -------
    [(file_offset, call_abs_va), ...]
    """
    results: list[tuple[int, int]] = []
    n = len(sec_data)
    i = 0

    while i < n - 5:
        if sec_data[i] != 0xFF or sec_data[i + 1] != 0x15:
            i += 1
            continue

        call_file_offset = sec_file_offset + i
        call_abs_va = image_base + sec_rva + i

        if is_64bit:
            # FF 15 [rel32]  →  target = (call_va + 6) + rel32
            if i + 6 > n:
                i += 1
                continue
            rel = struct.unpack_from("<i", sec_data, i + 2)[0]
            target = call_abs_va + 6 + rel
        else:
            # FF 15 [abs32]  →  직접 비교
            if i + 6 > n:
                i += 1
                continue
            target = struct.unpack_from("<I", sec_data, i + 2)[0]

        if target == iat_abs_va:
            results.append((call_file_offset, call_abs_va))

        i += 1

    return results


# ── 콜사이트 이후 조건부 점프 탐색 ───────────────────────────────
def find_prev_cond_jump(
    cs: Cs,
    pe_data: bytearray,
    from_file_offset: int,
    from_va: int,
    max_bytes: int = 256,
) -> tuple[int, int, bytes] | None:
    """
    from_file_offset 이전 max_bytes 범위에서 가장 가까운 조건부 점프를 반환.
    정방향 디스어셈블 후 마지막 Jcc 반환.
    """
    start = max(0, from_file_offset - max_bytes)
    chunk = bytes(pe_data[start: from_file_offset])
    chunk_va = from_va - (from_file_offset - start)

    last_jcc: tuple[int, int, bytes] | None = None
    for insn in cs.disasm(chunk, chunk_va):
        m = insn.mnemonic
        if m.startswith("j") and m != "jmp":
            offset_in_chunk = insn.address - chunk_va
            last_jcc = (start + offset_in_chunk, insn.address, bytes(insn.bytes))
    return last_jcc


def find_next_cond_jump(
    cs: Cs,
    pe_data: bytearray,
    from_file_offset: int,
    from_va: int,
    max_bytes: int = 128,
) -> tuple[int, int, bytes] | None:
    """
    from_file_offset 이후 max_bytes 범위에서 첫 번째 조건부 점프를 반환.

    Returns
    -------
    (file_offset, va, insn_bytes) 또는 None
    """
    chunk = bytes(pe_data[from_file_offset : from_file_offset + max_bytes])
    for insn in cs.disasm(chunk, from_va):
        m = insn.mnemonic
        if m.startswith("j") and m != "jmp":
            offset_in_chunk = insn.address - from_va
            return (
                from_file_offset + offset_in_chunk,
                insn.address,
                bytes(insn.bytes),
            )
    return None


# ── 콜사이트 이전 인자 탐색 (Sleep/SleepEx 대상) ─────────────────
def find_sleep_arg_before_call(
    cs: Cs,
    pe_data: bytearray,
    call_file_offset: int,
    call_va: int,
    is_64bit: bool,
) -> tuple[int, int, bytes] | None:
    """
    CALL 직전 명령어에서 Sleep 인자(imm 값)를 찾는다.

    x86  : PUSH imm8/imm32  직전 명령어
    x64  : MOV ECX/RCX, imm 직전 명령어

    Returns
    -------
    (file_offset_of_imm_instr, imm_value, original_bytes) 또는 None
    """
    look_back = min(call_file_offset, 64)
    chunk_start = call_file_offset - look_back
    chunk = bytes(pe_data[chunk_start : call_file_offset])
    base_va = call_va - look_back

    insns = list(cs.disasm(chunk, base_va))

    # CALL 바로 앞 몇 개 명령어를 역순으로 확인
    for insn in reversed(insns):
        if insn.address >= call_va:
            continue
        if not insn.operands:
            break

        m = insn.mnemonic.lower()

        if not is_64bit and m == "push":
            op = insn.operands[0]
            if op.type == X86_OP_IMM:
                val = op.imm & 0xFFFFFFFF
                off = chunk_start + (insn.address - base_va)
                return (off, val, bytes(pe_data[off : off + insn.size]))

        elif is_64bit and m == "mov" and len(insn.operands) == 2:
            op0, op1 = insn.operands
            if (
                op0.type == X86_OP_REG
                and op0.reg in (X86_REG_ECX, X86_REG_RCX)
                and op1.type == X86_OP_IMM
            ):
                val = op1.imm & 0xFFFFFFFF
                off = chunk_start + (insn.address - base_va)
                return (off, val, bytes(pe_data[off : off + insn.size]))

        # 중간에 무관한 명령어가 끼어 있으면 탐색 중단
        break

    return None


# ── 2바이트 패턴 스캔 (RDTSC / CPUID) ────────────────────────────
def scan_two_byte_pattern(
    sec_data: bytes,
    sec_file_offset: int,
    sec_rva: int,
    image_base: int,
    pattern: bytes,  # e.g. b"\x0f\x31" or b"\x0f\xa2"
) -> list[tuple[int, int]]:
    """
    섹션 내 2바이트 패턴 전체 위치 반환.

    Returns
    -------
    [(file_offset, abs_va), ...]
    """
    results: list[tuple[int, int]] = []
    i = 0
    n = len(sec_data)
    while i < n - 1:
        if sec_data[i] == pattern[0] and sec_data[i + 1] == pattern[1]:
            results.append((sec_file_offset + i, image_base + sec_rva + i))
        i += 1
    return results


# ── 문자열 경계 역탐색 ───────────────────────────────────────────
def str_boundary_start(data: bytes, offset: int, max_lookback: int = 256) -> int:
    """
    offset 위치에서 역방향으로 스캔하여 ASCII 문자열의 실제 시작 오프셋 반환.
    null 바이트 또는 비ASCII 문자(< 0x20 or > 0x7E) 이전 위치를 반환.
    """
    i = offset - 1
    limit = max(0, offset - max_lookback)
    while i >= limit:
        b = data[i]
        if b == 0 or b < 0x20 or b > 0x7E:
            return i + 1
        i -= 1
    return offset


# ── 코드 섹션 내 VA 참조 탐색 (push/LEA) ──────────────────────────
def find_va_refs_in_code(
    str_va: int,
    code_sections: list,
    is_64bit: bool,
    image_base: int,
) -> list[tuple[int, int]]:
    """
    코드 섹션에서 str_va를 참조하는 push imm32(x86) 또는 LEA rip+disp32(x64)
    명령어의 (file_offset, instr_va) 목록을 반환.
    """
    import struct as _s
    results: list[tuple[int, int]] = []
    va_lo32 = _s.pack('<I', str_va & 0xFFFFFFFF)

    for sec_off, sec_rva, sec_va, sec_data in code_sections:
        n = len(sec_data)
        if not is_64bit:
            # push imm32: 0x68 <4-byte LE VA>
            for i in range(1, n - 4):
                if sec_data[i - 1] == 0x68 and sec_data[i:i + 4] == va_lo32:
                    results.append((sec_off + i - 1, image_base + sec_rva + i - 1))
        else:
            # LEA reg, [RIP+disp32]: Rex(0x40-0x4F) + 0x8D + ModRM(RIP-rel) + disp32
            for i in range(n - 6):
                if (0x40 <= sec_data[i] <= 0x4F
                        and sec_data[i + 1] == 0x8D
                        and (sec_data[i + 2] & 0xC7) == 0x05):
                    instr_va = image_base + sec_rva + i
                    disp = _s.unpack_from('<i', sec_data, i + 3)[0]
                    if instr_va + 7 + disp == str_va:
                        results.append((sec_off + i, instr_va))
    return results


# ── 문자열 패턴 스캔 (VM 아티팩트 탐지) ──────────────────────────
def scan_ascii_pattern(
    sec_data: bytes,
    sec_file_offset: int,
    pattern: bytes,   # lowercase ASCII
) -> list[int]:
    """
    섹션 내 ASCII 문자열 패턴(대소문자 무시) 파일 오프셋 목록 반환.
    """
    lower = sec_data.lower()
    results = []
    start = 0
    while True:
        idx = lower.find(pattern, start)
        if idx == -1:
            break
        results.append(sec_file_offset + idx)
        start = idx + 1
    return results


def scan_wide_pattern(
    sec_data: bytes,
    sec_file_offset: int,
    pattern: bytes,   # lowercase ASCII bytes
) -> list[int]:
    """
    섹션 내 UTF-16LE 문자열 패턴(대소문자 무시) 파일 오프셋 목록 반환.
    C++/CLI 혼합 모드 바이너리의 네이티브 데이터 섹션에 저장된
    와이드 문자열(MessageBoxW 인자 등) 탐지용.
    """
    pat_lower = bytes(b | 0x20 if 0x41 <= b <= 0x5A else b for b in pattern)
    plen = len(pat_lower)
    n = len(sec_data)
    results: list[int] = []
    i = 0
    while i <= n - plen * 2:
        match = True
        for j in range(plen):
            hi = sec_data[i + j * 2]
            lo = sec_data[i + j * 2 + 1]
            if lo != 0:          # 고바이트(BMP 아닌 문자) → 불일치
                match = False
                break
            c = hi | 0x20 if 0x41 <= hi <= 0x5A else hi
            if c != pat_lower[j]:
                match = False
                break
        if match:
            results.append(sec_file_offset + i)
        i += 1
    return results


def str_boundary_start_wide(data: bytes, offset: int, max_lookback: int = 512) -> int:
    """
    UTF-16LE 문자열에서 offset 위치의 실제 시작 오프셋을 역방향으로 탐색.
    2바이트 단위로 역탐색하며 null 와이드 문자(\x00\x00) 또는
    비ASCII 와이드 문자 직후를 반환.
    """
    i = (offset - 2) & ~1   # 2바이트 정렬 후 1문자 뒤로
    limit = max(0, offset - max_lookback) & ~1
    while i >= limit:
        if i + 1 >= len(data):
            break
        lo = data[i + 1]   # UTF-16LE 고바이트
        hi = data[i]       # UTF-16LE 저바이트 (코드포인트)
        if lo != 0 or hi == 0 or hi < 0x20 or hi > 0x7E:
            return i + 2   # 다음 위치가 문자열 시작
        i -= 2
    return offset
