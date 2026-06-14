"""
.NET CLR PE 파싱 유틸리티

지원 범위: .NET 2.0+ (ECMA-335 메타데이터 포맷)

주요 기능
---------
- CLR 헤더 감지
- 메타데이터 스트림 탐색 (#US, #~, #Strings)
- #US 힙 파싱 → 문자열 리터럴 토큰 조회
- #~ 테이블 파싱 → MemberRef 토큰 조회 (MessageBox.Show / Environment.Exit 등)
- ldstr / call IL 명령어 탐색
- IL 조건 분기(brfalse/brtrue 등) 역방향 탐색
"""
from __future__ import annotations

import struct

# ── IL 조건 분기 opcode (ECMA-335 §III.3) ────────────────────────
# short form: opcode(1) + int8 offset(1) = 2 bytes
_IL_SHORT_BRANCH: frozenset[int] = frozenset({
    0x2C,  # brfalse.s
    0x2D,  # brtrue.s
    0x3B,  # beq.s
    0x3C,  # bge.s
    0x3D,  # bgt.s
    0x3E,  # ble.s
    0x3F,  # blt.s
    0x40,  # bne.un.s
    0x41,  # bge.un.s
    0x42,  # bgt.un.s
    0x43,  # ble.un.s
    0x44,  # blt.un.s
})
# long form: opcode(1) + int32 offset(4) = 5 bytes
_IL_LONG_BRANCH: frozenset[int] = frozenset({
    0x39,  # brfalse
    0x3A,  # brtrue
    0x45,  # beq
    0x46,  # bge
    0x47,  # bgt
    0x48,  # ble
    0x49,  # blt
    0x4A,  # bne.un
    0x4B,  # bge.un
    0x4C,  # bgt.un
    0x4D,  # ble.un
    0x4E,  # blt.un
})
_IL_LDSTR    = 0x72   # ldstr <token>     5 bytes (opcode + 4-byte token)
_IL_CALL     = 0x28   # call  <token>     5 bytes
_IL_CALLVIRT = 0x6F   # callvirt <token>  5 bytes
_IL_NOP      = 0x00   # nop


# ── PE 보조 ──────────────────────────────────────────────────────

def _rva_to_file_offset(pe_data: bytearray, rva: int) -> int | None:
    """PE 섹션 테이블을 이용한 RVA → 파일 오프셋 변환."""
    try:
        e_lfanew     = struct.unpack_from('<I', pe_data, 0x3C)[0]
        num_sections = struct.unpack_from('<H', pe_data, e_lfanew + 6)[0]
        opt_hdr_size = struct.unpack_from('<H', pe_data, e_lfanew + 20)[0]
        sec_base     = e_lfanew + 24 + opt_hdr_size
        for i in range(num_sections):
            s      = sec_base + i * 40
            v_size = struct.unpack_from('<I', pe_data, s + 8)[0]
            v_rva  = struct.unpack_from('<I', pe_data, s + 12)[0]
            r_size = struct.unpack_from('<I', pe_data, s + 16)[0]
            r_off  = struct.unpack_from('<I', pe_data, s + 20)[0]
            if v_rva <= rva < v_rva + max(v_size, r_size):
                return r_off + (rva - v_rva)
    except Exception:
        pass
    return None


def _find_metadata_streams(pe_data: bytearray) -> dict[str, tuple[int, bytes]] | None:
    """
    PE에서 모든 .NET 메타데이터 스트림을 파싱하여
    {스트림이름: (파일오프셋, raw 바이트)} 딕셔너리 반환.
    """
    try:
        e_lfanew = struct.unpack_from('<I', pe_data, 0x3C)[0]
        magic    = struct.unpack_from('<H', pe_data, e_lfanew + 24)[0]
        is_64    = (magic == 0x20B)
        dd_base  = e_lfanew + 24 + (112 if is_64 else 96)
        clr_rva  = struct.unpack_from('<I', pe_data, dd_base + 14 * 8)[0]
        clr_off  = _rva_to_file_offset(pe_data, clr_rva)
        if clr_off is None:
            return None
        meta_rva = struct.unpack_from('<I', pe_data, clr_off + 8)[0]
        meta_off = _rva_to_file_offset(pe_data, meta_rva)
        if meta_off is None:
            return None
        if bytes(pe_data[meta_off: meta_off + 4]) != b'BSJB':
            return None

        ver_len        = struct.unpack_from('<I', pe_data, meta_off + 12)[0]
        ver_len_padded = (ver_len + 3) & ~3
        hdr_base       = meta_off + 16 + ver_len_padded
        num_streams    = struct.unpack_from('<H', pe_data, hdr_base + 2)[0]

        streams: dict[str, tuple[int, bytes]] = {}
        pos = hdr_base + 4
        for _ in range(num_streams):
            s_off  = struct.unpack_from('<I', pe_data, pos)[0]
            s_size = struct.unpack_from('<I', pe_data, pos + 4)[0]
            name_start = pos + 8
            name_end   = name_start
            while name_end < len(pe_data) and pe_data[name_end] != 0:
                name_end += 1
            name = bytes(pe_data[name_start:name_end]).decode('ascii', errors='replace')
            name_padded = ((name_end - name_start + 1) + 3) & ~3
            pos += 8 + name_padded
            abs_off = meta_off + s_off
            streams[name] = (abs_off, bytes(pe_data[abs_off: abs_off + s_size]))
        return streams
    except Exception:
        return None


# ── .NET 감지 ────────────────────────────────────────────────────

def is_dotnet(pe_data: bytearray) -> bool:
    """PE에 CLR Runtime Header(DataDirectory[14])가 있는지 확인."""
    try:
        e_lfanew = struct.unpack_from('<I', pe_data, 0x3C)[0]
        magic    = struct.unpack_from('<H', pe_data, e_lfanew + 24)[0]
        is_64    = (magic == 0x20B)
        dd_base  = e_lfanew + 24 + (112 if is_64 else 96)
        clr_rva  = struct.unpack_from('<I', pe_data, dd_base + 14 * 8)[0]
        clr_size = struct.unpack_from('<I', pe_data, dd_base + 14 * 8 + 4)[0]
        return clr_rva != 0 and clr_size >= 72
    except Exception:
        return False


# ── #US 힙 파싱 ──────────────────────────────────────────────────

def get_us_heap(pe_data: bytearray) -> tuple[int, bytes] | None:
    """
    .NET #US (UserStrings) 힙의 (파일 오프셋, raw 바이트) 반환.
    문자열 리터럴(ldstr 대상)이 UTF-16LE로 저장됨.
    """
    streams = _find_metadata_streams(pe_data)
    if not streams or '#US' not in streams:
        return None
    return streams['#US']


def find_us_string_tokens(us_data: bytes, search: str) -> list[int]:
    """
    #US 힙에서 search 문자열을 포함하는 항목의 메타데이터 토큰 목록 반환.
    토큰 = 0x70000000 | heap_byte_offset  (ECMA-335 §II.22.9)
    """
    search_lower = search.lower()
    tokens: list[int] = []
    i = 1
    n = len(us_data)

    while i < n:
        b0 = us_data[i]
        if b0 == 0:
            i += 1
            continue
        if b0 & 0x80 == 0:
            length, hdr = b0, 1
        elif b0 & 0xC0 == 0x80:
            if i + 1 >= n:
                break
            length, hdr = ((b0 & 0x3F) << 8) | us_data[i + 1], 2
        elif b0 & 0xE0 == 0xC0:
            if i + 3 >= n:
                break
            length = ((b0 & 0x1F) << 24) | (us_data[i+1] << 16) | (us_data[i+2] << 8) | us_data[i+3]
            hdr = 4
        else:
            i += 1
            continue

        if length == 0:
            i += hdr
            continue

        data_start = i + hdr
        entry_bytes = us_data[data_start: data_start + length]
        if len(entry_bytes) >= 2:
            try:
                # last byte is terminal flag; actual UTF-16LE = entry_bytes[:-1]
                s = entry_bytes[:-1].decode('utf-16-le', errors='ignore').lower()
                if search_lower in s:
                    tokens.append(0x70000000 | i)
            except Exception:
                pass
        i = data_start + length

    return tokens


# ── #~ 테이블 파싱 — MemberRef 토큰 조회 ────────────────────────

def _read_cstring(data: bytes, idx: int) -> str:
    """#Strings 힙에서 idx 위치의 null-terminated UTF-8 문자열 반환."""
    if idx >= len(data):
        return ''
    end = idx
    while end < len(data) and data[end] != 0:
        end += 1
    return data[idx:end].decode('utf-8', errors='ignore')


def _parse_member_ref_tokens(
    tilde: bytes,
    strings: bytes,
    targets: list[tuple[str, str]],
) -> list[tuple[int, str]]:
    """
    #~ 스트림과 #Strings 힙을 파싱하여 targets에 해당하는
    MemberRef 메타데이터 토큰 목록 반환.

    Parameters
    ----------
    targets : [(type_simple_name, method_name), ...]
              예) [("MessageBox", "Show"), ("Environment", "Exit")]

    Returns
    -------
    [(token_int, "TypeName.MethodName"), ...]
    토큰 = 0x0A000000 | memberref_rid  (1-based RID)
    """
    if len(tilde) < 24:
        return []

    # ── 헤더 파싱 ─────────────────────────────────────────────────
    heap_sizes = tilde[6]
    SI = 4 if (heap_sizes & 0x01) else 2  # #Strings 인덱스 크기
    GI = 4 if (heap_sizes & 0x02) else 2  # #GUID 인덱스 크기
    BI = 4 if (heap_sizes & 0x04) else 2  # #Blob 인덱스 크기

    valid = struct.unpack_from('<Q', tilde, 8)[0]
    row_counts: dict[int, int] = {}
    pos = 24
    for tid in range(64):
        if valid & (1 << tid):
            if pos + 4 > len(tilde):
                break
            row_counts[tid] = struct.unpack_from('<I', tilde, pos)[0]
            pos += 4
    tables_start = pos

    # ── 코딩 인덱스 크기 ──────────────────────────────────────────
    # 태그 비트만큼 shift 후 나머지가 인덱스.
    # max_rows < 2^(16-tag_bits) → 2바이트, 이상 → 4바이트
    def _ci(tag_bits: int, *tids: int) -> int:
        m = max((row_counts.get(t, 0) for t in tids), default=0)
        return 4 if m >= (1 << (16 - tag_bits)) else 2

    def _ri(tid: int) -> int:
        return 4 if row_counts.get(tid, 0) > 0xFFFF else 2

    # ResolutionScope (2 tag bits): Module(0), ModuleRef(26), AssemblyRef(35), TypeRef(1)
    RS  = _ci(2, 0x00, 0x1A, 0x23, 0x01)
    # TypeDefOrRef    (2 tag bits): TypeDef(2), TypeRef(1), TypeSpec(27)
    TDR = _ci(2, 0x02, 0x01, 0x1B)
    # MemberRefParent (3 tag bits): TypeDef(2), TypeRef(1), ModuleRef(26), MethodDef(6), TypeSpec(27)
    MRP = _ci(3, 0x02, 0x01, 0x1A, 0x06, 0x1B)

    # ── 테이블별 행 크기 ──────────────────────────────────────────
    # ECMA-335 §II.22.* 테이블 스키마 (0x00-0x0A)
    _SIZES: dict[int, int] = {
        0x00: 2 + SI + GI + GI + GI,                   # Module
        0x01: RS + SI + SI,                              # TypeRef
        0x02: 4 + SI + SI + TDR + _ri(4) + _ri(6),      # TypeDef
        0x03: _ri(4),                                    # FieldPtr (non-standard)
        0x04: 2 + SI + BI,                               # Field
        0x05: _ri(6),                                    # MethodPtr (non-standard)
        0x06: 4 + 2 + 2 + SI + BI + _ri(8),             # MethodDef
        0x07: 0,                                         # (미사용)
        0x08: 2 + 2 + SI,                                # Param
        0x09: _ri(2) + TDR,                              # InterfaceImpl
        0x0A: MRP + SI + BI,                             # MemberRef
    }

    def row_size(tid: int) -> int:
        if tid not in _SIZES:
            raise ValueError(f"알 수 없는 테이블 0x{tid:02X}")
        return _SIZES[tid]

    # ── 유틸 ──────────────────────────────────────────────────────
    def read_idx(off: int, size: int) -> int:
        if size == 2:
            return struct.unpack_from('<H', tilde, off)[0]
        return struct.unpack_from('<I', tilde, off)[0]

    # ── TypeRef 테이블 오프셋 계산 ────────────────────────────────
    # TypeRef(0x01) 이전 테이블 = Module(0x00)
    tr_table_off = tables_start
    for tid in range(0x01):
        if tid in row_counts:
            tr_table_off += row_size(tid) * row_counts[tid]

    # 타겟 타입 이름 집합 (대소문자 무시)
    target_type_set = {tn.lower() for tn, _ in targets}

    # TypeRef RID → 타입 단순 이름 매핑
    typeref_name: dict[int, str] = {}
    tr_row_sz = row_size(0x01)
    for rid in range(1, row_counts.get(0x01, 0) + 1):
        roff = tr_table_off + (rid - 1) * tr_row_sz
        name_idx = read_idx(roff + RS, SI)
        tname = _read_cstring(strings, name_idx)
        if tname.lower() in target_type_set:
            typeref_name[rid] = tname

    if not typeref_name:
        return []

    # ── MemberRef 테이블 오프셋 계산 ─────────────────────────────
    # MemberRef(0x0A) 이전 테이블 = 0x00-0x09
    mr_table_off = tables_start
    for tid in range(0x0A):
        if tid in row_counts:
            mr_table_off += row_size(tid) * row_counts[tid]

    # 타겟 (타입, 메서드) 집합 (대소문자 무시)
    target_set = {(tn.lower(), mn.lower()) for tn, mn in targets}

    results: list[tuple[int, str]] = []
    mr_row_sz = row_size(0x0A)
    for rid in range(1, row_counts.get(0x0A, 0) + 1):
        roff = mr_table_off + (rid - 1) * mr_row_sz

        # Class (MemberRefParent coded index)
        # tag=1 → TypeRef, index = coded >> 3
        class_coded = read_idx(roff, MRP)
        if (class_coded & 0x07) != 1:
            continue
        typeref_rid = class_coded >> 3
        type_name = typeref_name.get(typeref_rid, '')
        if not type_name:
            continue

        # Name (string index)
        method_name = _read_cstring(strings, read_idx(roff + MRP, SI))
        if (type_name.lower(), method_name.lower()) in target_set:
            token = 0x0A000000 | rid
            results.append((token, f"{type_name}.{method_name}"))

    return results


def find_method_call_tokens(
    pe_data: bytearray,
    targets: list[tuple[str, str]],
) -> list[tuple[int, str]]:
    """
    .NET MemberRef 테이블에서 타겟 타입·메서드의 IL 토큰 목록 반환.

    Parameters
    ----------
    targets : [(type_simple_name, method_name), ...]
              예) [("MessageBox", "Show"), ("Environment", "Exit")]

    Returns
    -------
    [(token_int, "TypeName.MethodName"), ...]
    """
    try:
        streams = _find_metadata_streams(pe_data)
        if not streams:
            return []
        tilde_data   = streams.get('#~',       (0, b''))[1]
        strings_data = streams.get('#Strings', (0, b''))[1]
        if not tilde_data or not strings_data:
            return []
        return _parse_member_ref_tokens(tilde_data, strings_data, targets)
    except Exception:
        return []


# ── IL 탐색 / 패치 ───────────────────────────────────────────────

def find_ldstr_refs(pe_data: bytearray, token: int) -> list[int]:
    """
    PE 데이터에서 특정 .NET 문자열 토큰을 참조하는
    ldstr(0x72) 명령어의 파일 오프셋 목록 반환.
    토큰 고바이트가 항상 0x70이므로 이를 필터로 활용해 빠르게 스캔.
    """
    token_bytes = struct.pack('<I', token)
    results: list[int] = []
    n = len(pe_data) - 5
    for i in range(n):
        if pe_data[i] == _IL_LDSTR and pe_data[i + 4] == 0x70:
            if bytes(pe_data[i + 1: i + 5]) == token_bytes:
                results.append(i)
    return results


def find_call_sites_il(pe_data: bytearray, token: int) -> list[int]:
    """
    PE 데이터에서 call(0x28) 또는 callvirt(0x6F) <token> 명령어의
    파일 오프셋 목록 반환.
    """
    token_bytes = struct.pack('<I', token)
    results: list[int] = []
    n = len(pe_data) - 4
    for i in range(n):
        if pe_data[i] in (_IL_CALL, _IL_CALLVIRT):
            if bytes(pe_data[i + 1: i + 5]) == token_bytes:
                results.append(i)
    return results


def find_prev_il_branch(
    pe_data: bytearray,
    from_offset: int,
    max_lookback: int = 64,
) -> tuple[int, bytes] | None:
    """
    from_offset 이전 max_lookback 범위에서 가장 가까운 IL 조건 분기 반환.

    Returns
    -------
    (file_offset, original_bytes) 또는 None
    """
    start = max(0, from_offset - max_lookback)
    last: tuple[int, bytes] | None = None
    i = start
    while i < from_offset:
        b = pe_data[i]
        if b in _IL_SHORT_BRANCH and i + 2 <= from_offset:
            last = (i, bytes(pe_data[i: i + 2]))
            i += 2
        elif b in _IL_LONG_BRANCH and i + 5 <= from_offset:
            last = (i, bytes(pe_data[i: i + 5]))
            i += 5
        else:
            i += 1
    return last
