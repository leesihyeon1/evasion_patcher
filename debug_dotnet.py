"""
.NET 메타데이터 진단 스크립트

사용법:
  python debug_dotnet.py <PE 파일>
"""
import sys
import struct
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
sys.stdout.reconfigure(encoding='utf-8')

from core.dotnet_utils import (
    is_dotnet,
    _find_metadata_streams,
    _parse_member_ref_tokens,
    find_us_string_tokens,
    find_ldstr_refs,
    find_call_sites_il,
    find_method_call_tokens,
    find_prev_il_branch,
    _IL_SHORT_BRANCH,
    _IL_LONG_BRANCH,
)

def main():
    if len(sys.argv) < 2:
        print("usage: python debug_dotnet.py <PE 파일>")
        sys.exit(1)

    path = sys.argv[1]
    data = bytearray(Path(path).read_bytes())
    print(f"\n=== {Path(path).name} ===")

    # ── 1. CLR 헤더 확인 ─────────────────────────────────────────
    print(f"\n[1] CLR 헤더: {'있음' if is_dotnet(data) else '없음 (비-.NET PE)'}")
    if not is_dotnet(data):
        return

    # ── 2. 메타데이터 스트림 목록 ────────────────────────────────
    streams = _find_metadata_streams(data)
    if not streams:
        print("[2] 메타데이터 스트림 파싱 실패")
        return
    print(f"\n[2] 메타데이터 스트림: {list(streams.keys())}")
    for name, (off, raw) in streams.items():
        print(f"    {name:<12} 파일오프셋=0x{off:X}  크기={len(raw)}B")

    # ── 3. #US 힙 문자열 탐색 ────────────────────────────────────
    us_result = streams.get('#US')
    if us_result:
        _, us_data = us_result
        print(f"\n[3] #US 힙 크기: {len(us_data)}B")
        targets = [
            "File corrupted", "manipulated", "cracked",
            "debugger has been found", "unload it from memory",
            "windbg.exe", "x64dbg.exe",
        ]
        for s in targets:
            toks = find_us_string_tokens(us_data, s)
            if toks:
                print(f"    '{s}' 토큰: {[hex(t) for t in toks]}")
                for tok in toks:
                    refs = find_ldstr_refs(data, tok)
                    print(f"      ldstr 참조 오프셋: {[hex(r) for r in refs]}")
                    for r in refs:
                        br = find_prev_il_branch(data, r, max_lookback=64)
                        print(f"        IL 분기 @ 0x{r:X} 이전: {br}")
            else:
                print(f"    '{s}' → 없음")
    else:
        print("\n[3] #US 힙 없음")

    # ── 4. #~ TypeRef / MemberRef 파싱 ──────────────────────────
    tilde_data   = streams.get('#~', (0, b''))[1]
    strings_data = streams.get('#Strings', (0, b''))[1]

    if not tilde_data:
        print("\n[4] #~ 스트림 없음")
        return

    print(f"\n[4] #~ 스트림 크기: {len(tilde_data)}B  #Strings: {len(strings_data)}B")

    # HeapSizes 및 테이블 row counts 출력
    heap_sizes = tilde_data[6]
    valid = struct.unpack_from('<Q', tilde_data, 8)[0]
    row_counts: dict[int, int] = {}
    pos = 24
    for tid in range(64):
        if valid & (1 << tid):
            row_counts[tid] = struct.unpack_from('<I', tilde_data, pos)[0]
            pos += 4
    print(f"    HeapSizes=0x{heap_sizes:02X}  "
          f"(Strings={'4B' if heap_sizes&1 else '2B'}  "
          f"GUID={'4B' if heap_sizes&2 else '2B'}  "
          f"Blob={'4B' if heap_sizes&4 else '2B'})")
    print(f"    존재하는 테이블 (ID: rows): "
          + ", ".join(f"0x{t:02X}:{n}" for t, n in sorted(row_counts.items())))

    # TypeRef 전체 이름 출력 (MessageBox/Environment 포함 여부 확인)
    print(f"\n[5] TypeRef 테이블 (0x01): {row_counts.get(0x01, 0)}행")
    try:
        results = _parse_member_ref_tokens(tilde_data, strings_data, [
            ("MessageBox",  "Show"),
            ("MessageBox",  "ShowDialog"),
            ("Environment", "Exit"),
            ("Application", "Exit"),
            ("Console",     "WriteLine"),  # 추가 테스트용
        ])
        if results:
            print(f"    탐지된 MemberRef 토큰:")
            for tok, name in results:
                print(f"      {name}  토큰=0x{tok:08X}")
                call_sites = find_call_sites_il(data, tok)
                print(f"      call 사이트: {[hex(c) for c in call_sites]}")
                for c in call_sites:
                    br = find_prev_il_branch(data, c, max_lookback=128)
                    print(f"        @ 0x{c:X} 이전 IL 분기: {br}")
        else:
            print("    MessageBox/Environment MemberRef 없음")
    except Exception as e:
        print(f"    MemberRef 파싱 오류: {e}")
        import traceback; traceback.print_exc()

    # ── 5. #Strings 힙에서 직접 탐색 ────────────────────────────
    print(f"\n[6] #Strings 힙에서 직접 탐색:")
    for name in [b"MessageBox", b"Show", b"Environment", b"Exit",
                 b"Application", b"Form", b"Dialog"]:
        idx = strings_data.find(name)
        if idx >= 0:
            print(f"    '{name.decode()}' @ strings[0x{idx:X}]")
        else:
            print(f"    '{name.decode()}' → 없음")

if __name__ == "__main__":
    main()
