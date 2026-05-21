#!/usr/bin/env python3
"""
evasion_patcher 예제 샘플 PE32(x86) 파일 생성기

생성 파일
---------
  sleep_evasion.exe     — RDTSC, Sleep(600000), GetTickCount 패턴
  vm_evasion.exe        — CPUID, RegOpenKeyExA, GetModuleHandleA 패턴
  userinput_evasion.exe — GetCursorPos, GetAsyncKeyState, GetSystemMetrics 패턴
  antidebug_evasion.exe — IsDebuggerPresent, NtQueryInformationProcess, FindWindowA 패턴
  combined_evasion.exe  — 위 4가지 카테고리 모두 포함

주의
----
  실제 악성코드가 아닙니다.  실행 시 import 해결 실패로 예외가 발생합니다.
  evasion_patcher 탐지·패치 테스트 전용입니다.

PE 구조 (PE32 / x86)
---------------------
  0x000  DOS header (64 bytes, e_lfanew = 0x40)
  0x040  PE signature + COFF header + Optional header + section headers
  0x200  .text  section  (실행 코드 — 회피 기법 패턴 포함)
  0x400  .idata section  (Import Table : IAT / INT / 이름 문자열)

탐지기가 보는 핵심 패턴
-----------------------
  FF 15 [4-byte IAT 슬롯 절대 VA]  — IAT 간접 호출
  0F 31                              — RDTSC
  0F A2                              — CPUID
  7x XX                              — 조건부 점프(Jcc)
"""

import sys
import struct
from pathlib import Path

sys.stdout.reconfigure(encoding='utf-8')

# ── 전역 상수 ─────────────────────────────────────────────────────
IMAGE_BASE = 0x00400000
FILE_ALIGN = 0x0200
SECT_ALIGN = 0x1000
TEXT_RVA   = 0x1000      # .text 섹션 RVA
IDATA_RVA  = 0x2000      # .idata 섹션 RVA
TEXT_FOFF  = 0x0200      # .text 파일 오프셋 (헤더 1블록 뒤)
IDATA_FOFF = 0x0400      # .idata 파일 오프셋

# ── x86 어셈블리 헬퍼 ─────────────────────────────────────────────
def _push32(v: int) -> bytes:
    """PUSH imm32 : 68 xx xx xx xx"""
    return b'\x68' + struct.pack('<I', v & 0xFFFFFFFF)

def _push8(v: int) -> bytes:
    """PUSH imm8 : 6A xx"""
    return bytes([0x6A, v & 0xFF])

def _call_iat(abs_va: int) -> bytes:
    """CALL DWORD PTR [abs_va] : FF 15 xx xx xx xx"""
    return b'\xFF\x15' + struct.pack('<I', abs_va)

def _jz(rel8: int)  -> bytes: return bytes([0x74, rel8 & 0xFF])
def _jnz(rel8: int) -> bytes: return bytes([0x75, rel8 & 0xFF])
def _jl(rel8: int)  -> bytes: return bytes([0x7C, rel8 & 0xFF])

def _test_eax() -> bytes: return b'\x85\xC0'          # TEST EAX, EAX
def _cmp_eax_imm32(v: int) -> bytes:                  # CMP EAX, imm32
    return b'\x3D' + struct.pack('<I', v & 0xFFFFFFFF)

RDTSC       = b'\x0F\x31'   # Read Time-Stamp Counter
CPUID       = b'\x0F\xA2'   # CPU Identification
XOR_EAX     = b'\x33\xC0'   # XOR EAX, EAX
PUSH_EBP    = b'\x55'
MOV_EBP_ESP = b'\x8B\xEC'
POP_EBP     = b'\x5D'
PUSH_0      = b'\x6A\x00'
PUSH_1      = b'\x6A\x01'
RET         = b'\xC3'


# ── 내부 유틸 ─────────────────────────────────────────────────────
def _align(n: int, a: int) -> int:
    return (n + a - 1) & ~(a - 1)


def _build_idata(
    imports: dict[str, list[str]],
    idata_rva: int,
) -> tuple[bytes, dict[str, dict[str, int]]]:
    """
    .idata 섹션(Import Table) 바이트 생성.

    Parameters
    ----------
    imports   : {dll_name: [func_name, ...]}
    idata_rva : .idata 섹션의 RVA

    Returns
    -------
    (idata_bytes, {dll: {func: iat_slot_abs_va}})
      iat_slot_abs_va = IMAGE_BASE + idata_rva + iat_내_슬롯_오프셋
      → pefile의 imp.address 와 동일한 값
    """
    dlls = list(imports.items())
    n_dlls = len(dlls)

    # ── 오프셋 배치 계산 ────────────────────────────────────────
    cur = (n_dlls + 1) * 20          # IMAGE_IMPORT_DESCRIPTOR 배열

    # INT (Import Name Table) — 각 DLL마다 (n_funcs + 1) * 4 bytes
    int_off: dict[str, int] = {}
    for dll, funcs in dlls:
        int_off[dll] = cur
        cur += (len(funcs) + 1) * 4

    # IAT (Import Address Table) — INT와 동일 크기
    iat_off: dict[str, int] = {}
    for dll, funcs in dlls:
        iat_off[dll] = cur
        cur += (len(funcs) + 1) * 4

    # DLL 이름 문자열
    dll_name_off: dict[str, int] = {}
    for dll, _ in dlls:
        dll_name_off[dll] = cur
        cur += len(dll) + 1
        if cur & 1: cur += 1         # word-align

    # IMAGE_IMPORT_BY_NAME (2-byte hint + 이름 + null)
    func_name_off: dict[str, dict[str, int]] = {}
    for dll, funcs in dlls:
        func_name_off[dll] = {}
        for func in funcs:
            func_name_off[dll][func] = cur
            cur += 2 + len(func) + 1
            if cur & 1: cur += 1

    total = _align(cur, 16)
    idata = bytearray(total)

    # ── IMAGE_IMPORT_DESCRIPTOR 배열 ────────────────────────────
    for i, (dll, funcs) in enumerate(dlls):
        struct.pack_into('<IIIII', idata, i * 20,
            idata_rva + int_off[dll],       # OriginalFirstThunk (INT RVA)
            0,                               # TimeDateStamp
            0,                               # ForwarderChain
            idata_rva + dll_name_off[dll],  # Name (DLL name RVA)
            idata_rva + iat_off[dll],       # FirstThunk (IAT RVA)
        )
    # null terminator: 이미 0

    # ── INT 및 IAT 초기값 (RVA to IMAGE_IMPORT_BY_NAME) ─────────
    for dll, funcs in dlls:
        for j, func in enumerate(funcs):
            fn_rva = idata_rva + func_name_off[dll][func]
            struct.pack_into('<I', idata, int_off[dll] + j * 4, fn_rva)
            struct.pack_into('<I', idata, iat_off[dll] + j * 4, fn_rva)

    # ── DLL 이름 문자열 ──────────────────────────────────────────
    for dll, _ in dlls:
        off = dll_name_off[dll]
        idata[off:off + len(dll)] = dll.encode()

    # ── IMAGE_IMPORT_BY_NAME (hint=0 + 함수명) ───────────────────
    for dll, funcs in dlls:
        for func in funcs:
            off = func_name_off[dll][func]
            # hint word = 0 (already zero)
            idata[off + 2 : off + 2 + len(func)] = func.encode()

    # ── IAT 슬롯 절대 VA 맵 ─────────────────────────────────────
    #    pefile의 imp.address = IMAGE_BASE + idata_rva + iat_off + slot_idx * 4
    iat_va_map: dict[str, dict[str, int]] = {}
    for dll, funcs in dlls:
        iat_va_map[dll] = {}
        for j, func in enumerate(funcs):
            iat_va_map[dll][func] = IMAGE_BASE + idata_rva + iat_off[dll] + j * 4

    return bytes(idata), iat_va_map


def _build_pe(code: bytes, idata: bytes) -> bytes:
    """
    최소 PE32 파일 조립.

    레이아웃
    --------
      [0x000] DOS header (64 bytes)
      [0x040] PE sig + COFF + Optional(224) + section headers(2*40)
              → 0x040 + 4 + 20 + 224 + 80 = 0x188 → padded to 0x200
      [0x200] .text  raw data (FILE_ALIGN 정렬)
      [0x400] .idata raw data (FILE_ALIGN 정렬)
    """
    code_raw  = _align(len(code),  FILE_ALIGN)
    idata_raw = _align(len(idata), FILE_ALIGN)

    headers_size = FILE_ALIGN   # 0x200
    image_size   = _align(IDATA_RVA + _align(idata_raw, SECT_ALIGN), SECT_ALIGN)

    # ── DataDirectory ────────────────────────────────────────────
    data_dirs = bytearray(128)                               # 16 * 8 bytes
    struct.pack_into('<II', data_dirs, 8, IDATA_RVA, len(idata))  # [1] Import

    # ── Optional header (96 bytes 고정 부분) ─────────────────────
    opt = bytearray(96)
    o = [0]
    def w1(v): opt[o[0]] = v & 0xFF; o[0] += 1
    def w2(v): struct.pack_into('<H', opt, o[0], v); o[0] += 2
    def w4(v): struct.pack_into('<I', opt, o[0], v); o[0] += 4

    w2(0x010B)        # Magic: PE32
    w1(10); w1(0)     # MajorLinkerVersion, MinorLinkerVersion
    w4(code_raw)      # SizeOfCode
    w4(idata_raw)     # SizeOfInitializedData
    w4(0)             # SizeOfUninitializedData
    w4(TEXT_RVA)      # AddressOfEntryPoint
    w4(TEXT_RVA)      # BaseOfCode
    w4(IDATA_RVA)     # BaseOfData  (PE32 전용)
    w4(IMAGE_BASE)    # ImageBase
    w4(SECT_ALIGN)    # SectionAlignment
    w4(FILE_ALIGN)    # FileAlignment
    w2(4); w2(0)      # MajorOSVersion, MinorOSVersion
    w2(0); w2(0)      # MajorImageVersion, MinorImageVersion
    w2(4); w2(0)      # MajorSubsystemVersion, MinorSubsystemVersion
    w4(0)             # Win32VersionValue
    w4(image_size)    # SizeOfImage
    w4(headers_size)  # SizeOfHeaders
    w4(0)             # CheckSum
    w2(3)             # Subsystem: IMAGE_SUBSYSTEM_WINDOWS_CUI
    w2(0)             # DllCharacteristics
    w4(0x100000)      # SizeOfStackReserve
    w4(0x1000)        # SizeOfStackCommit
    w4(0x100000)      # SizeOfHeapReserve
    w4(0x1000)        # SizeOfHeapCommit
    w4(0)             # LoaderFlags
    w4(16)            # NumberOfRvaAndSizes

    opt_full = bytes(opt) + bytes(data_dirs)   # 224 bytes

    # ── Section headers ──────────────────────────────────────────
    def sec_hdr(name, vsize, vrva, raw_size, raw_off, chars):
        nm = name.encode()[:8].ljust(8, b'\x00')
        return struct.pack('<8sIIIIIIHHI',
                           nm, vsize, vrva, raw_size, raw_off,
                           0, 0, 0, 0, chars)

    secs = (
        sec_hdr('.text',  len(code),  TEXT_RVA,  code_raw,  TEXT_FOFF,  0x60000020) +
        sec_hdr('.idata', len(idata), IDATA_RVA, idata_raw, IDATA_FOFF, 0xC0000040)
    )

    # ── COFF header ──────────────────────────────────────────────
    coff = struct.pack('<HHIIIHH',
        0x014C,  # Machine: IMAGE_FILE_MACHINE_I386
        2,       # NumberOfSections
        0,       # TimeDateStamp
        0, 0,    # Symbol table (unused)
        224,     # SizeOfOptionalHeader
        0x0102,  # Characteristics: EXECUTABLE | 32BIT_MACHINE
    )

    # ── DOS header ───────────────────────────────────────────────
    dos = bytearray(64)
    dos[0:2] = b'MZ'
    struct.pack_into('<H', dos,  2, 0x90)   # e_cblp
    struct.pack_into('<H', dos,  4, 3)      # e_cp
    struct.pack_into('<H', dos,  8, 4)      # e_cparhdr
    struct.pack_into('<H', dos, 14, 0xFF)   # e_maxalloc
    struct.pack_into('<H', dos, 18, 0xB8)   # e_sp
    struct.pack_into('<H', dos, 24, 0x40)   # e_lfarlc
    struct.pack_into('<I', dos, 60, 64)     # e_lfanew → PE sig at 0x40

    # ── 파일 조립 ────────────────────────────────────────────────
    buf = bytearray(headers_size + code_raw + idata_raw)
    buf[0:64] = dos
    header_blob = b'PE\x00\x00' + coff + opt_full + secs
    buf[64 : 64 + len(header_blob)] = header_blob
    buf[TEXT_FOFF  : TEXT_FOFF  + len(code)]  = code
    buf[IDATA_FOFF : IDATA_FOFF + len(idata)] = idata

    return bytes(buf)


# ═══════════════════════════════════════════════════════════════════
# 샘플 생성 함수
# ═══════════════════════════════════════════════════════════════════

def create_sleep_sample(out: Path) -> None:
    """
    Sleep / 타이밍 회피 샘플

    패턴
    ----
    - RDTSC (0F 31) × 2
    - Sleep(600_000 ms)       → 인자 패치 대상
    - SleepEx(180_000 ms)     → 인자 패치 대상
    - GetTickCount → JZ       → Jcc NOP 대상
    """
    imports = {'kernel32.dll': ['Sleep', 'SleepEx', 'GetTickCount', 'ExitProcess']}
    idata, iat = _build_idata(imports, IDATA_RVA)
    k = iat['kernel32.dll']

    code = bytearray()
    code += PUSH_EBP + MOV_EBP_ESP

    # [1] RDTSC 타이밍 체크 #1
    code += RDTSC                              # 0F 31
    code += b'\x50'                            # PUSH EAX

    # [2] Sleep(600_000) = 10분
    code += _push32(600_000)
    code += _call_iat(k['Sleep'])

    # [3] SleepEx(180_000, TRUE) = 3분
    code += PUSH_1                             # bAlertable = TRUE
    code += _push32(180_000)
    code += _call_iat(k['SleepEx'])

    # [4] GetTickCount → TEST → JZ
    code += _call_iat(k['GetTickCount'])
    code += _test_eax()
    # JZ 이후 skip: RDTSC(2)+PUSH(1)+PUSH32(5)+CALL_IAT(6) = 14 bytes
    code += _jz(14)

    # [5] RDTSC 타이밍 체크 #2
    code += RDTSC                              # 0F 31
    code += b'\x50'
    code += _push32(30_000)
    code += _call_iat(k['Sleep'])

    # ExitProcess(0)
    code += PUSH_0
    code += _call_iat(k['ExitProcess'])
    code += POP_EBP + RET

    pe = _build_pe(bytes(code), idata)
    out.write_bytes(pe)
    print(f'  ✔ {out.name:<28} {len(pe):5d} bytes'
          f'  [RDTSC×2, Sleep(600000), SleepEx(180000), GetTickCount+JZ]')


def create_vm_sample(out: Path) -> None:
    """
    VM / 환경 탐지 샘플

    패턴
    ----
    - CPUID (0F A2) × 2       → NOP 대상
    - GetModuleHandleA → JNZ  → Jcc NOP 대상 (vmtoolsd 등 확인)
    - RegOpenKeyExA → JZ      → Jcc NOP 대상 (VMware 레지스트리 키)
    - CreateFileA → JNZ       → Jcc NOP 대상 (VM 장치 경로 등)
    """
    imports = {
        'kernel32.dll': ['GetModuleHandleA', 'CreateFileA', 'ExitProcess'],
        'advapi32.dll': ['RegOpenKeyExA', 'RegCloseKey'],
    }
    idata, iat = _build_idata(imports, IDATA_RVA)
    k = iat['kernel32.dll']
    a = iat['advapi32.dll']

    code = bytearray()
    code += PUSH_EBP + MOV_EBP_ESP

    # [1] CPUID #1 — 하이퍼바이저 비트 확인
    code += XOR_EAX                            # XOR EAX, EAX (leaf 0)
    code += CPUID                              # 0F A2
    code += _test_eax()
    code += _jnz(8)                            # VM 탐지 시 분기

    # [2] GetModuleHandleA(NULL) → TEST → JNZ
    code += PUSH_0
    code += _call_iat(k['GetModuleHandleA'])
    code += _test_eax()
    code += _jnz(6)

    # [3] RegOpenKeyExA(HKLM, "SOFTWARE\\VMware, Inc.", …)
    #     인자 5개 push (dummy 주소 사용)
    code += _push32(0x00401500)                # phkResult
    code += _push32(0x20019)                   # samDesired = KEY_READ
    code += PUSH_0                             # ulOptions
    code += _push32(0x00401100)                # lpSubKey ptr (fake)
    code += _push32(0x80000002)                # hKey = HKEY_LOCAL_MACHINE
    code += _call_iat(a['RegOpenKeyExA'])
    code += _test_eax()
    code += _jz(8)                             # 키 없으면(ERROR_FILE_NOT_FOUND) 분기

    # RegCloseKey 정리
    code += PUSH_0
    code += _call_iat(a['RegCloseKey'])

    # [4] CPUID #2 — extended leaf
    code += _push32(1)
    code += b'\x58'                            # POP EAX  (eax=1)
    code += CPUID                              # 0F A2

    # [5] CreateFileA("\\\\.\\pipe\\triage", …) → TEST → JNZ
    code += _push32(0)                         # lpSecurityAttributes
    code += _push32(3)                         # dwCreationDisposition = OPEN_EXISTING
    code += _push32(0)
    code += _push32(0)
    code += _push32(0x40000000)                # dwDesiredAccess = GENERIC_READ
    code += _push32(0x00401200)                # lpFileName ptr (fake)
    code += _call_iat(k['CreateFileA'])
    code += _test_eax()
    code += _jnz(6)

    code += PUSH_0
    code += _call_iat(k['ExitProcess'])
    code += POP_EBP + RET

    pe = _build_pe(bytes(code), idata)
    out.write_bytes(pe)
    print(f'  ✔ {out.name:<28} {len(pe):5d} bytes'
          f'  [CPUID×2, GetModuleHandleA+JNZ, RegOpenKeyExA+JZ, CreateFileA+JNZ]')


def create_userinput_sample(out: Path) -> None:
    """
    사용자 상호작용 체크 샘플

    패턴
    ----
    - GetCursorPos → JZ        → Jcc NOP 대상
    - GetAsyncKeyState → JZ    → Jcc NOP 대상
    - GetSystemMetrics → JL    → Jcc NOP 대상 (해상도 640 미만 체크)
    - GetLastInputInfo → JZ    → Jcc NOP 대상
    """
    imports = {
        'user32.dll':   ['GetCursorPos', 'GetAsyncKeyState',
                         'GetSystemMetrics', 'GetLastInputInfo'],
        'kernel32.dll': ['ExitProcess'],
    }
    idata, iat = _build_idata(imports, IDATA_RVA)
    u = iat['user32.dll']
    k = iat['kernel32.dll']

    code = bytearray()
    code += PUSH_EBP + MOV_EBP_ESP

    # [1] GetCursorPos(&pt) → TEST → JZ
    code += _push32(0x00401200)                # dummy POINT 주소
    code += _call_iat(u['GetCursorPos'])
    code += _test_eax()
    code += _jz(8)                             # 마우스 없음 → 분기

    # [2] GetAsyncKeyState(VK_LBUTTON=1) → TEST → JZ
    code += _push8(0x01)                       # VK_LBUTTON
    code += _call_iat(u['GetAsyncKeyState'])
    code += _test_eax()
    code += _jz(10)                            # 키 없음 → 분기

    # [3] GetSystemMetrics(SM_CXSCREEN=0) → CMP → JL
    code += PUSH_0                             # SM_CXSCREEN
    code += _call_iat(u['GetSystemMetrics'])
    code += _cmp_eax_imm32(640)               # CMP EAX, 640
    code += _jl(8)                             # 640 미만 = 저해상도 sandbox

    # [4] GetLastInputInfo(&lii) → TEST → JZ
    code += _push32(0x00401210)                # dummy LASTINPUTINFO 주소
    code += _call_iat(u['GetLastInputInfo'])
    code += _test_eax()
    code += _jz(6)

    code += PUSH_0
    code += _call_iat(k['ExitProcess'])
    code += POP_EBP + RET

    pe = _build_pe(bytes(code), idata)
    out.write_bytes(pe)
    print(f'  ✔ {out.name:<28} {len(pe):5d} bytes'
          f'  [GetCursorPos+JZ, GetAsyncKeyState+JZ, GetSystemMetrics+JL, GetLastInputInfo+JZ]')


def create_antidebug_sample(out: Path) -> None:
    """
    안티디버깅 샘플

    패턴
    ----
    - IsDebuggerPresent → JNZ             → CALL 패치(XOR EAX) + Jcc NOP
    - CheckRemoteDebuggerPresent → JZ     → Jcc NOP 대상
    - NtQueryInformationProcess → JZ      → Jcc NOP 대상
    - FindWindowA → JNZ                   → Jcc NOP 대상
    - OutputDebugStringA                  → 타이밍 안티디버그
    """
    imports = {
        'kernel32.dll': ['IsDebuggerPresent', 'CheckRemoteDebuggerPresent',
                         'OutputDebugStringA', 'FindWindowA', 'ExitProcess'],
        'ntdll.dll':    ['NtQueryInformationProcess'],
    }
    idata, iat = _build_idata(imports, IDATA_RVA)
    k = iat['kernel32.dll']
    n = iat['ntdll.dll']

    code = bytearray()
    code += PUSH_EBP + MOV_EBP_ESP

    # [1] IsDebuggerPresent → TEST → JNZ
    code += _call_iat(k['IsDebuggerPresent'])
    code += _test_eax()
    code += _jnz(12)                           # 디버거 감지 → 분기

    # [2] CheckRemoteDebuggerPresent(hProc, &bDebug)
    code += _push32(0x00401300)                # &bDebuggerPresent (dummy)
    code += _push32(0xFFFFFFFF)                # GetCurrentProcess() pseudo-handle
    code += _call_iat(k['CheckRemoteDebuggerPresent'])
    code += _test_eax()
    code += _jz(8)

    # [3] NtQueryInformationProcess(hProc, ProcessDebugPort=7, …)
    code += PUSH_0                             # ReturnLength (dummy)
    code += _push8(4)                          # ProcessInformationLength
    code += _push32(0x00401310)                # ProcessInformation (dummy)
    code += _push8(7)                          # ProcessInformationClass = ProcessDebugPort
    code += _push32(0xFFFFFFFF)                # ProcessHandle
    code += _call_iat(n['NtQueryInformationProcess'])
    code += _test_eax()
    code += _jz(10)

    # [4] FindWindowA(NULL, "OllyDbg") → TEST → JNZ
    code += _push32(0x00401320)                # lpWindowName ptr (fake "OllyDbg")
    code += PUSH_0                             # lpClassName = NULL
    code += _call_iat(k['FindWindowA'])
    code += _test_eax()
    code += _jnz(8)

    # [5] OutputDebugStringA — 타이밍 측정용 안티디버그
    code += _push32(0x00401330)                # dummy string
    code += _call_iat(k['OutputDebugStringA'])

    code += PUSH_0
    code += _call_iat(k['ExitProcess'])
    code += POP_EBP + RET

    pe = _build_pe(bytes(code), idata)
    out.write_bytes(pe)
    print(f'  ✔ {out.name:<28} {len(pe):5d} bytes'
          f'  [IsDebuggerPresent+JNZ, CheckRemote+JZ, NtQueryInfo+JZ, FindWindow+JNZ]')


def create_combined_sample(out: Path) -> None:
    """
    전체 카테고리 복합 샘플

    4가지 카테고리(sleep, vm, userinput, antidebug) 기법을 모두 포함.
    patcher.py 기본 실행(카테고리 미지정) 테스트에 사용.
    """
    imports = {
        'kernel32.dll': ['Sleep', 'GetTickCount', 'IsDebuggerPresent',
                         'GetModuleHandleA', 'ExitProcess'],
        'user32.dll':   ['GetCursorPos', 'GetSystemMetrics'],
        'advapi32.dll': ['RegOpenKeyExA'],
        'ntdll.dll':    ['NtDelayExecution'],
    }
    idata, iat = _build_idata(imports, IDATA_RVA)
    k = iat['kernel32.dll']
    u = iat['user32.dll']
    a = iat['advapi32.dll']
    n = iat['ntdll.dll']

    code = bytearray()
    code += PUSH_EBP + MOV_EBP_ESP

    # [sleep] RDTSC + Sleep
    code += RDTSC
    code += _push32(600_000)
    code += _call_iat(k['Sleep'])

    # [sleep] GetTickCount → JZ
    code += _call_iat(k['GetTickCount'])
    code += _test_eax()
    code += _jz(8)

    # [vm] CPUID
    code += XOR_EAX + CPUID
    code += _test_eax()
    code += _jnz(6)

    # [vm] GetModuleHandleA → JNZ
    code += PUSH_0
    code += _call_iat(k['GetModuleHandleA'])
    code += _test_eax()
    code += _jnz(6)

    # [vm] RegOpenKeyExA → JZ
    code += _push32(0) + _push32(0x20019) + PUSH_0
    code += _push32(0x00401100) + _push32(0x80000002)
    code += _call_iat(a['RegOpenKeyExA'])
    code += _test_eax()
    code += _jz(8)

    # [userinput] GetCursorPos → JZ
    code += _push32(0x00401200)
    code += _call_iat(u['GetCursorPos'])
    code += _test_eax()
    code += _jz(6)

    # [userinput] GetSystemMetrics → JL
    code += PUSH_0
    code += _call_iat(u['GetSystemMetrics'])
    code += _cmp_eax_imm32(640)
    code += _jl(6)

    # [antidebug] IsDebuggerPresent → JNZ
    code += _call_iat(k['IsDebuggerPresent'])
    code += _test_eax()
    code += _jnz(8)

    # [sleep] NtDelayExecution
    code += PUSH_1
    code += _push32(0x00401400)
    code += _call_iat(n['NtDelayExecution'])

    code += PUSH_0
    code += _call_iat(k['ExitProcess'])
    code += POP_EBP + RET

    pe = _build_pe(bytes(code), idata)
    out.write_bytes(pe)
    print(f'  ✔ {out.name:<28} {len(pe):5d} bytes'
          f'  [sleep+vm+userinput+antidebug 복합]')


# ── 진입점 ────────────────────────────────────────────────────────
def main() -> None:
    out_dir = Path(__file__).parent
    print('샘플 PE32 파일 생성 중...\n')

    create_sleep_sample    (out_dir / 'sleep_evasion.exe')
    create_vm_sample       (out_dir / 'vm_evasion.exe')
    create_userinput_sample(out_dir / 'userinput_evasion.exe')
    create_antidebug_sample(out_dir / 'antidebug_evasion.exe')
    create_combined_sample (out_dir / 'combined_evasion.exe')

    print(f'\n생성 완료 → {out_dir}')
    print('\n[ 빠른 테스트 ]')
    print('  cd ..  &&  python patcher.py samples/combined_evasion.exe --dry-run')
    print('  python patcher.py samples/sleep_evasion.exe -c sleep --dry-run')


if __name__ == '__main__':
    main()
