"""
PE 파일 래퍼 — 로드, 섹션 순회, 바이트 패치, 저장
"""
import pefile


class PEFile:
    def __init__(self, path: str) -> None:
        self.path = path
        self.pe = pefile.PE(path, fast_load=False)
        # 수정 가능한 raw 바이트 버퍼
        self.data = bytearray(self.pe.__data__)
        # PE32+(x64) = 0x20B, PE32(x86) = 0x10B
        self.is_64bit: bool = (self.pe.OPTIONAL_HEADER.Magic == 0x20B)
        self.image_base: int = self.pe.OPTIONAL_HEADER.ImageBase

    # ── VA 변환 ───────────────────────────────────────────────────
    def rva_to_offset(self, rva: int) -> int | None:
        """섹션 RVA → 파일 오프셋"""
        for sec in self.pe.sections:
            va   = sec.VirtualAddress
            size = max(sec.Misc_VirtualSize, sec.SizeOfRawData)
            if va <= rva < va + size:
                return sec.PointerToRawData + (rva - va)
        return None

    def offset_to_rva(self, offset: int) -> int | None:
        """파일 오프셋 → 섹션 RVA"""
        for sec in self.pe.sections:
            raw  = sec.PointerToRawData
            size = sec.SizeOfRawData
            if size and raw <= offset < raw + size:
                return sec.VirtualAddress + (offset - raw)
        return None

    def va_to_offset(self, va: int) -> int | None:
        """절대 VA → 파일 오프셋"""
        return self.rva_to_offset(va - self.image_base)

    def offset_to_va(self, offset: int) -> int | None:
        """파일 오프셋 → 절대 VA"""
        rva = self.offset_to_rva(offset)
        return (self.image_base + rva) if rva is not None else None

    # ── 섹션 순회 ─────────────────────────────────────────────────
    def get_code_sections(self) -> list[tuple[int, int, int, bytes]]:
        """
        실행 속성(MEM_EXECUTE)을 가진 섹션 목록 반환.
        returns: [(file_offset, rva, va, data), ...]
        """
        IMAGE_SCN_MEM_EXECUTE = 0x20000000
        result = []
        for sec in self.pe.sections:
            if sec.Characteristics & IMAGE_SCN_MEM_EXECUTE:
                off  = sec.PointerToRawData
                size = sec.SizeOfRawData
                result.append((
                    off,
                    sec.VirtualAddress,
                    self.image_base + sec.VirtualAddress,
                    bytes(self.data[off : off + size]),
                ))
        return result

    def get_all_sections(self) -> list[tuple[int, int, int, bytes]]:
        """모든 섹션 반환 (data 포함)"""
        result = []
        for sec in self.pe.sections:
            off  = sec.PointerToRawData
            size = sec.SizeOfRawData
            result.append((
                off,
                sec.VirtualAddress,
                self.image_base + sec.VirtualAddress,
                bytes(self.data[off : off + size]),
            ))
        return result

    # ── 임포트 테이블 ──────────────────────────────────────────────
    def get_imports(self) -> dict[str, dict[str, int]]:
        """
        {dll_name_lower: {func_name: iat_abs_va}}
        iat_abs_va = IAT 슬롯의 절대 VA (pefile imp.address)
        """
        result: dict[str, dict[str, int]] = {}
        if not hasattr(self.pe, "DIRECTORY_ENTRY_IMPORT"):
            return result
        for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode(errors="replace").lower()
            result[dll] = {}
            for imp in entry.imports:
                if imp.name:
                    name = imp.name.decode(errors="replace")
                    result[dll][name] = imp.address  # 절대 VA
        return result

    # ── 패치 / 저장 ───────────────────────────────────────────────
    def read_bytes(self, file_offset: int, size: int) -> bytes:
        return bytes(self.data[file_offset : file_offset + size])

    def get_checksum_offset(self) -> int:
        """PE OptionalHeader.CheckSum 필드 파일 오프셋."""
        import struct as _s
        e_lfanew = _s.unpack_from('<I', bytes(self.data), 0x3C)[0]
        return e_lfanew + 4 + 20 + 64  # PE sig(4) + COFF(20) + OptHdr→CheckSum(64)

    def compute_checksum(self) -> int:
        """현재 self.data 기준 PE 체크섬 계산 (CheckSum 필드는 0으로 제외)."""
        import struct as _s
        chksum_off = self.get_checksum_offset()
        buf = bytearray(self.data)
        buf[chksum_off:chksum_off + 4] = b'\x00\x00\x00\x00'
        if len(buf) % 2:
            buf.append(0)
        checksum = 0
        for i in range(0, len(buf), 2):
            word = buf[i] | (buf[i + 1] << 8)
            checksum += word
            checksum = (checksum & 0xFFFF) + (checksum >> 16)
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
        return (checksum & 0xFFFF) + len(self.data)

    def update_checksum(self) -> None:
        """패치된 self.data 기준으로 PE 체크섬 재계산 후 헤더에 기록."""
        import struct as _s
        chksum_off = self.get_checksum_offset()
        _s.pack_into('<I', self.data, chksum_off, self.compute_checksum())

    def patch_bytes(self, file_offset: int, new_bytes: bytes) -> None:
        end = file_offset + len(new_bytes)
        self.data[file_offset:end] = new_bytes

    def save(self, output_path: str) -> None:
        with open(output_path, "wb") as f:
            f.write(self.data)
        print(f"[+] 저장 완료: {output_path}")
