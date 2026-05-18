"""extract_section.py -- extract PIC blob from a PE's .text section.

Output format:
    [4 bytes LE: offset to entry point within blob]
    [full .text section raw bytes]

The trampoline reads the first 4 bytes to find where sleep_mask_entry
starts, then jumps to (blob + offset). This preserves .rdata strings
that are merged into .text before the code (MSVC /MERGE:.rdata=.text).

Usage: python extract_section.py <pe_file> <section_name> <output_file>
"""

import sys
import struct


def extract(pe_path: str, section_name: str, out_path: str) -> None:
    with open(pe_path, "rb") as f:
        data = f.read()

    # Поддерживаем два формата: PE-исполняемые файлы и COFF .obj
    # объектные файлы. Это разные форматы, но и тот, и тот
    # содержит таблицу секций с одинаковой структурой 40 байт.
    if data[:2] == b"MZ":
        # PE-файл: MZ-заголовок -> e_lfanew -> "PE\0\0" -> COFF-заголовок
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            raise ValueError("Invalid PE signature")
        coff_off = e_lfanew + 4
        is_pe = True
    else:
        # COFF-объектник: первый байт - Machine (нижний байт LE)
        # 0x8664 (x64), 0x014C (x86). У PE здесь "MZ" = 0x5A4D.
        machine = struct.unpack_from("<H", data, 0)[0]
        if machine not in (0x8664, 0x014C, 0x01C0, 0xAA64):
            raise ValueError(
                f"Unknown file format: first bytes={data[:4].hex()}, "
                f"machine=0x{machine:04X}"
            )
        coff_off = 0
        is_pe = False

    num_sections = struct.unpack_from("<H", data, coff_off + 2)[0]
    opt_hdr_size = struct.unpack_from("<H", data, coff_off + 16)[0]

    # Entry point RVA - есть только в PE (offset 16 в Optional Header).
    # В COFF .obj точки входа нет, считаем 0 от начала .text.
    if is_pe and opt_hdr_size > 0:
        opt_off = coff_off + 20
        entry_rva = struct.unpack_from("<I", data, opt_off + 16)[0]
    else:
        entry_rva = 0

    sec_table_off = coff_off + 20 + opt_hdr_size
    target = section_name.encode("ascii").ljust(8, b"\x00")[:8]
    # В COFF .obj секции бывают разбиты на ".text$mn" - тоже считаем "своими"
    target_grouped = (section_name + "$mn").encode("ascii").ljust(8, b"\x00")[:8]

    for i in range(num_sections):
        sec_off = sec_table_off + i * 40
        name = data[sec_off:sec_off + 8]
        virt_size = struct.unpack_from("<I", data, sec_off + 8)[0]
        virt_addr = struct.unpack_from("<I", data, sec_off + 12)[0]
        raw_size = struct.unpack_from("<I", data, sec_off + 16)[0]
        raw_ptr = struct.unpack_from("<I", data, sec_off + 20)[0]

        if name == target or name == target_grouped:
            size = min(virt_size, raw_size) if virt_size else raw_size
            section_bytes = data[raw_ptr:raw_ptr + size]

            # Calculate entry point offset within the section.
            # Add 4 to account for the header we prepend.
            ep_offset_in_section = 0
            if virt_addr <= entry_rva < virt_addr + size:
                ep_offset_in_section = entry_rva - virt_addr

            # Blob = [4-byte LE offset to EP from blob start] + [section data]
            # EP from blob start = 4 (header size) + ep_offset_in_section
            ep_from_blob_start = 4 + ep_offset_in_section
            header = struct.pack("<I", ep_from_blob_start)

            with open(out_path, "wb") as out:
                out.write(header)
                out.write(section_bytes)

            total = 4 + size
            print(f"[+] Extracted {section_name}: {total} bytes "
                  f"(EP at +0x{ep_from_blob_start:X}) -> {out_path}")
            return

    raise ValueError(f"Section '{section_name}' not found in {pe_path}")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <pe_file> <section_name> <output_file>")
        sys.exit(1)
    extract(sys.argv[1], sys.argv[2], sys.argv[3])
