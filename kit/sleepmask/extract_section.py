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

    if data[:2] != b"MZ":
        raise ValueError("Not a PE file")

    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]

    if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        raise ValueError("Invalid PE signature")

    coff_off = e_lfanew + 4
    num_sections = struct.unpack_from("<H", data, coff_off + 2)[0]
    opt_hdr_size = struct.unpack_from("<H", data, coff_off + 16)[0]

    # Entry point RVA (offset 16 in optional header for both PE32/PE32+).
    opt_off = coff_off + 20
    entry_rva = struct.unpack_from("<I", data, opt_off + 16)[0]

    sec_table_off = coff_off + 20 + opt_hdr_size
    target = section_name.encode("ascii").ljust(8, b"\x00")[:8]

    for i in range(num_sections):
        sec_off = sec_table_off + i * 40
        name = data[sec_off:sec_off + 8]
        virt_size = struct.unpack_from("<I", data, sec_off + 8)[0]
        virt_addr = struct.unpack_from("<I", data, sec_off + 12)[0]
        raw_size = struct.unpack_from("<I", data, sec_off + 16)[0]
        raw_ptr = struct.unpack_from("<I", data, sec_off + 20)[0]

        if name == target:
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
