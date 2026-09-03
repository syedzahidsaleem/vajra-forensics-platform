#!/usr/bin/env python3
"""
Synthetic Ground-Truth Corpus Generator for File Carving & Recovery (§26, §27, §45, §46).

Generates `test_data/carve_test.img` with:
- 5 Intact files (PNG, JPEG, PDF, SQLite, ZIP)
- 2 Truncated files (PNG, JPEG)
- 3 Corrupted false-positive candidates (PNG CRC corruption, JPEG bitstream corruption, SQLite page type corruption)
- 1 Genuinely 2-fragmented PNG file across an 8-sector gap (LBA 150 and LBA 159)
"""

import os
import struct
import zlib

SECTOR_SIZE = 512
TOTAL_SECTORS = 400

def create_valid_png():
    magic = b"\x89PNG\r\n\x1a\n"
    ihdr_data = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    ihdr_crc = zlib.crc32(b"IHDR" + ihdr_data)
    ihdr_chunk = struct.pack(">I", len(ihdr_data)) + b"IHDR" + ihdr_data + struct.pack(">I", ihdr_crc)

    iend_crc = zlib.crc32(b"IEND")
    iend_chunk = struct.pack(">I", 0) + b"IEND" + struct.pack(">I", iend_crc)

    return magic + ihdr_chunk + iend_chunk

def create_valid_jpeg():
    # SOI
    data = bytearray(b"\xFF\xD8")
    # SOF0
    sof0 = b"\x08\x00\x10\x00\x10\x01\x01\x11\x00"
    data += b"\xFF\xC0" + struct.pack(">H", len(sof0) + 2) + sof0
    # SOS
    sos = b"\x01\x01\x00\x00"
    data += b"\xFF\xDA" + struct.pack(">H", len(sos) + 2) + sos
    # Scan data with stuffed bytes
    data += b"\x12\x34\xFF\x00\x56\x78\x9A\xBC"
    # EOI
    data += b"\xFF\xD9"
    return bytes(data)

def create_valid_pdf():
    pdf = (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog >>\nendobj\n"
        b"xref\n0 2\n0000000000 65535 f \n0000000009 00000 n \n"
        b"trailer\n<< /Size 2 /Root 1 0 R >>\nstartxref\n49\n%%EOF\n"
    )
    return pdf

def create_valid_sqlite():
    page = bytearray(1024)
    page[0:16] = b"SQLite format 3\0"
    struct.pack_into(">H", page, 16, 1024) # page size
    struct.pack_into(">I", page, 28, 1)    # 1 page total
    page[100] = 0x0D                      # Leaf table b-tree
    struct.pack_into(">H", page, 103, 0)   # 0 cells
    struct.pack_into(">H", page, 105, 1024)# cell content offset
    return bytes(page)

def create_valid_zip():
    # Local file header
    filename = b"test.txt"
    content = b"Vajra ground-truth zip test file 2026.\n"
    crc = zlib.crc32(content)
    
    lfh = struct.pack(
        "<IHHHHHIIIHH",
        0x04034B50,
        20, 0, 0, 0, 0,
        crc, len(content), len(content),
        len(filename), 0
    ) + filename + content

    cd_offset = len(lfh)
    cd = struct.pack(
        "<IHHHHHHIIIHHHHHII",
        0x02014B50,
        20, 20, 0, 0, 0, 0,
        crc, len(content), len(content),
        len(filename), 0, 0, 0, 0, 0,
        0
    ) + filename

    eocd = struct.pack(
        "<IHHHHIIH",
        0x06054B50,
        0, 0, 1, 1,
        len(cd), cd_offset, 0
    )

    return lfh + cd + eocd

def generate_carve_corpus():
    out_dir = os.path.join(os.path.dirname(__file__), "..", "test_data")
    os.makedirs(out_dir, exist_ok=True)
    img_path = os.path.join(out_dir, "carve_test.img")

    img = bytearray(TOTAL_SECTORS * SECTOR_SIZE)

    # 1. Intact Files (Ground Truth Positives)
    # LBA 10: Intact PNG
    png_bytes = create_valid_png()
    img[10 * SECTOR_SIZE : 10 * SECTOR_SIZE + len(png_bytes)] = png_bytes

    # LBA 20: Intact JPEG
    jpg_bytes = create_valid_jpeg()
    img[20 * SECTOR_SIZE : 20 * SECTOR_SIZE + len(jpg_bytes)] = jpg_bytes

    # LBA 30: Intact PDF
    pdf_bytes = create_valid_pdf()
    img[30 * SECTOR_SIZE : 30 * SECTOR_SIZE + len(pdf_bytes)] = pdf_bytes

    # LBA 40: Intact SQLite (2 sectors)
    sqlite_bytes = create_valid_sqlite()
    img[40 * SECTOR_SIZE : 40 * SECTOR_SIZE + len(sqlite_bytes)] = sqlite_bytes

    # LBA 50: Intact ZIP
    zip_bytes = create_valid_zip()
    img[50 * SECTOR_SIZE : 50 * SECTOR_SIZE + len(zip_bytes)] = zip_bytes

    # 2. Truncated Files (Ground Truth Truncations)
    # LBA 70: Truncated PNG (missing IEND)
    trunc_png = png_bytes[:-12]
    img[70 * SECTOR_SIZE : 70 * SECTOR_SIZE + len(trunc_png)] = trunc_png

    # LBA 80: Truncated JPEG (missing EOI)
    trunc_jpg = jpg_bytes[:-2]
    img[80 * SECTOR_SIZE : 80 * SECTOR_SIZE + len(trunc_jpg)] = trunc_jpg

    # 3. Corrupted Files (Ground Truth False Positives / Negative Rejections)
    # LBA 100: Corrupted PNG (Valid magic, corrupted IHDR CRC)
    corrupt_png = bytearray(png_bytes)
    corrupt_png[16] ^= 0xFF # bitflip in payload without updating CRC
    img[100 * SECTOR_SIZE : 100 * SECTOR_SIZE + len(corrupt_png)] = corrupt_png

    # LBA 110: Corrupted JPEG (Valid SOI, invalid marker prefix)
    corrupt_jpg = bytearray(jpg_bytes)
    corrupt_jpg[2] = 0xAA # corrupted marker
    img[110 * SECTOR_SIZE : 110 * SECTOR_SIZE + len(corrupt_jpg)] = corrupt_jpg

    # LBA 120: Corrupted SQLite (Valid magic, invalid page type 0xFF)
    corrupt_sqlite = bytearray(sqlite_bytes)
    corrupt_sqlite[100] = 0xFF
    img[120 * SECTOR_SIZE : 120 * SECTOR_SIZE + len(corrupt_sqlite)] = corrupt_sqlite

    # 4. Genuinely 2-Fragmented File (Tier 3 BGC Target)
    # Fragment 1 at LBA 150: Exactly 512 bytes (Magic + IHDR + valid tEXt chunk)
    magic = b"\x89PNG\r\n\x1a\n"
    ihdr_data = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    ihdr_crc = zlib.crc32(b"IHDR" + ihdr_data)
    ihdr_chunk = struct.pack(">I", len(ihdr_data)) + b"IHDR" + ihdr_data + struct.pack(">I", ihdr_crc)

    # Add a tEXt chunk that pads Fragment 1 to exactly 512 bytes (512 - 33 = 479 bytes chunk -> 467 bytes text data)
    text_data = b"Comment\0Vajra forensic ground-truth fragmented PNG reconstruction test."
    text_data += b"A" * (467 - len(text_data))
    text_crc = zlib.crc32(b"tEXt" + text_data)
    text_chunk = struct.pack(">I", len(text_data)) + b"tEXt" + text_data + struct.pack(">I", text_crc)

    frag1 = magic + ihdr_chunk + text_chunk
    assert len(frag1) == 512, f"frag1 length is {len(frag1)}"
    img[150 * SECTOR_SIZE : 151 * SECTOR_SIZE] = frag1

    # Gap filler at LBAs 151..158 (8 sectors of unrelated noise data)
    for g in range(151, 159):
        img[g * SECTOR_SIZE : (g + 1) * SECTOR_SIZE] = b"UNRELATED GAP NOISE " * 25 + b"XX"

    # Fragment 2 at LBA 159 (IEND chunk)
    iend_crc = zlib.crc32(b"IEND")
    frag2 = struct.pack(">I", 0) + b"IEND" + struct.pack(">I", iend_crc)
    img[159 * SECTOR_SIZE : 159 * SECTOR_SIZE + len(frag2)] = frag2

    with open(img_path, "wb") as f:
        f.write(img)

    print(f"Generated Carving Ground-Truth Image: {img_path} ({len(img)} bytes, {TOTAL_SECTORS} sectors)")

# ---------------------------------------------------------------------------
# MP4 / ISO-BMFF fixture (§26.2, §28) — Vaibhavi, MP4 validator task.
#
# DELIBERATELY written to a SEPARATE image. It is not added to carve_test.img
# because tests/carve_tests.rs derives false positives as
# (artifacts.len() - true_positives) and asserts precision == 1.0, so any extra
# artifact in the shared corpus would break that ground-truth benchmark.
# carve_test.img and its expected results are therefore untouched.
# ---------------------------------------------------------------------------

MP4_TOTAL_SECTORS = 200


def _mp4_box(box_type: bytes, payload: bytes) -> bytes:
    return struct.pack(">I", 8 + len(payload)) + box_type + payload


def _mp4_ftyp(major: bytes, compatible=()) -> bytes:
    payload = major + struct.pack(">I", 512) + b"".join(compatible)
    return _mp4_box(b"ftyp", payload)


def build_valid_mp4(major: bytes = b"isom") -> bytes:
    """Minimal structurally complete ISO-BMFF object: ftyp + moov + mdat."""
    return (
        _mp4_ftyp(major, [b"isom", b"mp42"])
        + _mp4_box(b"moov", bytes(range(256)) * 2)
        + _mp4_box(b"mdat", bytes([(i * 7 + 3) % 256 for i in range(1024)]))
    )


def generate_mp4_fixture(img_path: str):
    """Generates test_data/mp4_test.img with known MP4 ground truth."""
    img = bytearray(MP4_TOTAL_SECTORS * SECTOR_SIZE)

    # LBA 10: intact MP4 (ftyp at byte 0, 'ftyp' magic at byte 4)
    intact = build_valid_mp4(b"isom")
    img[10 * SECTOR_SIZE : 10 * SECTOR_SIZE + len(intact)] = intact

    # LBA 40: intact QuickTime-brand MP4 ('qt  ')
    qt = build_valid_mp4(b"qt  ")
    img[40 * SECTOR_SIZE : 40 * SECTOR_SIZE + len(qt)] = qt

    # LBA 70: corrupted - first box declares size 4, below its own 8-byte header
    bad_size = bytearray(intact)
    bad_size[0:4] = struct.pack(">I", 4)
    img[70 * SECTOR_SIZE : 70 * SECTOR_SIZE + len(bad_size)] = bad_size

    # LBA 100: truncated - mdat declares 8 MiB but only a stub is present
    trunc = _mp4_ftyp(b"isom", [b"isom"]) + _mp4_box(b"moov", b"\xAA" * 64)
    trunc += struct.pack(">I", 8 * 1024 * 1024) + b"mdat" + b"\x5A" * 64
    img[100 * SECTOR_SIZE : 100 * SECTOR_SIZE + len(trunc)] = trunc

    # LBA 130: decoy - the ASCII bytes 'ftyp' at offset 0 instead of offset 4,
    # which the offset-aware signature matcher must NOT claim.
    decoy = b"ftypisom" + b"\x00" * 64
    img[130 * SECTOR_SIZE : 130 * SECTOR_SIZE + len(decoy)] = decoy

    with open(img_path, "wb") as f:
        f.write(bytes(img))

    print(
        f"Generated MP4 Ground-Truth Image: {img_path} "
        f"({len(img)} bytes, {MP4_TOTAL_SECTORS} sectors) "
        f"[intact@LBA10, qt-brand@LBA40, bad-size@LBA70, truncated@LBA100, decoy@LBA130]"
    )


if __name__ == "__main__":
    generate_carve_corpus()
    generate_mp4_fixture(os.path.join(os.path.dirname(__file__), "..", "test_data", "mp4_test.img"))
