"""
Dataset Generator for File-Type Classifier Training (§33).

Generates synthetic, labeled samples across 6 classes:
- JPEG (0)
- PNG (1)
- PDF (2)
- ZIP (3)
- SQLite (4)
- Raw Binary / Unknown (5)

Includes intact, truncated, corrupted, and header-stripped variations.
Also exports `training/parity_fixtures.json` for the mandatory train/serve feature-parity test.
"""

import json
import os
import random
import struct
import zlib
import numpy as np
from feature_extractor import extract_features

CLASSES = ["jpeg", "png", "pdf", "zip", "sqlite", "unknown"]
CLASS_TO_IDX = {c: i for i, c in enumerate(CLASSES)}


def make_jpeg(intact=True, strip_header=False, truncate=False, noise=False) -> bytes:
    # JPEG header: FFD8FFE0 0010 4A46494600 010100 00010001 0000
    jfif_header = bytes.fromhex("FFD8FFE000104A46494600010100000100010000")
    dqt = bytes.fromhex("FFDB004300") + bytes([random.randint(1, 16) for _ in range(64)])
    sof = bytes.fromhex("FFC00011080080008003012200021101031101")
    sos = bytes.fromhex("FFDA000C03010002110311003F00")
    # Entropy-coded compressed scan data
    scan_data = bytes([random.randint(0, 254) for _ in range(random.randint(500, 2000))])
    eoi = bytes.fromhex("FFD9")

    data = jfif_header + dqt + sof + sos + scan_data + eoi

    if strip_header:
        # Zero out or strip first 16 bytes
        data = b"\x00" * 16 + data[16:]
    if noise:
        b_list = list(data)
        for _ in range(len(b_list) // 20):
            b_list[random.randint(0, len(b_list) - 1)] = random.randint(0, 255)
        data = bytes(b_list)
    if truncate:
        data = data[: len(data) // 2]

    return data


def make_png(intact=True, strip_header=False, truncate=False, noise=False) -> bytes:
    png_sig = bytes.fromhex("89504E470D0A1A0A")
    # IHDR
    ihdr_data = struct.pack(">IIBBBBB", 100, 100, 8, 2, 0, 0, 0)
    ihdr_crc = zlib.crc32(b"IHDR" + ihdr_data)
    ihdr = struct.pack(">I", len(ihdr_data)) + b"IHDR" + ihdr_data + struct.pack(">I", ihdr_crc)
    # IDAT (deflated raw image data)
    raw_pixels = bytes([random.randint(0, 255) for _ in range(random.randint(1000, 3000))])
    compressed = zlib.compress(raw_pixels)
    idat_crc = zlib.crc32(b"IDAT" + compressed)
    idat = struct.pack(">I", len(compressed)) + b"IDAT" + compressed + struct.pack(">I", idat_crc)
    # IEND
    iend_crc = zlib.crc32(b"IEND")
    iend = struct.pack(">I", 0) + b"IEND" + struct.pack(">I", iend_crc)

    data = png_sig + ihdr + idat + iend

    if strip_header:
        data = b"\x00" * 8 + data[8:]
    if noise:
        b_list = list(data)
        for _ in range(len(b_list) // 25):
            b_list[random.randint(0, len(b_list) - 1)] = random.randint(0, 255)
        data = bytes(b_list)
    if truncate:
        data = data[: len(data) // 2]

    return data


def make_pdf(intact=True, strip_header=False, truncate=False, noise=False) -> bytes:
    stream_content = f"/Title (Forensic Report {random.randint(100, 999)})\n/Author (Analyst {random.randint(1, 20)})\n".encode("utf-8")
    stream_data = b"BT /F1 12 Tf 72 712 Td (Confidential Evidence Data) Tj ET\n"
    pdf = (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>\nendobj\n"
        b"4 0 obj\n<< /Length " + str(len(stream_data)).encode() + b" >>\nstream\n" +
        stream_data +
        b"\nendstream\nendobj\n"
        b"xref\n0 5\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n0000000115 00000 n \n0000000210 00000 n \n"
        b"trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n320\n%%EOF\n"
    )

    if strip_header:
        pdf = b"   " + pdf[8:]
    if noise:
        b_list = list(pdf)
        for _ in range(len(b_list) // 30):
            b_list[random.randint(0, len(b_list) - 1)] = random.randint(32, 126)
        pdf = bytes(b_list)
    if truncate:
        pdf = pdf[: len(pdf) // 2]

    return pdf


def make_zip(intact=True, strip_header=False, truncate=False, noise=False) -> bytes:
    # Local file header: 50 4B 03 04
    filename = f"evidence_{random.randint(1, 100)}.txt".encode("utf-8")
    uncompressed = f"Confidential logs and case evidence record #{random.randint(1000, 9999)}\n".encode("utf-8") * 20
    compressed = zlib.compress(uncompressed)[2:-4] # raw deflate

    lfh = struct.pack(
        "<IHHHHHIIIHH",
        0x04034B50,
        20, 0, 8, 0, 0,
        zlib.crc32(uncompressed),
        len(compressed),
        len(uncompressed),
        len(filename),
        0
    ) + filename + compressed

    # Central directory header: 50 4B 01 02
    cdh = struct.pack(
        "<IHHHHHHIIIHHHHHII",
        0x02014B50,
        20, 20, 0, 8, 0, 0,
        zlib.crc32(uncompressed),
        len(compressed),
        len(uncompressed),
        len(filename),
        0, 0, 0, 0, 0,
        0
    ) + filename

    # End of central directory record: 50 4B 05 06
    eocd = struct.pack(
        "<IHHHHIIH",
        0x06054B50,
        0, 0, 1, 1,
        len(cdh),
        len(lfh),
        0
    )

    data = lfh + cdh + eocd

    if strip_header:
        data = b"\x00\x00\x00\x00" + data[4:]
    if noise:
        b_list = list(data)
        for _ in range(len(b_list) // 25):
            b_list[random.randint(0, len(b_list) - 1)] = random.randint(0, 255)
        data = bytes(b_list)
    if truncate:
        data = data[: len(data) // 2]

    return data


def make_sqlite(intact=True, strip_header=False, truncate=False, noise=False) -> bytes:
    # 100-byte SQLite header
    header = bytearray(100)
    header[0:16] = b"SQLite format 3\x00"
    struct.pack_into(">H", header, 16, 4096) # page size
    header[18] = 1 # write version
    header[19] = 1 # read version
    header[20] = 0 # reserved space
    header[21] = 64 # max embedded payload fraction
    header[22] = 32 # min embedded payload fraction
    header[23] = 32 # leaf payload fraction
    struct.pack_into(">I", header, 24, 1) # file change counter
    struct.pack_into(">I", header, 28, 5) # page count
    struct.pack_into(">I", header, 56, 1) # text encoding = UTF-8

    # Page 1 b-tree content
    page1 = bytearray(4096)
    page1[0:100] = header
    page1[100] = 0x0D # leaf table b-tree page
    struct.pack_into(">H", page1, 103, 1) # 1 cell
    struct.pack_into(">H", page1, 105, 4000) # cell start offset

    # Fill cell content
    sql_schema = b"CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, hash TEXT);"
    page1[4000: 4000 + len(sql_schema)] = sql_schema

    data = bytes(page1)

    if strip_header:
        data = b"\x00" * 16 + data[16:]
    if noise:
        b_list = list(data)
        for _ in range(len(b_list) // 30):
            b_list[random.randint(100, len(b_list) - 1)] = random.randint(0, 255)
        data = bytes(b_list)
    if truncate:
        data = data[: 1024]

    return data


def make_unknown() -> bytes:
    pattern_type = random.randint(0, 3)
    length = random.randint(512, 4096)
    if pattern_type == 0:
        # Uniform zero bytes (blank unallocated sector)
        return b"\x00" * length
    elif pattern_type == 1:
        # High entropy random noise (encrypted block or crypto key)
        return bytes([random.randint(0, 255) for _ in range(length)])
    elif pattern_type == 2:
        # Plain text ASCII log / source code (unstructured)
        words = ["INFO", "DEBUG", "WARN", "timestamp=2026-08-31", "transaction_id=", "auth_token=", "session_start\n"]
        text = " ".join(random.choice(words) for _ in range(length // 8))
        return text.encode("utf-8")[:length]
    else:
        # Repetitive byte pattern
        pat = bytes([random.randint(0, 255) for _ in range(4)])
        return (pat * (length // 4 + 1))[:length]


def generate_dataset(samples_per_class: int = 300):
    random.seed(42)
    np.random.seed(42)

    X = []
    y = []
    metadata = []

    generators = {
        "jpeg": make_jpeg,
        "png": make_png,
        "pdf": make_pdf,
        "zip": make_zip,
        "sqlite": make_sqlite,
    }

    for class_name, gen_fn in generators.items():
        class_idx = CLASS_TO_IDX[class_name]
        for i in range(samples_per_class):
            mode = i % 4
            if mode == 0:
                raw = gen_fn(intact=True)
                var = "intact"
            elif mode == 1:
                raw = gen_fn(strip_header=True)
                var = "header_stripped"
            elif mode == 2:
                raw = gen_fn(truncate=True)
                var = "truncated"
            else:
                raw = gen_fn(noise=True)
                var = "corrupted"

            feats = extract_features(raw)
            X.append(feats)
            y.append(class_idx)
            metadata.append({"class": class_name, "variation": var, "bytes_len": len(raw)})

    # Unknown / raw binary class
    unknown_idx = CLASS_TO_IDX["unknown"]
    for i in range(samples_per_class):
        raw = make_unknown()
        feats = extract_features(raw)
        X.append(feats)
        y.append(unknown_idx)
        metadata.append({"class": "unknown", "variation": "synthetic_noise", "bytes_len": len(raw)})

    X = np.array(X, dtype=np.float32)
    y = np.array(y, dtype=np.int64)

    print(f"Generated {len(X)} samples across {len(CLASSES)} classes ({samples_per_class} per class).")
    return X, y, metadata


def export_parity_fixtures():
    """Exports 10 distinct byte payloads and their exact 280-dim feature vectors for Rust parity testing."""
    random.seed(1337)
    test_cases = [
        ("intact_jpeg", make_jpeg(intact=True)),
        ("stripped_jpeg", make_jpeg(strip_header=True)),
        ("intact_png", make_png(intact=True)),
        ("stripped_png", make_png(strip_header=True)),
        ("intact_pdf", make_pdf(intact=True)),
        ("stripped_pdf", make_pdf(strip_header=True)),
        ("intact_zip", make_zip(intact=True)),
        ("intact_sqlite", make_sqlite(intact=True)),
        ("zero_block", b"\x00" * 1024),
        ("random_noise", bytes([random.randint(0, 255) for _ in range(1024)])),
        ("plain_ascii", b"THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG\n" * 20),
    ]

    fixtures = []
    for name, data in test_cases:
        feats = extract_features(data)
        fixtures.append({
            "name": name,
            "hex_data": data.hex(),
            "expected_features": [float(x) for x in feats],
        })

    os.makedirs("training", exist_ok=True)
    with open("training/parity_fixtures.json", "w") as f:
        json.dump(fixtures, f, indent=2)
    print(f"Exported {len(fixtures)} feature-parity test fixtures to training/parity_fixtures.json")


if __name__ == "__main__":
    X, y, meta = generate_dataset(300)
    export_parity_fixtures()
