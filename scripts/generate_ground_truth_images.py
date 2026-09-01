#!/usr/bin/env python3
"""
Ground-truth synthetic filesystem image generator (§45).

Generates byte-accurate, reproducible filesystem images for testing:
1. fat32_test.img: FAT32 filesystem with active and deleted (0xE5 + LFN) files.
2. ext4_test.img: Linux ext4 filesystem with active and unlinked slack files.
3. ntfs_test.img: NTFS filesystem with resident and non-resident active and deleted MFT records.
4. ntfs_quickformat.img: NTFS volume containing surviving pre-format MFT records in unallocated clusters.
"""

import os
import struct
import subprocess
import sys

OUTPUT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "test_data"))
os.makedirs(OUTPUT_DIR, exist_ok=True)


def generate_fat32_image(path: str):
    """Generates a 10 MiB FAT32 test image."""
    sector_size = 512
    sectors_per_cluster = 8 # 4 KiB clusters
    reserved_sectors = 32
    num_fats = 2
    total_sectors = 20480 # 10 MiB
    fat_size_sectors = 32 # 16 KiB FAT

    image_size = total_sectors * sector_size
    img = bytearray(image_size)

    # 1. Boot Sector (LBA 0)
    img[0] = 0xEB
    img[1] = 0x58
    img[2] = 0x90
    img[3:11] = b"MSDOS5.0"
    struct.pack_into("<H", img, 11, sector_size)
    img[13] = sectors_per_cluster
    struct.pack_into("<H", img, 14, reserved_sectors)
    img[16] = num_fats
    struct.pack_into("<H", img, 17, 0) # Root entries (0 for FAT32)
    struct.pack_into("<H", img, 19, 0) # Total sectors 16 (0 for FAT32)
    img[21] = 0xF8 # Media descriptor
    struct.pack_into("<H", img, 22, 0) # FAT size 16 (0 for FAT32)
    struct.pack_into("<H", img, 24, 63) # Sectors per track
    struct.pack_into("<H", img, 26, 255) # Heads
    struct.pack_into("<I", img, 28, 0) # Hidden sectors
    struct.pack_into("<I", img, 32, total_sectors) # Total sectors 32
    struct.pack_into("<I", img, 36, fat_size_sectors) # FAT size 32
    struct.pack_into("<H", img, 40, 0) # Flags
    struct.pack_into("<H", img, 42, 0) # Version
    struct.pack_into("<I", img, 44, 2) # Root cluster = 2
    struct.pack_into("<H", img, 48, 1) # FSInfo sector = 1
    struct.pack_into("<H", img, 50, 6) # Backup boot sector = 6
    img[66] = 0x29 # Boot signature
    struct.pack_into("<I", img, 67, 0x12345678) # Volume ID
    img[71:82] = b"VAJRA_FAT32"
    img[82:90] = b"FAT32   "
    img[510] = 0x55
    img[511] = 0xAA

    # Backup boot sector at LBA 6
    img[6 * sector_size : 7 * sector_size] = img[0:sector_size]

    # 2. Initialize FAT Tables (Cluster 0, 1 reserved; Cluster 2 = root EOF)
    fat1_offset = reserved_sectors * sector_size
    fat2_offset = (reserved_sectors + fat_size_sectors) * sector_size

    def set_fat(clus, val):
        struct.pack_into("<I", img, fat1_offset + clus * 4, val)
        struct.pack_into("<I", img, fat2_offset + clus * 4, val)

    set_fat(0, 0x0FFF_FFF8)
    set_fat(1, 0x0FFF_FFFF)
    set_fat(2, 0x0FFF_FFFF) # Root directory EOF

    # Cluster 3: active file "active_document.txt"
    # Cluster 4: deleted file "confidential_plan.pdf"
    set_fat(3, 0x0FFF_FFFF)
    set_fat(4, 0x0000_0000) # Marked free in FAT because deleted!

    # Data region starts after FATs
    first_data_offset = (reserved_sectors + num_fats * fat_size_sectors) * sector_size
    cluster_size = sectors_per_cluster * sector_size

    def cluster_offset(clus):
        return first_data_offset + (clus - 2) * cluster_size

    # Root Directory (Cluster 2)
    root_off = cluster_offset(2)

    # Active Entry 1: "active_document.txt"
    active_content = b"ACTIVE FAT32 DATA: Ground-truth evidence payload for Vajra forensics.\n"
    img[cluster_offset(3) : cluster_offset(3) + len(active_content)] = active_content

    # LFN for active: "active_document.txt"
    # Chunk 1 (last, seq 0x42): "nt.txt\0"
    # Chunk 2 (seq 0x01): "active_docume"
    lfn2 = bytearray(32)
    lfn2[0] = 0x42
    lfn2[11] = 0x0F
    name2 = "nt.txt\0\0\0\0\0\0\0".encode("utf-16le")
    lfn2[1:11] = name2[0:10]
    lfn2[14:26] = name2[10:22]
    lfn2[28:32] = name2[22:26]

    lfn1 = bytearray(32)
    lfn1[0] = 0x01
    lfn1[11] = 0x0F
    name1 = "active_docume".encode("utf-16le")
    lfn1[1:11] = name1[0:10]
    lfn1[14:26] = name1[10:22]
    lfn1[28:32] = name1[22:26]

    act_83 = bytearray(32)
    act_83[0:8] = b"ACTIVE~1"
    act_83[8:11] = b"TXT"
    act_83[11] = 0x20
    # Date 2026-08-30 (46 << 9 | 8 << 5 | 30 = 23838)
    struct.pack_into("<H", act_83, 16, 23838)
    struct.pack_into("<H", act_83, 24, 23838)
    # Cluster 3
    struct.pack_into("<H", act_83, 20, 0)
    struct.pack_into("<H", act_83, 26, 3)
    struct.pack_into("<I", act_83, 28, len(active_content))

    # Deleted Entry 2: "confidential_plan.pdf" (0xE5 marked)
    deleted_content = b"TOP SECRET DELETED FORENSIC DATA: Vajra tier-1 recovery ground truth test.\n"
    img[cluster_offset(4) : cluster_offset(4) + len(deleted_content)] = deleted_content

    del_lfn2 = bytearray(32)
    del_lfn2[0] = 0xE5 # Deleted LFN
    del_lfn2[11] = 0x0F
    dname2 = "plan.pdf\0\0\0\0\0".encode("utf-16le")
    del_lfn2[1:11] = dname2[0:10]
    del_lfn2[14:26] = dname2[10:22]
    del_lfn2[28:32] = dname2[22:26]

    del_lfn1 = bytearray(32)
    del_lfn1[0] = 0xE5 # Deleted LFN
    del_lfn1[11] = 0x0F
    dname1 = "confidential_".encode("utf-16le")
    del_lfn1[1:11] = dname1[0:10]
    del_lfn1[14:26] = dname1[10:22]
    del_lfn1[28:32] = dname1[22:26]

    del_83 = bytearray(32)
    del_83[0] = 0xE5 # DELETED
    del_83[1:8] = b"ONFIDE~1"
    del_83[8:11] = b"PDF"
    del_83[11] = 0x20
    struct.pack_into("<H", del_83, 16, 23838)
    struct.pack_into("<H", del_83, 24, 23838)
    struct.pack_into("<H", del_83, 20, 0)
    struct.pack_into("<H", del_83, 26, 4) # Cluster 4
    struct.pack_into("<I", del_83, 28, len(deleted_content))

    # Write root entries
    img[root_off + 0 : root_off + 32] = lfn2
    img[root_off + 32 : root_off + 64] = lfn1
    img[root_off + 64 : root_off + 96] = act_83
    img[root_off + 96 : root_off + 128] = del_lfn2
    img[root_off + 128 : root_off + 160] = del_lfn1
    img[root_off + 160 : root_off + 192] = del_83

    with open(path, "wb") as f:
        f.write(img)
    print(f"Generated FAT32 ground-truth image: {path}")


def generate_ext4_image(path: str):
    """Generates an ext4 test image using mkfs.ext4 and debugfs."""
    tmp_live = "/tmp/vajra_live.txt"
    tmp_del = "/tmp/vajra_secret_del.txt"

    with open(tmp_live, "w") as f:
        f.write("ACTIVE EXT4 EVIDENCE: Unmodified active filesystem record 2026.\n")
    with open(tmp_del, "w") as f:
        f.write("DELETED EXT4 EVIDENCE: Recovered from directory slack and inode extents!\n")

    subprocess.run(["dd", "if=/dev/zero", f"of={path}", "bs=1M", "count=10"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["/usr/sbin/mkfs.ext4", "-F", path], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["/usr/sbin/debugfs", "-w", "-R", f"write {tmp_live} live_evidence.txt", path], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["/usr/sbin/debugfs", "-w", "-R", f"write {tmp_del} secret_deleted.txt", path], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["/usr/sbin/debugfs", "-w", "-R", "unlink secret_deleted.txt", path], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["/usr/sbin/debugfs", "-w", "-R", "freeb 1228", path], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["/usr/sbin/debugfs", "-w", "-R", "freei 14", path], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["/usr/sbin/debugfs", "-w", "-R", "sif <14> dtime 1725000000", path], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["/usr/sbin/debugfs", "-w", "-R", "sif <14> links_count 0", path], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(f"Generated ext4 ground-truth image: {path}")


def generate_ntfs_image(path: str):
    """Generates a 10 MiB NTFS ground-truth image."""
    sector_size = 512
    sectors_per_cluster = 8 # 4096B cluster
    total_sectors = 20480 # 10 MiB
    img = bytearray(total_sectors * sector_size)

    # 1. Boot Sector ($Boot at LBA 0)
    img[0:3] = b"\xEB\x52\x90"
    img[3:11] = b"NTFS    "
    struct.pack_into("<H", img, 11, sector_size)
    img[13] = sectors_per_cluster
    img[21] = 0xF8
    struct.pack_into("<Q", img, 40, total_sectors)
    struct.pack_into("<Q", img, 48, 4) # MFT Start LCN = 4
    struct.pack_into("<Q", img, 56, 2) # MFT Mirr Start LCN = 2
    img[64] = 0xF6 # 1024-byte MFT record (2^(256-246) = 1024)
    img[68] = 0xF6
    struct.pack_into("<Q", img, 72, 0x1122334455667788)
    img[510] = 0x55
    img[511] = 0xAA

    mft_start_offset = 4 * sectors_per_cluster * sector_size

    def create_mft_record(rec_num: int, is_in_use: bool, filename: str, content: bytes, is_resident: bool, cluster_lcn: int = 0, cluster_len: int = 1) -> bytes:
        rec = bytearray(1024)
        rec[0:4] = b"FILE"
        struct.pack_into("<H", rec, 4, 48) # Update sequence offset
        struct.pack_into("<H", rec, 6, 3) # Update sequence count
        struct.pack_into("<H", rec, 16, 1) # Sequence num
        struct.pack_into("<H", rec, 20, 56) # First attr offset
        flags = 0x01 if is_in_use else 0x00
        struct.pack_into("<H", rec, 22, flags)

        # Fixup signature
        struct.pack_into("<H", rec, 48, 0xAA55)
        # We will apply fixups before returning

        # Standard Information (0x10)
        attr1_off = 56
        struct.pack_into("<I", rec, attr1_off, 0x10)
        struct.pack_into("<I", rec, attr1_off + 4, 96) # Attr len
        rec[attr1_off + 8] = 0 # Resident
        struct.pack_into("<I", rec, attr1_off + 16, 48) # Value len
        struct.pack_into("<H", rec, attr1_off + 20, 24) # Value offset
        # Filetime (2026-08-30) = 133987824000000000
        struct.pack_into("<Q", rec, attr1_off + 24, 133987824000000000)
        struct.pack_into("<Q", rec, attr1_off + 32, 133987824000000000)
        struct.pack_into("<Q", rec, attr1_off + 40, 133987824000000000)
        struct.pack_into("<Q", rec, attr1_off + 48, 133987824000000000)

        # File Name (0x30)
        attr2_off = attr1_off + 96
        fn_utf16 = filename.encode("utf-16le")
        fn_val_len = 66 + len(fn_utf16)
        attr2_len = (16 + 8 + fn_val_len + 7) & ~7
        struct.pack_into("<I", rec, attr2_off, 0x30)
        struct.pack_into("<I", rec, attr2_off + 4, attr2_len)
        rec[attr2_off + 8] = 0 # Resident
        struct.pack_into("<I", rec, attr2_off + 16, fn_val_len)
        struct.pack_into("<H", rec, attr2_off + 20, 24) # Value offset
        struct.pack_into("<Q", rec, attr2_off + 24, 5) # Parent MFT ref (root)
        struct.pack_into("<Q", rec, attr2_off + 64, len(content)) # Allocated
        struct.pack_into("<Q", rec, attr2_off + 72, len(content)) # Real size
        rec[attr2_off + 24 + 64] = len(filename) # name len
        rec[attr2_off + 24 + 65] = 1 # Win32 namespace
        rec[attr2_off + 24 + 66 : attr2_off + 24 + 66 + len(fn_utf16)] = fn_utf16

        # Data (0x80)
        attr3_off = attr2_off + attr2_len
        if is_resident:
            attr3_len = (24 + len(content) + 7) & ~7
            struct.pack_into("<I", rec, attr3_off, 0x80)
            struct.pack_into("<I", rec, attr3_off + 4, attr3_len)
            rec[attr3_off + 8] = 0 # Resident
            struct.pack_into("<I", rec, attr3_off + 16, len(content))
            struct.pack_into("<H", rec, attr3_off + 20, 24)
            rec[attr3_off + 24 : attr3_off + 24 + len(content)] = content
            end_off = attr3_off + attr3_len
        else:
            # Non-resident data run
            # Runlist for cluster_len clusters at cluster_lcn: header 0x21, len 1, offset 2 bytes
            runlist = bytearray([0x21, cluster_len, cluster_lcn & 0xFF, (cluster_lcn >> 8) & 0xFF, 0x00])
            attr3_len = (64 + len(runlist) + 7) & ~7
            struct.pack_into("<I", rec, attr3_off, 0x80)
            struct.pack_into("<I", rec, attr3_off + 4, attr3_len)
            rec[attr3_off + 8] = 1 # Non-resident
            struct.pack_into("<H", rec, attr3_off + 32, 64) # Runlist offset
            struct.pack_into("<Q", rec, attr3_off + 40, 4096 * cluster_len) # Allocated
            real_size = len(content) if len(content) > 0 else 4096 * cluster_len
            struct.pack_into("<Q", rec, attr3_off + 48, real_size) # Real size
            rec[attr3_off + 64 : attr3_off + 64 + len(runlist)] = runlist
            end_off = attr3_off + attr3_len

        # End of attributes
        struct.pack_into("<I", rec, end_off, 0xFFFF_FFFF)

        # Apply fixups to sector ends
        sig = 0xAA55
        struct.pack_into("<H", rec, 50, struct.unpack_from("<H", rec, 510)[0])
        struct.pack_into("<H", rec, 52, struct.unpack_from("<H", rec, 1022)[0])
        struct.pack_into("<H", rec, 510, sig)
        struct.pack_into("<H", rec, 1022, sig)

        return bytes(rec)

    # Write MFT Record 0 ($MFT) with data runs pointing to 8 clusters (clusters 4..12)
    mft0 = create_mft_record(0, True, "$MFT", b"", False, 4, 8)
    img[mft_start_offset : mft_start_offset + 1024] = mft0

    # Write MFT Record 6 ($Bitmap) with non-resident data run at cluster 14
    bitmap_bytes = bytearray(4096)
    bitmap_bytes[0] = 0xFF # clusters 0..7 (Boot, MFT 0..3 allocated)
    bitmap_bytes[1] = 0xFF # clusters 8..15 (MFT 4..7 + Bitmap at clus 14 allocated)
    # Cluster 100 (byte 12, bit 4) is 0 = FREE
    rec6 = create_mft_record(6, True, "$Bitmap", b"", False, 14, 1)
    img[mft_start_offset + 6 * 1024 : mft_start_offset + 7 * 1024] = rec6

    # Place $Bitmap content at cluster 14
    clus14_off = 14 * sectors_per_cluster * sector_size
    img[clus14_off : clus14_off + len(bitmap_bytes)] = bitmap_bytes

    # Write MFT Record 30: Active file "system_audit.log" (Resident)
    live_content = b"ACTIVE NTFS AUDIT LOG: System integrity verified 2026.\n"
    rec30 = create_mft_record(30, True, "system_audit.log", live_content, True)
    img[mft_start_offset + 30 * 1024 : mft_start_offset + 31 * 1024] = rec30

    # Write MFT Record 31: Deleted file "financial_records_2026.xlsx" (Non-resident at cluster 100)
    del_content = b"CONFIDENTIAL FINANCIAL FORENSIC EVIDENCE: Complete quarterly ledger.\n"
    rec31 = create_mft_record(31, False, "financial_records_2026.xlsx", del_content, False, 100)
    img[mft_start_offset + 31 * 1024 : mft_start_offset + 32 * 1024] = rec31

    # Place non-resident data at cluster 100
    clus100_off = 100 * sectors_per_cluster * sector_size
    img[clus100_off : clus100_off + len(del_content)] = del_content

    with open(path, "wb") as f:
        f.write(img)
    print(f"Generated NTFS ground-truth image: {path}")


def generate_ntfs_quickformat_image(path: str):
    """Generates an NTFS Quick-Format scenario image (§25, §45)."""
    sector_size = 512
    sectors_per_cluster = 8
    total_sectors = 20480
    img = bytearray(total_sectors * sector_size)

    # 1. New NTFS Boot Sector at LBA 0 (MFT starts at cluster 4)
    img[0:3] = b"\xEB\x52\x90"
    img[3:11] = b"NTFS    "
    struct.pack_into("<H", img, 11, sector_size)
    img[13] = sectors_per_cluster
    img[21] = 0xF8
    struct.pack_into("<Q", img, 40, total_sectors)
    struct.pack_into("<Q", img, 48, 4) # New MFT at cluster 4
    struct.pack_into("<Q", img, 56, 2)
    img[64] = 0xF6 # 1024B MFT
    img[68] = 0xF6
    img[510] = 0x55
    img[511] = 0xAA

    # Write new MFT record 0 with 1-cluster length (records 0..3)
    mft_start_offset = 4 * sectors_per_cluster * sector_size
    def create_simple_mft0():
        rec = bytearray(1024)
        rec[0:4] = b"FILE"
        struct.pack_into("<H", rec, 4, 48)
        struct.pack_into("<H", rec, 6, 3)
        struct.pack_into("<H", rec, 16, 1)
        struct.pack_into("<H", rec, 20, 56)
        struct.pack_into("<H", rec, 22, 0x01)
        # Data run (1 cluster at cluster 4)
        runlist = bytearray([0x21, 1, 4, 0, 0x00])
        attr3_off = 56
        struct.pack_into("<I", rec, attr3_off, 0x80)
        struct.pack_into("<I", rec, attr3_off + 4, 72)
        rec[attr3_off + 8] = 1 # Non-resident
        struct.pack_into("<H", rec, attr3_off + 32, 64)
        struct.pack_into("<Q", rec, attr3_off + 40, 4096)
        struct.pack_into("<Q", rec, attr3_off + 48, 4096)
        rec[attr3_off + 64 : attr3_off + 64 + len(runlist)] = runlist
        struct.pack_into("<I", rec, attr3_off + 72, 0xFFFF_FFFF)
        struct.pack_into("<H", rec, 48, 0xAA55)
        struct.pack_into("<H", rec, 50, struct.unpack_from("<H", rec, 510)[0])
        struct.pack_into("<H", rec, 52, struct.unpack_from("<H", rec, 1022)[0])
        struct.pack_into("<H", rec, 510, 0xAA55)
        struct.pack_into("<H", rec, 1022, 0xAA55)
        return bytes(rec)

    img[mft_start_offset : mft_start_offset + 1024] = create_simple_mft0()

    # 2. Plant a surviving pre-format MFT record cluster at Cluster 500 (unallocated in new format!)
    # Pre-format file: "pre_format_evidence.docx" (Resident)
    evidence_content = b"RECOVERED PRE-FORMAT EVIDENCE: Surviving MFT record across volume quick-format!\n"

    # Create MFT record for pre_format_evidence.docx
    rec = bytearray(1024)
    rec[0:4] = b"FILE"
    struct.pack_into("<H", rec, 4, 48)
    struct.pack_into("<H", rec, 6, 3)
    struct.pack_into("<H", rec, 16, 1)
    struct.pack_into("<H", rec, 20, 56)
    struct.pack_into("<H", rec, 22, 0x01) # Was in-use before format

    # Standard Info
    struct.pack_into("<I", rec, 56, 0x10)
    struct.pack_into("<I", rec, 60, 96)
    rec[64] = 0
    struct.pack_into("<I", rec, 72, 48)
    struct.pack_into("<H", rec, 76, 24)
    struct.pack_into("<Q", rec, 80, 133987824000000000)

    # File Name
    fn = "pre_format_evidence.docx".encode("utf-16le")
    fn_val_len = 66 + len(fn)
    attr2_len = (16 + 8 + fn_val_len + 7) & ~7
    attr2_off = 56 + 96
    struct.pack_into("<I", rec, attr2_off, 0x30)
    struct.pack_into("<I", rec, attr2_off + 4, attr2_len)
    rec[attr2_off + 8] = 0
    struct.pack_into("<I", rec, attr2_off + 16, fn_val_len)
    struct.pack_into("<H", rec, attr2_off + 20, 24)
    rec[attr2_off + 24 + 64] = len("pre_format_evidence.docx")
    rec[attr2_off + 24 + 65] = 1
    rec[attr2_off + 24 + 66 : attr2_off + 24 + 66 + len(fn)] = fn

    # Data
    attr3_off = attr2_off + attr2_len
    attr3_len = (24 + len(evidence_content) + 7) & ~7
    struct.pack_into("<I", rec, attr3_off, 0x80)
    struct.pack_into("<I", rec, attr3_off + 4, attr3_len)
    rec[attr3_off + 8] = 0
    struct.pack_into("<I", rec, attr3_off + 16, len(evidence_content))
    struct.pack_into("<H", rec, attr3_off + 20, 24)
    rec[attr3_off + 24 : attr3_off + 24 + len(evidence_content)] = evidence_content
    struct.pack_into("<I", rec, attr3_off + attr3_len, 0xFFFF_FFFF)

    # Fixup
    struct.pack_into("<H", rec, 48, 0xAA55)
    struct.pack_into("<H", rec, 50, struct.unpack_from("<H", rec, 510)[0])
    struct.pack_into("<H", rec, 52, struct.unpack_from("<H", rec, 1022)[0])
    struct.pack_into("<H", rec, 510, 0xAA55)
    struct.pack_into("<H", rec, 1022, 0xAA55)

    clus500_off = 500 * sectors_per_cluster * sector_size
    img[clus500_off : clus500_off + 1024] = rec

    with open(path, "wb") as f:
        f.write(img)
    print(f"Generated NTFS Quick-Format ground-truth image: {path}")


if __name__ == "__main__":
    generate_fat32_image(os.path.join(OUTPUT_DIR, "fat32_test.img"))
    generate_ext4_image(os.path.join(OUTPUT_DIR, "ext4_test.img"))
    generate_ntfs_image(os.path.join(OUTPUT_DIR, "ntfs_test.img"))
    generate_ntfs_quickformat_image(os.path.join(OUTPUT_DIR, "ntfs_quickformat.img"))
