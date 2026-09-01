//! Integration tests for vajra-image format layer (§19).

use tempfile::tempdir;
use vajra_core::{MediaType, ReadOnlyBlockSource};
use vajra_image::{
    aff4::open_aff4_not_implemented,
    error::ImageError,
    metadata::ImageFormat,
    traits::ForensicImageWriter,
    RawImageReader, RawImageWriter,
};

#[test]
fn test_raw_image_write_and_read_roundtrip() {
    let tmp = tempdir().unwrap();
    let img_path = tmp.path().join("test_disk.raw");

    let block_size = 512u32;
    let num_blocks = 16u64;
    let total_bytes = num_blocks * block_size as u64;

    // 1. Create and write synthetic pattern to RAW image
    let mut writer = RawImageWriter::create(&img_path, block_size).expect("Failed to create RAW writer");

    let mut synthetic_data = Vec::with_capacity(total_bytes as usize);
    for lba in 0..num_blocks {
        let mut block = vec![0u8; block_size as usize];
        for (i, b) in block.iter_mut().enumerate() {
            *b = ((lba as usize * 17 + i) % 256) as u8;
        }
        writer.write_image_blocks(lba, &block).expect("Write block failed");
        synthetic_data.extend_from_slice(&block);
    }

    assert_eq!(writer.bytes_written(), total_bytes);
    let meta = writer.finalize().expect("Failed to finalize writer");
    assert_eq!(meta.format, ImageFormat::Raw);
    assert_eq!(meta.capacity_bytes, total_bytes);
    assert_eq!(meta.total_blocks, num_blocks);
    assert_eq!(meta.block_size, block_size);

    // 2. Open with RawImageReader and verify metadata
    let mut reader = RawImageReader::open(&img_path, Some(block_size)).expect("Failed to open RAW reader");
    assert_eq!(reader.total_blocks(), num_blocks);
    assert_eq!(reader.block_size(), block_size);
    assert_eq!(reader.media_type(), MediaType::ForensicImage);
    assert!(reader.is_write_blocked());

    // 3. Verify ReadOnlyBlockSource read_blocks byte-for-byte fidelity
    let read_back = reader.read_blocks(0, num_blocks as u32).expect("Read all blocks failed");
    assert_eq!(read_back, synthetic_data);

    // 4. Read single block at offset
    let lba_5_data = reader.read_blocks(5, 1).expect("Read block 5 failed");
    let expected_5 = &synthetic_data[5 * 512..6 * 512];
    assert_eq!(lba_5_data, expected_5);

    // 5. Test out of bounds read
    let oob_err = reader.read_blocks(num_blocks + 10, 1);
    assert!(oob_err.is_err(), "Out of bounds read must return error");
}

#[test]
fn test_raw_image_fingerprint_determinism() {
    let tmp = tempdir().unwrap();
    let img_path = tmp.path().join("fingerprint_test.raw");

    let mut writer = RawImageWriter::create(&img_path, 512).unwrap();
    let test_block = vec![0xAB; 512];
    writer.write_image_blocks(0, &test_block).unwrap();
    writer.finalize().unwrap();

    let reader1 = RawImageReader::open(&img_path, Some(512)).unwrap();
    let fp1 = reader1.device_fingerprint();

    let reader2 = RawImageReader::open(&img_path, Some(512)).unwrap();
    let fp2 = reader2.device_fingerprint();

    assert_eq!(fp1.sha256_hash, fp2.sha256_hash);
    assert_eq!(fp1.capacity_bytes, 512);
    assert!(fp1.serial.starts_with("RAW-"));
}

#[test]
fn test_raw_image_resume_writer() {
    let tmp = tempdir().unwrap();
    let img_path = tmp.path().join("resumed.raw");

    // Write first 4 blocks
    {
        let mut writer = RawImageWriter::create(&img_path, 512).unwrap();
        writer.write_image_blocks(0, &vec![0x11; 512 * 4]).unwrap();
        writer.finalize().unwrap();
    }

    // Open for resume and write next 4 blocks at LBA 4
    {
        let mut resume_writer = RawImageWriter::open_for_resume(&img_path, 512).unwrap();
        assert_eq!(resume_writer.bytes_written(), 512 * 4);
        resume_writer.write_image_blocks(4, &vec![0x22; 512 * 4]).unwrap();
        resume_writer.finalize().unwrap();
    }

    let mut reader = RawImageReader::open(&img_path, Some(512)).unwrap();
    assert_eq!(reader.total_blocks(), 8);

    let first_half = reader.read_blocks(0, 4).unwrap();
    assert_eq!(first_half, vec![0x11; 512 * 4]);

    let second_half = reader.read_blocks(4, 4).unwrap();
    assert_eq!(second_half, vec![0x22; 512 * 4]);
}

#[test]
fn test_aff4_stub_unsupported_error() {
    let err = open_aff4_not_implemented().unwrap_err();
    match err {
        ImageError::UnsupportedFormat(msg) => {
            assert!(msg.contains("AFF4"));
        }
        other => panic!("Expected UnsupportedFormat, got {:?}", other),
    }
}
