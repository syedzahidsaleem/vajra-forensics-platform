//! Windows native block device enumeration, SMART diagnostics, and raw sector I/O (§23–§24).
//!
//! Uses Win32 Storage IOCTLs against `\\.\PhysicalDriveN` handles.
//! Raw sector access requires elevated Administrator privileges (§18).

use crate::descriptor::DeviceDescriptor;
use crate::detection::{check_write_blocker, detect_partition_table};
use crate::health::{DeviceHealth, HddHealthInfo, NvmeHealthInfo, SmartAttribute};
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use vajra_core::{IoError, MediaType};
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_ACCESS_DENIED, ERROR_WRITE_PROTECT, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, SetFilePointerEx, WriteFile, FILE_BEGIN, FILE_FLAG_NO_BUFFERING,
    FILE_FLAG_WRITE_THROUGH, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::System::IO::DeviceIoControl;

// IOCTL control codes per Win32 headers
const IOCTL_STORAGE_QUERY_PROPERTY: u32 = 0x002D1400;
const IOCTL_DISK_GET_DRIVE_GEOMETRY_EX: u32 = 0x000700A0;
const IOCTL_DISK_GET_LENGTH_INFO: u32 = 0x0007405C;
const IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS: u32 = 0x00560000;
const IOCTL_STORAGE_PREDICT_FAILURE: u32 = 0x002D1100;
const IOCTL_DISK_IS_WRITABLE: u32 = 0x00070024;

// Storage property query constants
const STORAGE_PROPERTY_DEVICE: u32 = 0; // StorageDeviceProperty
const PROPERTY_STANDARD_QUERY: u32 = 0; // PropertyStandardQuery
const STORAGE_PROPERTY_SEEK_PENALTY: u32 = 7; // StorageDeviceSeekPenaltyProperty
const STORAGE_PROPERTY_ADAPTER_PROTOCOL: u32 = 49; // StorageAdapterProtocolSpecificProperty
const PROTOCOL_TYPE_NVME: u32 = 1; // ProtocolTypeNvme
const NVME_DATA_TYPE_LOG_PAGE: u32 = 1; // NVMeDataTypeLogPage
const NVME_LOG_PAGE_SMART: u32 = 0x02; // SMART / Health Information Log

#[repr(C, align(8))]
struct AlignedBuf1024([u8; 1024]);

#[repr(C, align(8))]
struct AlignedBuf256([u8; 256]);

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct StoragePropertyQuery {
    property_id: u32,
    query_type: u32,
    additional_parameters: [u8; 4],
}

#[repr(C, align(8))]
#[derive(Clone, Copy, Default)]
struct DeviceSeekPenaltyDescriptor {
    version: u32,
    size: u32,
    incurs_seek_penalty: u8,
    _pad: [u8; 3],
}

#[repr(C, align(8))]
#[derive(Clone, Copy, Default)]
struct StorageProtocolSpecificData {
    protocol_type: u32,
    data_type: u32,
    protocol_data_request_value: u32,
    protocol_data_request_sub_value: u32,
    protocol_data_offset: u32,
    protocol_data_length: u32,
    fixed_protocol_return_data: u32,
    protocol_data_request_sub_value2: u32,
    protocol_data_request_sub_value3: u32,
    protocol_data_request_sub_value4: u32,
}

#[repr(C, align(8))]
#[derive(Clone, Copy, Default)]
struct StorageDeviceDescriptor {
    version: u32,
    size: u32,
    device_type: u8,
    device_type_modifier: u8,
    removable_media: u8,
    command_queueing: u8,
    vendor_id_offset: u32,
    product_id_offset: u32,
    product_revision_offset: u32,
    serial_number_offset: u32,
    bus_type: u32,
    raw_properties_length: u32,
}

#[repr(C, align(8))]
#[derive(Clone, Copy, Default)]
struct DiskGeometry {
    cylinders: i64,
    media_type: u32,
    tracks_per_cylinder: u32,
    sectors_per_track: u32,
    bytes_per_sector: u32,
}

#[repr(C, align(8))]
#[derive(Clone, Copy, Default)]
struct DiskGeometryEx {
    geometry: DiskGeometry,
    disk_size: i64,
    data: [u8; 1],
}

#[repr(C, align(8))]
#[derive(Clone, Copy, Default)]
struct GetLengthInformation {
    length: i64,
}

#[repr(C, align(8))]
#[derive(Clone, Copy, Default)]
struct DiskExtent {
    disk_number: u32,
    _pad: u32,
    starting_offset: i64,
    extent_length: i64,
}

#[repr(C, align(8))]
#[derive(Clone, Copy, Default)]
struct VolumeDiskExtents {
    number_of_disk_extents: u32,
    _pad: u32,
    extents: [DiskExtent; 1],
}

#[repr(C, align(8))]
struct PredictFailurePredictor {
    predictor_failure: u32,
    vendor_specific: [u8; 512],
}

fn to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

pub struct AutoHandle(pub HANDLE);

impl AutoHandle {
    pub fn is_valid(&self) -> bool {
        self.0 != INVALID_HANDLE_VALUE && !self.0.is_null()
    }
}

impl Drop for AutoHandle {
    fn drop(&mut self) {
        if self.is_valid() {
            // Safety: Handle cleanup.
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

fn get_system_disk_number() -> Option<u32> {
    let path = to_wide(r"\\.\C:");
    // Safety: Volume query handle.
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        )
    };

    if handle == INVALID_HANDLE_VALUE || handle.is_null() {
        return None;
    }
    let auto_handle = AutoHandle(handle);

    let mut extents_buf = AlignedBuf1024([0u8; 1024]);
    let mut bytes_returned = 0u32;

    // Safety: DeviceIoControl with aligned buffer.
    let success = unsafe {
        DeviceIoControl(
            auto_handle.0,
            IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
            std::ptr::null(),
            0,
            extents_buf.0.as_mut_ptr() as _,
            extents_buf.0.len() as u32,
            &mut bytes_returned,
            std::ptr::null_mut(),
        )
    };

    if success != 0 && bytes_returned >= std::mem::size_of::<VolumeDiskExtents>() as u32 {
        let extents: VolumeDiskExtents = unsafe { std::ptr::read_unaligned(extents_buf.0.as_ptr() as *const VolumeDiskExtents) };
        if extents.number_of_disk_extents > 0 {
            return Some(extents.extents[0].disk_number);
        }
    }

    None
}

fn extract_string(buffer: &[u8], offset: u32) -> String {
    if offset == 0 || (offset as usize) >= buffer.len() {
        return String::new();
    }
    let slice = &buffer[(offset as usize)..];
    let mut end = 0;
    while end < slice.len() && slice[end] != 0 {
        end += 1;
    }
    String::from_utf8_lossy(&slice[..end]).trim().to_string()
}

pub fn enumerate_devices() -> Result<Vec<DeviceDescriptor>, IoError> {
    let mut devices = Vec::new();
    let system_disk_idx = get_system_disk_number();

    for drive_idx in 0..32 {
        let drive_path = format!(r"\\.\PhysicalDrive{}", drive_idx);
        let wide_path = to_wide(&drive_path);

        // First attempt opening with GENERIC_READ for full metadata + sector reading
        let mut handle = unsafe {
            CreateFileW(
                wide_path.as_ptr(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                std::ptr::null(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            )
        };

        let mut has_read_access = true;

        // If GENERIC_READ failed (e.g. ERROR_ACCESS_DENIED without admin elevation),
        // fallback to query access (0), which allows querying hardware identity/geometry!
        if handle == INVALID_HANDLE_VALUE || handle.is_null() {
            has_read_access = false;
            handle = unsafe {
                CreateFileW(
                    wide_path.as_ptr(),
                    0,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    std::ptr::null(),
                    OPEN_EXISTING,
                    0,
                    std::ptr::null_mut(),
                )
            };
        }

        if handle == INVALID_HANDLE_VALUE || handle.is_null() {
            continue;
        }

        let auto_handle = AutoHandle(handle);

        // 1. Query STORAGE_DEVICE_DESCRIPTOR
        let query = StoragePropertyQuery {
            property_id: STORAGE_PROPERTY_DEVICE,
            query_type: PROPERTY_STANDARD_QUERY,
            additional_parameters: [0; 4],
        };

        let mut desc_buf = AlignedBuf1024([0u8; 1024]);
        let mut bytes_returned = 0u32;

        let ok = unsafe {
            DeviceIoControl(
                auto_handle.0,
                IOCTL_STORAGE_QUERY_PROPERTY,
                &query as *const _ as _,
                std::mem::size_of::<StoragePropertyQuery>() as u32,
                desc_buf.0.as_mut_ptr() as _,
                desc_buf.0.len() as u32,
                &mut bytes_returned,
                std::ptr::null_mut(),
            )
        };

        let (vendor, model, serial, bus_type, removable) = if ok != 0 && bytes_returned >= std::mem::size_of::<StorageDeviceDescriptor>() as u32 {
            let desc: StorageDeviceDescriptor = unsafe { std::ptr::read_unaligned(desc_buf.0.as_ptr() as *const StorageDeviceDescriptor) };
            let vendor = extract_string(&desc_buf.0, desc.vendor_id_offset);
            let product = extract_string(&desc_buf.0, desc.product_id_offset);
            let serial = extract_string(&desc_buf.0, desc.serial_number_offset);
            (vendor, product, serial, desc.bus_type, desc.removable_media != 0)
        } else {
            (String::new(), format!("PhysicalDrive{}", drive_idx), String::new(), 0, false)
        };

        // 2. Query Seek Penalty (detects SSD vs HDD for SATA/SCSI/RAID)
        let seek_query = StoragePropertyQuery {
            property_id: STORAGE_PROPERTY_SEEK_PENALTY,
            query_type: PROPERTY_STANDARD_QUERY,
            additional_parameters: [0; 4],
        };
        let mut seek_buf = [0u8; 64];
        let mut seek_bytes = 0u32;
        let has_seek_penalty = unsafe {
            let ok = DeviceIoControl(
                auto_handle.0,
                IOCTL_STORAGE_QUERY_PROPERTY,
                &seek_query as *const _ as _,
                std::mem::size_of::<StoragePropertyQuery>() as u32,
                seek_buf.as_mut_ptr() as _,
                seek_buf.len() as u32,
                &mut seek_bytes,
                std::ptr::null_mut(),
            );
            if ok != 0 && seek_bytes >= std::mem::size_of::<DeviceSeekPenaltyDescriptor>() as u32 {
                let desc: DeviceSeekPenaltyDescriptor = std::ptr::read_unaligned(seek_buf.as_ptr() as *const DeviceSeekPenaltyDescriptor);
                desc.incurs_seek_penalty != 0
            } else {
                true // default assumption
            }
        };

        // 3. Query Geometry and Capacity
        let mut geom_buf = AlignedBuf256([0u8; 256]);
        let mut geom_bytes = 0u32;
        let mut capacity_bytes = 0u64;
        let mut logical_block_size = 512u32;
        let mut physical_block_size = 512u32;

        let geom_ok = unsafe {
            DeviceIoControl(
                auto_handle.0,
                IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
                std::ptr::null(),
                0,
                geom_buf.0.as_mut_ptr() as _,
                geom_buf.0.len() as u32,
                &mut geom_bytes,
                std::ptr::null_mut(),
            )
        };

        if geom_ok != 0 && geom_bytes >= std::mem::size_of::<DiskGeometryEx>() as u32 {
            let geom_ex: DiskGeometryEx = unsafe { std::ptr::read_unaligned(geom_buf.0.as_ptr() as *const DiskGeometryEx) };
            capacity_bytes = geom_ex.disk_size as u64;
            logical_block_size = geom_ex.geometry.bytes_per_sector;
            physical_block_size = logical_block_size;
        } else {
            let mut len_info = GetLengthInformation { length: 0 };
            let mut len_bytes = 0u32;
            let len_ok = unsafe {
                DeviceIoControl(
                    auto_handle.0,
                    IOCTL_DISK_GET_LENGTH_INFO,
                    std::ptr::null(),
                    0,
                    &mut len_info as *mut _ as _,
                    std::mem::size_of::<GetLengthInformation>() as u32,
                    &mut len_bytes,
                    std::ptr::null_mut(),
                )
            };
            if len_ok != 0 {
                capacity_bytes = len_info.length as u64;
            }
        }

        // 4. Classify Media Type & Interface string
        let (media_type, interface_str) = match bus_type {
            17 => (MediaType::Nvme, "NVMe".to_string()),
            7 => {
                if model.to_uppercase().contains("CARD") || model.to_uppercase().contains("SD") {
                    (MediaType::SdCard, "USB (Card Reader)".to_string())
                } else {
                    (MediaType::Usb, "USB".to_string())
                }
            }
            12 | 13 => (MediaType::SdCard, "SD/MMC".to_string()),
            11 => {
                // SATA
                if !has_seek_penalty || model.to_uppercase().contains("SSD") || vendor.to_uppercase().contains("SSD") {
                    (MediaType::SataSsd, "SATA".to_string())
                } else {
                    (MediaType::Hdd, "SATA".to_string())
                }
            }
            1 | 10 => {
                // SAS / SCSI
                if !has_seek_penalty || model.to_uppercase().contains("SSD") {
                    (MediaType::SataSsd, "SAS/SCSI".to_string())
                } else {
                    (MediaType::Hdd, "SAS/SCSI".to_string())
                }
            }
            _ => {
                if model.to_uppercase().contains("NVME") {
                    (MediaType::Nvme, "NVMe".to_string())
                } else if removable {
                    (MediaType::Usb, "Removable USB/Flash".to_string())
                } else if !has_seek_penalty || model.to_uppercase().contains("SSD") {
                    (MediaType::SataSsd, "SATA/NVMe SSD".to_string())
                } else {
                    (MediaType::Hdd, "Direct Block".to_string())
                }
            }
        };

        // 5. Check OS Read-Only Status
        let mut dummy = 0u32;
        let is_writable = unsafe {
            DeviceIoControl(
                auto_handle.0,
                IOCTL_DISK_IS_WRITABLE,
                std::ptr::null(),
                0,
                std::ptr::null_mut(),
                0,
                &mut dummy,
                std::ptr::null_mut(),
            )
        };
        let is_read_only = is_writable == 0 && unsafe { GetLastError() } == ERROR_WRITE_PROTECT;

        // 6. Check Write Blocker
        let (is_write_blocked, write_blocker_info) = check_write_blocker(None, None, &vendor, &model, is_read_only);

        // 7. Read Sector 0 & 1 for boundary sample and partition table
        let mut sector_0 = vec![0u8; logical_block_size.max(512) as usize];
        let mut sector_1 = vec![0u8; logical_block_size.max(512) as usize];
        let mut bytes_read = 0u32;

        let mut read_sec0_ok = false;
        let mut read_sec1_ok = false;

        if has_read_access {
            let r0 = unsafe {
                ReadFile(
                    auto_handle.0,
                    sector_0.as_mut_ptr() as _,
                    sector_0.len() as u32,
                    &mut bytes_read,
                    std::ptr::null_mut(),
                )
            };
            if r0 != 0 && bytes_read as usize == sector_0.len() {
                read_sec0_ok = true;
                let r1 = unsafe {
                    ReadFile(
                        auto_handle.0,
                        sector_1.as_mut_ptr() as _,
                        sector_1.len() as u32,
                        &mut bytes_read,
                        std::ptr::null_mut(),
                    )
                };
                if r1 != 0 && bytes_read as usize == sector_1.len() {
                    read_sec1_ok = true;
                }
            }
        }

        let partition_table = if read_sec0_ok {
            let sec1_ref = if read_sec1_ok { Some(sector_1.as_slice()) } else { None };
            detect_partition_table(&sector_0, sec1_ref)
        } else if !has_read_access {
            "Protected (Elevated Administrator privileges required for sector access)".to_string()
        } else {
            "Raw / Inaccessible".to_string()
        };

        let boundary_sample = if read_sec0_ok {
            sector_0[..512.min(sector_0.len())].to_vec()
        } else {
            vec![0u8; 512]
        };

        let is_system_disk = system_disk_idx.map_or(false, |sys_idx| sys_idx == drive_idx);

        devices.push(DeviceDescriptor {
            path: drive_path,
            device_index: drive_idx,
            manufacturer: if vendor.is_empty() { "Generic".to_string() } else { vendor },
            model: if model.is_empty() { format!("Drive {}", drive_idx) } else { model },
            serial: if serial.is_empty() { format!("UNKNOWN-{}", drive_idx) } else { serial },
            capacity_bytes,
            logical_block_size,
            physical_block_size,
            media_type,
            interface: interface_str,
            partition_table,
            is_system_disk,
            is_read_only,
            is_write_blocked,
            write_blocker_info,
            boundary_sample,
        });
    }

    Ok(devices)
}

fn query_windows_nvme_health(handle: HANDLE) -> Option<NvmeHealthInfo> {
    let query_size = std::mem::size_of::<StoragePropertyQuery>() + std::mem::size_of::<StorageProtocolSpecificData>() + 512;
    let mut buffer = vec![0u8; query_size];

    let query = unsafe { &mut *(buffer.as_mut_ptr() as *mut StoragePropertyQuery) };
    query.property_id = STORAGE_PROPERTY_ADAPTER_PROTOCOL;
    query.query_type = PROPERTY_STANDARD_QUERY;

    let proto_data = unsafe {
        &mut *(buffer
            .as_mut_ptr()
            .add(std::mem::size_of::<StoragePropertyQuery>()) as *mut StorageProtocolSpecificData)
    };
    proto_data.protocol_type = PROTOCOL_TYPE_NVME;
    proto_data.data_type = NVME_DATA_TYPE_LOG_PAGE;
    proto_data.protocol_data_request_value = NVME_LOG_PAGE_SMART;
    proto_data.protocol_data_offset = std::mem::size_of::<StorageProtocolSpecificData>() as u32;
    proto_data.protocol_data_length = 512;

    let mut bytes_returned = 0u32;

    // Safety: NVMe protocol query IOCTL.
    let ok = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_STORAGE_QUERY_PROPERTY,
            buffer.as_ptr() as _,
            buffer.len() as u32,
            buffer.as_mut_ptr() as _,
            buffer.len() as u32,
            &mut bytes_returned,
            std::ptr::null_mut(),
        )
    };

    if ok != 0 {
        let proto_header_offset = std::mem::size_of::<StoragePropertyQuery>();
        let data_offset = proto_header_offset + std::mem::size_of::<StorageProtocolSpecificData>();

        if buffer.len() >= data_offset + 512 {
            let log = &buffer[data_offset..data_offset + 512];
            let critical_warnings = log[0];
            let temp_kelvin = u16::from_le_bytes([log[1], log[2]]);
            let temp_celsius = if temp_kelvin >= 273 { (temp_kelvin - 273) as i32 } else { 0 };
            let available_spare = log[3];
            let available_spare_thresh = log[4];
            let percentage_used = log[5];

            let read_u128 = |start: usize| -> u128 {
                let mut bytes = [0u8; 16];
                bytes.copy_from_slice(&log[start..start + 16]);
                u128::from_le_bytes(bytes)
            };

            let data_units_read = read_u128(32);
            let data_units_written = read_u128(48);
            let host_read_cmds = read_u128(64);
            let host_write_cmds = read_u128(80);
            let busy_time = read_u128(96);
            let power_cycles = read_u128(112);
            let power_on_hours = read_u128(128);
            let unsafe_shutdowns = read_u128(144);
            let media_errors = read_u128(160);
            let error_log_entries = read_u128(176);

            return Some(NvmeHealthInfo {
                critical_warnings,
                temperature_celsius: temp_celsius,
                available_spare_percent: available_spare,
                available_spare_threshold: available_spare_thresh,
                percentage_used,
                data_units_read,
                data_units_written,
                host_read_commands: host_read_cmds,
                host_write_commands: host_write_cmds,
                controller_busy_time_minutes: busy_time,
                power_cycles,
                power_on_hours,
                unsafe_shutdowns,
                media_errors,
                error_log_entries,
            });
        }
    }

    None
}

fn query_windows_ata_smart(handle: HANDLE) -> (Option<HddHealthInfo>, Vec<SmartAttribute>) {
    let mut predictor = PredictFailurePredictor {
        predictor_failure: 0,
        vendor_specific: [0u8; 512],
    };
    let mut bytes_returned = 0u32;

    // Safety: ATA SMART predict failure IOCTL.
    let ok = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_STORAGE_PREDICT_FAILURE,
            std::ptr::null(),
            0,
            &mut predictor as *mut _ as _,
            std::mem::size_of::<PredictFailurePredictor>() as u32,
            &mut bytes_returned,
            std::ptr::null_mut(),
        )
    };

    if ok == 0 || bytes_returned < 512 {
        return (None, Vec::new());
    }

    let raw = &predictor.vendor_specific;
    let mut smart_attrs = Vec::new();
    let mut reallocated = 0u64;
    let mut pending = 0u64;
    let mut uncorrectable = 0u64;
    let mut power_on_hours = 0u64;
    let mut temp = 0i32;
    let mut raw_read_err = 0u64;

    for i in 0..30 {
        let offset = 2 + i * 12;
        if offset + 12 > raw.len() {
            break;
        }
        let attr_slice = &raw[offset..offset + 12];
        let id = attr_slice[0];
        if id == 0 {
            continue;
        }

        let _flags = u16::from_le_bytes([attr_slice[1], attr_slice[2]]);
        let current = attr_slice[3];
        let worst = attr_slice[4];
        let mut raw_bytes = [0u8; 8];
        raw_bytes[0..6].copy_from_slice(&attr_slice[5..11]);
        let raw_val = u64::from_le_bytes(raw_bytes);

        let name = match id {
            0x01 => {
                raw_read_err = raw_val;
                "Raw Read Error Rate"
            }
            0x05 => {
                reallocated = raw_val;
                "Reallocated Sectors Count"
            }
            0x09 => {
                power_on_hours = raw_val;
                "Power-On Hours"
            }
            0x0C => "Power Cycle Count",
            0xC2 => {
                temp = (raw_val & 0xFF) as i32;
                "Temperature Celsius"
            }
            0xC5 => {
                pending = raw_val;
                "Current Pending Sector Count"
            }
            0xC6 => {
                uncorrectable = raw_val;
                "Offline Uncorrectable Sector Count"
            }
            _ => "Vendor Specific",
        };

        smart_attrs.push(SmartAttribute {
            id,
            name: name.to_string(),
            current,
            worst,
            threshold: 0,
            raw_value: raw_val,
            failing_now: predictor.predictor_failure != 0,
        });
    }

    let hdd_info = HddHealthInfo {
        reallocated_sectors: reallocated,
        pending_sectors: pending,
        uncorrectable_sectors: uncorrectable,
        power_on_hours,
        temperature_celsius: temp,
        raw_read_error_rate: raw_read_err,
    };

    (Some(hdd_info), smart_attrs)
}

pub fn query_device_health(descriptor: &DeviceDescriptor) -> Result<DeviceHealth, IoError> {
    let wide_path = to_wide(&descriptor.path);

    // Safety: Health query handle.
    let handle = unsafe {
        CreateFileW(
            wide_path.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        )
    };

    if handle == INVALID_HANDLE_VALUE || handle.is_null() {
        let err = unsafe { GetLastError() };
        if err == ERROR_ACCESS_DENIED {
            return Err(IoError::PermissionDenied {
                details: format!("Access denied querying health for {}", descriptor.path),
            });
        }
        return Err(IoError::DeviceNotFound {
            path: descriptor.path.clone(),
        });
    }

    let auto_handle = AutoHandle(handle);

    if descriptor.media_type == MediaType::Nvme {
        if let Some(nvme_info) = query_windows_nvme_health(auto_handle.0) {
            return Ok(DeviceHealth::evaluate(
                descriptor.media_type,
                Some(nvme_info),
                None,
                None,
                vec![],
            ));
        }
    }

    let (hdd_info, smart_attrs) = query_windows_ata_smart(auto_handle.0);

    Ok(DeviceHealth::evaluate(
        descriptor.media_type,
        None,
        hdd_info,
        None,
        smart_attrs,
    ))
}

pub struct OsDriveHandle {
    handle: HANDLE,
    #[allow(dead_code)]
    path: String,
    is_writable: bool,
}

unsafe impl Send for OsDriveHandle {}

impl Drop for OsDriveHandle {
    fn drop(&mut self) {
        if self.handle != INVALID_HANDLE_VALUE && !self.handle.is_null() {
            // Safety: Handle cleanup.
            unsafe {
                CloseHandle(self.handle);
            }
        }
    }
}

impl OsDriveHandle {
    pub fn open_readonly(path: &Path) -> Result<Self, IoError> {
        let path_str = path.to_string_lossy().to_string();
        let wide_path = to_wide(&path_str);

        // Safety: Unbuffered sector read handle.
        let handle = unsafe {
            CreateFileW(
                wide_path.as_ptr(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_NO_BUFFERING,
                std::ptr::null_mut(),
            )
        };

        if handle == INVALID_HANDLE_VALUE || handle.is_null() {
            let err = unsafe { GetLastError() };
            if err == ERROR_ACCESS_DENIED {
                return Err(IoError::PermissionDenied {
                    details: format!("Access denied opening {} (Administrator elevation required)", path_str),
                });
            }
            return Err(IoError::DeviceNotFound { path: path_str });
        }

        Ok(Self {
            handle,
            path: path_str,
            is_writable: false,
        })
    }

    pub fn open_writable(path: &Path) -> Result<Self, IoError> {
        let path_str = path.to_string_lossy().to_string();
        let wide_path = to_wide(&path_str);

        // Safety: Unbuffered sector write handle.
        let handle = unsafe {
            CreateFileW(
                wide_path.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH,
                std::ptr::null_mut(),
            )
        };

        if handle == INVALID_HANDLE_VALUE || handle.is_null() {
            let err = unsafe { GetLastError() };
            if err == ERROR_ACCESS_DENIED {
                return Err(IoError::PermissionDenied {
                    details: format!("Access denied opening {} for write (Administrator elevation required)", path_str),
                });
            }
            if err == ERROR_WRITE_PROTECT {
                return Err(IoError::UnsupportedOperation {
                    operation: "open_writable".to_string(),
                    reason: "Device is write-protected by hardware or OS policy".to_string(),
                });
            }
            return Err(IoError::DeviceNotFound { path: path_str });
        }

        Ok(Self {
            handle,
            path: path_str,
            is_writable: true,
        })
    }

    pub fn read_blocks(&mut self, lba: u64, count: u32, block_size: u32) -> Result<Vec<u8>, IoError> {
        let total_bytes = (count as u64)
            .checked_mul(block_size as u64)
            .ok_or_else(|| IoError::InvalidParameter {
                message: format!("Block count {count} overflowed for block size {block_size}"),
            })?;

        let offset = lba
            .checked_mul(block_size as u64)
            .ok_or_else(|| IoError::InvalidParameter {
                message: format!("LBA {lba} overflowed for block size {block_size}"),
            })?;

        let total_bytes_usize = total_bytes as usize;
        let mut buffer = AlignedBuffer::new(total_bytes_usize, 4096);

        let mut new_pos = 0i64;
        // Safety: Seek to 64-bit sector offset.
        let seek_ok = unsafe {
            SetFilePointerEx(
                self.handle,
                offset as i64,
                &mut new_pos,
                FILE_BEGIN,
            )
        };

        if seek_ok == 0 {
            let err = unsafe { GetLastError() };
            return Err(IoError::ReadFailureAtLba {
                lba,
                count,
                details: format!("SetFilePointerEx failed with Win32 error {err}"),
            });
        }

        let mut bytes_read = 0u32;
        // Safety: Unbuffered sector read into aligned buffer.
        let read_ok = unsafe {
            ReadFile(
                self.handle,
                buffer.as_mut_ptr() as _,
                total_bytes_usize as u32,
                &mut bytes_read,
                std::ptr::null_mut(),
            )
        };

        if read_ok == 0 || bytes_read as usize != total_bytes_usize {
            let err = unsafe { GetLastError() };
            return Err(IoError::ReadFailureAtLba {
                lba,
                count,
                details: format!("ReadFile failed with Win32 error {err} (bytes read: {bytes_read}/{total_bytes_usize})"),
            });
        }

        Ok(buffer.into_vec())
    }

    pub fn write_blocks(&mut self, lba: u64, data: &[u8], block_size: u32) -> Result<(), IoError> {
        if !self.is_writable {
            return Err(IoError::UnsupportedOperation {
                operation: "write_blocks".to_string(),
                reason: "Device handle was opened in read-only mode".to_string(),
            });
        }

        if data.len() % (block_size as usize) != 0 {
            return Err(IoError::InvalidParameter {
                message: format!(
                    "Write payload length {} is not a multiple of sector size {}",
                    data.len(),
                    block_size
                ),
            });
        }

        let offset = lba
            .checked_mul(block_size as u64)
            .ok_or_else(|| IoError::InvalidParameter {
                message: format!("LBA {lba} overflowed for block size {block_size}"),
            })?;

        let mut aligned_buf = AlignedBuffer::new(data.len(), 4096);
        aligned_buf.as_mut_slice().copy_from_slice(data);

        let mut new_pos = 0i64;
        // Safety: Seek to 64-bit sector offset.
        let seek_ok = unsafe {
            SetFilePointerEx(
                self.handle,
                offset as i64,
                &mut new_pos,
                FILE_BEGIN,
            )
        };

        if seek_ok == 0 {
            let err = unsafe { GetLastError() };
            return Err(IoError::WriteFailureAtLba {
                lba,
                count: (data.len() / block_size as usize) as u32,
                details: format!("SetFilePointerEx failed with Win32 error {err}"),
            });
        }

        let mut bytes_written = 0u32;
        // Safety: Unbuffered sector write from aligned buffer.
        let write_ok = unsafe {
            WriteFile(
                self.handle,
                aligned_buf.as_ptr() as _,
                data.len() as u32,
                &mut bytes_written,
                std::ptr::null_mut(),
            )
        };

        if write_ok == 0 || bytes_written as usize != data.len() {
            let err = unsafe { GetLastError() };
            return Err(IoError::WriteFailureAtLba {
                lba,
                count: (data.len() / block_size as usize) as u32,
                details: format!("WriteFile failed with Win32 error {err} (bytes written: {bytes_written}/{})", data.len()),
            });
        }

        Ok(())
    }
}

pub struct AlignedBuffer {
    layout: std::alloc::Layout,
    ptr: *mut u8,
    size: usize,
}

unsafe impl Send for AlignedBuffer {}

impl AlignedBuffer {
    pub fn new(size: usize, alignment: usize) -> Self {
        let layout = std::alloc::Layout::from_size_align(size, alignment)
            .unwrap_or_else(|_| std::alloc::Layout::from_size_align(size, 4096).unwrap());
        // Safety: std::alloc::alloc_zeroed allocates initialized zero memory.
        let ptr = unsafe { std::alloc::alloc_zeroed(layout) };
        if ptr.is_null() {
            std::alloc::handle_alloc_error(layout);
        }
        Self { layout, ptr, size }
    }

    pub fn as_ptr(&self) -> *const u8 {
        self.ptr
    }

    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.ptr
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        // Safety: self.ptr is non-null and points to `self.size` allocated bytes.
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.size) }
    }

    pub fn into_vec(self) -> Vec<u8> {
        // Safety: self.ptr points to `self.size` allocated bytes.
        let slice = unsafe { std::slice::from_raw_parts(self.ptr, self.size) };
        slice.to_vec()
    }
}

impl Drop for AlignedBuffer {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            // Safety: Deallocate memory with exact layout.
            unsafe {
                std::alloc::dealloc(self.ptr, self.layout);
            }
        }
    }
}
