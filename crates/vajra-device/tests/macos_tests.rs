use vajra_device::os::macos::parse_plist;


#[test]
fn test_macos_diskutil_list_plist_parsing() {
    let list_plist_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>AllDisks</key>
    <array>
        <string>disk0</string>
        <string>disk0s1</string>
        <string>disk0s2</string>
        <string>disk1</string>
        <string>disk1s1</string>
        <string>disk3</string>
        <string>disk3s1</string>
    </array>
    <key>AllDisksAndPartitions</key>
    <array>
        <dict>
            <key>Content</key>
            <string>GUID_partition_scheme</string>
            <key>DeviceIdentifier</key>
            <string>disk0</string>
            <key>Size</key>
            <integer>1000204886016</integer>
        </dict>
    </array>
    <key>WholeDisks</key>
    <array>
        <string>disk0</string>
        <string>disk1</string>
        <string>disk3</string>
    </array>
</dict>
</plist>"#;

    let root = parse_plist(list_plist_xml).expect("Should parse diskutil list plist XML");
    let dict = root.as_dict().expect("Root must be dictionary");

    let whole_disks = dict.get("WholeDisks").and_then(|v| v.as_array()).expect("Must have WholeDisks array");
    let disk_names: Vec<&str> = whole_disks.iter().filter_map(|v| v.as_str()).collect();

    assert_eq!(disk_names, vec!["disk0", "disk1", "disk3"]);
}

#[test]
fn test_macos_diskutil_info_plist_apfs_and_hardware_fields() {
    let info_plist_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>DeviceIdentifier</key>
    <string>disk0</string>
    <key>DeviceNode</key>
    <string>/dev/disk0</string>
    <key>DeviceVendor</key>
    <string>Apple</string>
    <key>DeviceModel</key>
    <string>APPLE SSD AP1024N</string>
    <key>DeviceSerialNumber</key>
    <string>C02941A0DB7F480F</string>
    <key>TotalSize</key>
    <integer>1000204886016</integer>
    <key>DeviceBlockSize</key>
    <integer>4096</integer>
    <key>BusProtocol</key>
    <string>PCI-Express</string>
    <key>SolidState</key>
    <true/>
    <key>Internal</key>
    <true/>
    <key>Writable</key>
    <true/>
    <key>SMARTStatus</key>
    <string>Verified</string>
    <key>WholeDisk</key>
    <true/>
    <key>VirtualOrPhysical</key>
    <string>Physical</string>
</dict>
</plist>"#;

    let parsed = parse_plist(info_plist_xml).expect("Should parse diskutil info plist");
    let dict = parsed.as_dict().expect("Must be dict");

    assert_eq!(dict.get("DeviceIdentifier").and_then(|v| v.as_str()), Some("disk0"));
    assert_eq!(dict.get("DeviceVendor").and_then(|v| v.as_str()), Some("Apple"));
    assert_eq!(dict.get("DeviceModel").and_then(|v| v.as_str()), Some("APPLE SSD AP1024N"));
    assert_eq!(dict.get("DeviceSerialNumber").and_then(|v| v.as_str()), Some("C02941A0DB7F480F"));
    assert_eq!(dict.get("TotalSize").and_then(|v| v.as_u64()), Some(1000204886016));
    assert_eq!(dict.get("DeviceBlockSize").and_then(|v| v.as_u64()), Some(4096));
    assert_eq!(dict.get("BusProtocol").and_then(|v| v.as_str()), Some("PCI-Express"));
    assert_eq!(dict.get("SolidState").and_then(|v| v.as_bool()), Some(true));
    assert_eq!(dict.get("Internal").and_then(|v| v.as_bool()), Some(true));
    assert_eq!(dict.get("SMARTStatus").and_then(|v| v.as_str()), Some("Verified"));
}

#[test]
fn test_macos_apfs_synthesized_container_detection() {
    let apfs_container_info = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>DeviceIdentifier</key>
    <string>disk3</string>
    <key>VirtualOrPhysical</key>
    <string>Virtual</string>
    <key>WholeDisk</key>
    <true/>
    <key>APFSPhysicalStores</key>
    <array>
        <dict>
            <key>DeviceIdentifier</key>
            <string>disk0s2</string>
        </dict>
    </array>
</dict>
</plist>"#;

    let parsed = parse_plist(apfs_container_info).expect("Should parse APFS container info");
    let dict = parsed.as_dict().expect("Must be dict");

    assert_eq!(dict.get("VirtualOrPhysical").and_then(|v| v.as_str()), Some("Virtual"));

    let stores = dict.get("APFSPhysicalStores").and_then(|v| v.as_array()).expect("Must have stores");
    assert_eq!(stores.len(), 1);

    let store_dict = stores[0].as_dict().expect("Store must be dict");
    let store_dev = store_dict.get("DeviceIdentifier").and_then(|v| v.as_str()).unwrap();
    assert_eq!(store_dev, "disk0s2");
}
