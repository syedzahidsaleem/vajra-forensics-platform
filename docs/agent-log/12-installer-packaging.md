# Agent Log 12 — Cross-Platform Installer Packaging & Distribution

**Date:** 2026-09-20  
**Scope:** Windows NSIS Installer (`.exe`), Linux Debian Package (`.deb`), and macOS Phase B Integration.  
**Author:** Syed Zahid Saleem / Antigravity Agent  

---

## 1. Executive Summary & Architecture

Prior conversations established Vajra's 20-crate backend, encrypted SQLCipher vault at rest, multi-tier carving pipeline, and modern Tauri/React desktop interface. However, the original blueprint (`Vajra_Master_Technical_Document.md`) lacked a dedicated installer and distribution specification.

This milestone establishes native, production-grade installer packaging for Windows and Linux without compiling from source on target examiner machines:
- **Windows**: Nullsoft Scriptable Install System (NSIS) installer (`Vajra-0.1.0-Setup.exe`, 19.2 MB) featuring a 5-page standard wizard, mandatory license acceptance, system `PATH` registration, Start Menu/Desktop shortcuts, and a clean uninstaller.
- **Linux**: Standard Debian package (`vajra_0.1.0_amd64.deb`, 4.38 MB) with `preinst` mount validation, standard `/usr/bin` installation, data directories under `/usr/share/vajra/`, and privilege elevation post-install guidance.
- **macOS (Phase B)**: Folded into the existing Phase B hardware checklist in `docs/agent-log/10-macos-device-support-phase-a.md`.

---

## 2. The Hard Rule: Enforcement of OS / Boot Drive Installation

### The Rationale
Vajra's `DeviceConfirmationGate` unconditionally refuses to wipe or sanitize the host's OS/boot disk to prevent bricking the examination workstation. Every *other* connected drive is intended to be fully sanitizable.

If Vajra's own installation binaries or case databases were placed on a non-OS storage drive, that drive would contain in-use, locked files, preventing the platform from performing full raw sanitization or overwrite passes against it. Restricting the platform installation strictly to the OS/boot volume guarantees that only the host OS drive is protected, leaving all secondary evidence drives fully sanitizable.

### Implementation Details

#### Windows (NSIS `installer.nsi`)
The installer overrides the directory selection page's leave callback (`MUI_PAGE_CUSTOMFUNCTION_LEAVE CheckInstallDirectory`):
```nsis
Function CheckInstallDirectory
    ; Extract first 3 characters of selected $INSTDIR (e.g. "D:\")
    StrCpy $0 $INSTDIR 3
    ; Extract first 3 characters of Windows system directory $WINDIR (e.g. "C:\")
    StrCpy $1 $WINDIR 3

    ${If} $0 != $1
        MessageBox MB_ICONSTOP|MB_OK \
            "Invalid Installation Location:$\r$\n$\r$\n\
Vajra must be installed on the Windows system/OS drive ($1) to ensure secondary evidence drives can be fully sanitized without in-use file locks.$\r$\n$\r$\n\
Please choose an installation path on drive $1 (such as $PROGRAMFILES64\Vajra)."
        Abort
    ${EndIf}
FunctionEnd
```
If an examiner attempts to select a secondary volume (e.g., `D:\ForensicTools\Vajra`), the installer displays a blocking error dialog and aborts navigation to the installation phase until a valid path on the system drive is selected.

#### Linux Debian Package (`preinst`)
The Debian `preinst` maintainer script dynamically inspects the filesystem mount table before unpacking files:
```sh
#!/bin/sh
set -e

ROOT_MOUNT=$(df -P / | tail -n1 | awk '{print $1}')
TARGET_MOUNT=$(df -P /usr | tail -n1 | awk '{print $1}')

if [ "$ROOT_MOUNT" != "$TARGET_MOUNT" ]; then
    echo "======================================================================" >&2
    echo "ERROR: Vajra Installation Location Restriction Violation" >&2
    echo "======================================================================" >&2
    echo "Vajra must be installed on the root OS filesystem (mount: $ROOT_MOUNT)." >&2
    echo "Target directory /usr is located on a separate mount ($TARGET_MOUNT)." >&2
    echo "This constraint ensures secondary evidence drives can be fully" >&2
    echo "sanitized without in-use file locks from the forensic platform." >&2
    echo "======================================================================" >&2
    exit 1
fi

exit 0
```

---

## 3. Installer UX Flow & Features

### Windows NSIS Flow
1. **Welcome Page**: Introduces the platform and prerequisites.
2. **License Agreement**: Displays the End User Terms & Conditions placeholder requiring explicit acceptance checkbox (`MUI_LICENSEPAGE_CHECKBOX`).
3. **Directory Selection**: Defaults to `$PROGRAMFILES64\Vajra` on the OS drive, enforcing the boot-drive rule.
4. **Installation Progress**:
   - Installs `vajra-tauri-app.exe` (GUI), `vajra-cli.exe` (CLI), `vajra-verify.exe` (Verifier).
   - Unpacks `config/signatures.json` and `ml-models/` tree weights.
   - Registers installation directory on System `PATH` (`HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment`) and broadcasts `WM_SETTINGCHANGE`.
   - Creates Start Menu entries ("Vajra Forensics Platform", "Vajra CLI Shell", "Uninstall Vajra") and Desktop shortcut.
   - Registers Add/Remove Programs metadata in `HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall\Vajra`.
5. **Finish Page**: Optional checkbox to immediately launch `vajra-tauri-app.exe`.
6. **Clean Uninstaller (`Uninstall.exe`)**:
   - Deletes installed executables, configurations, and models.
   - Removes Start Menu folder and Desktop shortcuts.
   - Safely strips `$INSTDIR` from System `PATH` and broadcasts `WM_SETTINGCHANGE`.
   - Removes registry keys without modifying case databases or evidence files.

---

## 4. Dependency Analysis & Binary Self-Containment

1. **SQLCipher & OpenSSL**:
   - `rusqlite` is compiled with `bundled-sqlcipher-vendored-openssl`.
   - `ldd` analysis on Linux release binaries confirms zero external dependencies on `libcrypto.so`, `libssl.so`, or `libsqlite3.so`:
     ```
     vajra-cli:
         linux-vdso.so.1
         libgcc_s.so.1 => /usr/lib/x86_64-linux-gnu/libgcc_s.so.1
         libm.so.6 => /usr/lib/x86_64-linux-gnu/libm.so.6
         libc.so.6 => /usr/lib/x86_64-linux-gnu/libc.so.6
     ```
   - On Windows, binaries are statically linked against vendored crypto routines and Universal C Runtime.
2. **WebView2 (Windows)**:
   - Uses the Evergreen WebView2 Runtime already built into Windows 10/11.
3. **VC++ Redistributable**:
   - Cross-compiled `x86_64-pc-windows-gnu` binaries link with static runtime libraries and standard Windows subsystem APIs, eliminating external VC++ redistributable dependencies.

---

## 5. Privilege Elevation Setup

Raw block device I/O (`\\.\PhysicalDriveX` on Windows, `/dev/sdX` / `/dev/nvmeX` on Linux) requires administrative privileges:
- **Windows**: NSIS installer requests `RequestExecutionLevel admin`. Start Menu shortcut and CLI shell prompt for standard UAC elevation.
- **Linux**: Post-install maintainer script displays guidance:
  - Standard: `sudo vajra-cli list`
  - Granular Capability (optional): `sudo setcap cap_sys_rawio,cap_sys_admin+ep /usr/bin/vajra-cli`

---

## 6. Build Artifacts & Verified Outputs

### 1. Windows Installer (`target/release/Vajra-0.1.0-Setup.exe`)
```
Output: "d:\Coding\Vajra\target\release\Vajra-0.1.0-Setup.exe"
Install: 5 pages (320 bytes), 1 section (1 required) (2072 bytes)
Uninstall: 3 pages (256 bytes), 1 section (2072 bytes)
Using zlib compression.
Total size: 19,286,853 bytes (~19.28 MB)
Build Script: packaging/windows/build_windows_installer.ps1
```

### 2. Linux Debian Package (`target/release/vajra_0.1.0_amd64.deb`)
```
Package: vajra
Version: 0.1.0
Architecture: amd64
Maintainer: Vajra Project Team <team@vajra.org>
Contents:
  /usr/bin/vajra-cli (13.8 MB, executable)
  /usr/bin/vajra-verify (0.79 MB, executable)
  /usr/share/vajra/config/signatures.json
  /usr/share/vajra/ml-models/file_type_classifier_trees.json
  /usr/share/vajra/ml-models/model_metadata.json
  /usr/share/doc/vajra/README.md
Debian Control Archive: control, preinst (chmod 755), postinst (chmod 755)
Total Size: 4,386,824 bytes (~4.38 MB)
Build Script: packaging/linux/build_deb_package.sh
```

---

## 7. macOS Phase B Traceability

Per Conversation 10, native macOS packaging (`.pkg` / `.dmg`) is deferred to Phase B when physical Apple Silicon hardware is connected. Item 9 in `docs/agent-log/10-macos-device-support-phase-a.md` has been updated to track macOS installer packaging alongside `/Applications` sealed-system-volume verification.
