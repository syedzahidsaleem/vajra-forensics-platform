; ============================================================================
; Vajra Digital Forensics Platform — Windows NSIS Installer Script
; ============================================================================

!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "WinMessages.nsh"
!include "x64.nsh"

; --- General Configuration ---
Name "Vajra Digital Forensics Platform"
OutFile "..\..\target\release\Vajra-0.1.0-Setup.exe"
Unicode True
RequestExecutionLevel admin

; Use 64-bit Program Files by default on Windows OS drive
InstallDir "$PROGRAMFILES64\Vajra"
InstallDirRegKey HKLM "Software\Vajra" "InstallLocation"

; --- Interface Settings ---
!define MUI_ABORTWARNING
!define MUI_ICON "..\..\crates\vajra-tauri-app\icons\icon.ico"
!define MUI_UNICON "..\..\crates\vajra-tauri-app\icons\icon.ico"

; --- Installer Pages ---
; 1. Welcome Page
!insertmacro MUI_PAGE_WELCOME

; 2. License Agreement Page (Mandatory acceptance checkbox)
!define MUI_LICENSEPAGE_CHECKBOX
!insertmacro MUI_PAGE_LICENSE "license.txt"

; 3. Install Location Page (With Hard OS-Drive Restriction)
!define MUI_PAGE_CUSTOMFUNCTION_LEAVE CheckInstallDirectory
!insertmacro MUI_PAGE_DIRECTORY

; 4. Installation Progress Page
!insertmacro MUI_PAGE_INSTFILES

; 5. Finish Page
!define MUI_FINISHPAGE_RUN "$INSTDIR\vajra-tauri-app.exe"
!define MUI_FINISHPAGE_RUN_TEXT "Launch Vajra Digital Forensics Platform"
!insertmacro MUI_PAGE_FINISH

; --- Uninstaller Pages ---
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_UNPAGE_FINISH

; --- Language ---
!insertmacro MUI_LANGUAGE "English"

; ============================================================================
; Hard Rule: Enforce Installation to OS / Boot Drive Only
; ============================================================================
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

; ============================================================================
; Installation Section
; ============================================================================
Section "Vajra Core Application" SecCore
    SectionIn RO

    SetOutPath "$INSTDIR"

    ; Core Executables
    File "..\..\target\x86_64-pc-windows-gnu\release\vajra-tauri-app.exe"
    File "..\..\target\x86_64-pc-windows-gnu\release\vajra-cli.exe"
    File "..\..\target\x86_64-pc-windows-gnu\release\vajra-verify.exe"

    ; Configuration and Signatures
    CreateDirectory "$INSTDIR\config"
    SetOutPath "$INSTDIR\config"
    File "..\..\config\signatures.json"

    ; ML Models
    CreateDirectory "$INSTDIR\ml-models"
    SetOutPath "$INSTDIR\ml-models"
    File "..\..\ml-models\file_type_classifier_trees.json"
    File "..\..\ml-models\model_metadata.json"

    ; Documentation & Legal Notice
    SetOutPath "$INSTDIR"
    File "license.txt"
    File "..\..\README.md"

    ; Store installation folder in Registry
    WriteRegStr HKLM "Software\Vajra" "InstallLocation" "$INSTDIR"
    WriteRegStr HKLM "Software\Vajra" "Version" "0.1.0"

    ; Create uninstaller
    WriteUninstaller "$INSTDIR\Uninstall.exe"

    ; Register in Windows Add/Remove Programs
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Vajra" \
                     "DisplayName" "Vajra Digital Forensics Platform"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Vajra" \
                     "DisplayVersion" "0.1.0"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Vajra" \
                     "Publisher" "Vajra Project Team"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Vajra" \
                     "InstallLocation" "$INSTDIR"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Vajra" \
                     "DisplayIcon" "$INSTDIR\vajra-tauri-app.exe"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Vajra" \
                     "UninstallString" "$\"$INSTDIR\Uninstall.exe$\""
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Vajra" \
                      "NoModify" 1
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Vajra" \
                      "NoRepair" 1

    ; Create Start Menu Shortcuts
    CreateDirectory "$SMPROGRAMS\Vajra"
    CreateShortcut "$SMPROGRAMS\Vajra\Vajra Forensics Platform.lnk" "$INSTDIR\vajra-tauri-app.exe" "" "$INSTDIR\vajra-tauri-app.exe" 0
    CreateShortcut "$SMPROGRAMS\Vajra\Vajra CLI Shell.lnk" "$SYSDIR\cmd.exe" "/k $\"echo Vajra Forensic CLI Environment && $\"$INSTDIR\vajra-cli.exe$\" --help$\"" "$INSTDIR\vajra-tauri-app.exe" 0
    CreateShortcut "$SMPROGRAMS\Vajra\Uninstall Vajra.lnk" "$INSTDIR\Uninstall.exe" "" "$INSTDIR\Uninstall.exe" 0

    ; Create Desktop Shortcut
    CreateShortcut "$DESKTOP\Vajra Forensics Platform.lnk" "$INSTDIR\vajra-tauri-app.exe" "" "$INSTDIR\vajra-tauri-app.exe" 0

    ; Add $INSTDIR to System PATH Environment Variable
    ReadRegStr $0 HKLM "SYSTEM\CurrentControlSet\Control\Session Manager\Environment" "Path"
    ${If} $0 != ""
        ; Check if $INSTDIR is already present in PATH
        Push "$0"
        Push "$INSTDIR"
        Call StrStr
        Pop $1
        ${If} $1 == ""
            WriteRegExpandStr HKLM "SYSTEM\CurrentControlSet\Control\Session Manager\Environment" "Path" "$0;$INSTDIR"
            SendMessage ${HWND_BROADCAST} ${WM_SETTINGCHANGE} 0 "STR:Environment" /TIMEOUT=5000
        ${EndIf}
    ${EndIf}

SectionEnd

; ============================================================================
; Uninstaller Section
; ============================================================================
Section "Uninstall"
    ; Remove files
    Delete "$INSTDIR\vajra-tauri-app.exe"
    Delete "$INSTDIR\vajra-cli.exe"
    Delete "$INSTDIR\vajra-verify.exe"
    Delete "$INSTDIR\license.txt"
    Delete "$INSTDIR\README.md"
    Delete "$INSTDIR\config\signatures.json"
    RMDir "$INSTDIR\config"
    Delete "$INSTDIR\ml-models\file_type_classifier_trees.json"
    Delete "$INSTDIR\ml-models\model_metadata.json"
    RMDir "$INSTDIR\ml-models"
    Delete "$INSTDIR\Uninstall.exe"
    RMDir "$INSTDIR"

    ; Remove Shortcuts
    Delete "$DESKTOP\Vajra Forensics Platform.lnk"
    Delete "$SMPROGRAMS\Vajra\Vajra Forensics Platform.lnk"
    Delete "$SMPROGRAMS\Vajra\Vajra CLI Shell.lnk"
    Delete "$SMPROGRAMS\Vajra\Uninstall Vajra.lnk"
    RMDir "$SMPROGRAMS\Vajra"

    ; Remove Add/Remove Programs registration
    DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Vajra"
    DeleteRegKey HKLM "Software\Vajra"

    ; Remove $INSTDIR from System PATH
    ReadRegStr $0 HKLM "SYSTEM\CurrentControlSet\Control\Session Manager\Environment" "Path"
    ${If} $0 != ""
        Push "$0"
        Push ";$INSTDIR"
        Call un.StrReplace
        Pop $0

        Push "$0"
        Push "$INSTDIR;"
        Call un.StrReplace
        Pop $0

        Push "$0"
        Push "$INSTDIR"
        Call un.StrReplace
        Pop $0

        WriteRegExpandStr HKLM "SYSTEM\CurrentControlSet\Control\Session Manager\Environment" "Path" "$0"
        SendMessage ${HWND_BROADCAST} ${WM_SETTINGCHANGE} 0 "STR:Environment" /TIMEOUT=5000
    ${EndIf}

SectionEnd

; ============================================================================
; Helper String Functions (Installer & Uninstaller)
; ============================================================================
Function StrStr
    Exch $R1 ; substring
    Exch
    Exch $R2 ; string
    Push $R3
    Push $R4
    Push $R5

    StrLen $R3 $R1
    StrCpy $R4 0

    loop:
        StrCpy $R5 $R2 $R3 $R4
        StrCmp $R5 $R1 found
        StrCmp $R5 "" notfound
        IntOp $R4 $R4 + 1
        Goto loop

    found:
        StrCpy $R1 $R2 "" $R4
        Goto done

    notfound:
        StrCpy $R1 ""

    done:
        Pop $R5
        Pop $R4
        Pop $R3
        Pop $R2
        Exch $R1
FunctionEnd

Function un.StrReplace
    Exch $R0 ; to replace
    Exch
    Exch $R1 ; to replace with
    Exch 2
    Exch $R2 ; in string
    Push $R3
    Push $R4
    Push $R5
    Push $R6
    Push $R7

    StrLen $R3 $R0
    StrCpy $R4 0
    StrCpy $R5 ""

    loop:
        StrCpy $R6 $R2 $R3 $R4
        StrCmp $R6 $R0 found
        StrCmp $R6 "" done
        StrCpy $R7 $R2 1 $R4
        StrCpy $R5 "$R5$R7"
        IntOp $R4 $R4 + 1
        Goto loop

    found:
        StrCpy $R5 "$R5$R1"
        IntOp $R4 $R4 + $R3
        Goto loop

    done:
        StrCpy $R2 $R5
        Pop $R7
        Pop $R6
        Pop $R5
        Pop $R4
        Pop $R3
        Pop $R1
        Pop $R0
        Exch $R2
FunctionEnd

