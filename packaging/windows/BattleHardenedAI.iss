; Inno Setup script for Battle-Hardened AI (Windows)
; This expects that PyInstaller has already produced BattleHardenedAI.exe
; at the repository root: C:\Users\<user>\workspace\battle-hardened-ai\BattleHardenedAI.exe

[Setup]
AppId={{4F9D4F5C-5F4B-4F5F-9C5C-4F5C9D5F4B4F}
AppName=Battle-Hardened AI
AppVersion=1.0.0
AppPublisher=Elite Cybersecurity Specialist
DefaultDirName={pf}\Battle-Hardened AI
DefaultGroupName=Battle-Hardened AI
DisableDirPage=no
DisableProgramGroupPage=yes
LicenseFile={#SourcePath}\..\..\..\LICENSE
OutputDir={#SourcePath}
OutputBaseFilename=BattleHardenedAI-Setup
Compression=lzma
SolidCompression=yes
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &Desktop icon"; GroupDescription: "Additional icons:"; Flags: unchecked

[Files]
; Main executable built by PyInstaller (must exist before running ISCC)
; {#SourcePath} = ...\packaging\windows\
; EXE is built into the local dist/ folder by build_windows_exe.ps1.
Source: "{#SourcePath}\dist\BattleHardenedAI.exe"; DestDir: "{app}"; Flags: ignoreversion

; Top-level docs (also at repo root)
Source: "{#SourcePath}\..\..\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourcePath}\..\..\LICENSE"; DestDir: "{app}"; Flags: ignoreversion

; Documentation and policies folders from repo root
Source: "{#SourcePath}\..\..\Documentation\*"; DestDir: "{app}\Documentation"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#SourcePath}\..\..\policies\*"; DestDir: "{app}\policies"; Flags: ignoreversion recursesubdirs createallsubdirs

; Windows environment file (copied from the same local dist folder as the EXE)
Source: "{#SourcePath}\dist\.env.windows"; DestDir: "{app}"; Flags: ignoreversion

; Windows Defender / firewall sync helper script
Source: "{#SourcePath}\..\..\windows-firewall\windows_defender_sync.ps1"; DestDir: "{app}\windows-firewall"; Flags: ignoreversion

[Icons]
; Start Menu shortcut
Name: "{group}\Battle-Hardened AI"; Filename: "{app}\BattleHardenedAI.exe"; WorkingDir: "{app}"

; Optional desktop shortcut
Name: "{commondesktop}\Battle-Hardened AI"; Filename: "{app}\BattleHardenedAI.exe"; WorkingDir: "{app}"; Tasks: desktopicon

[Run]
; Optionally start immediately after install (kept off by default for administrators)
; Name: "Launch Battle-Hardened AI"; Filename: "{app}\BattleHardenedAI.exe"; Description: "Launch Battle-Hardened AI"; Flags: nowait postinstall skipifsilent
