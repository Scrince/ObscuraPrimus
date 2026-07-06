#define MyAppName "ObscuraPrimus"
#define MyAppVersion "1.0.0"
#define MyAppExeName "ObscuraPrimus.exe"

[Setup]
AppId={{B1F79E1B-9E6C-4AB2-9C6D-0B5C0A901001}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
OutputBaseFilename=ObscuraPrimus-Setup-{#MyAppVersion}
Compression=lzma
SolidCompression=yes
WizardStyle=modern
SetupIconFile=..\assets\ico\windows\SteganographyAnalyzer.ico

[Files]
Source: "..\release\ObscuraPrimus-1.0.0-windows-x64\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional icons:"
