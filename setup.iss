; Script generated by the Inno Setup Script Wizard.
; SEE THE DOCUMENTATION FOR DETAILS ON CREATING INNO SETUP SCRIPT FILES!

#define MyAppName "VeriBlock vBTC"
#define MyAppVersion "2.26"
#define MyAppPublisher "VeriBlock Incorporated"
#define MyAppURL "https://www.veriblock.org"
#define MyAppExeName "bitcoin-qt.exe"

[Setup]
; NOTE: The value of AppId uniquely identifies this application.
; Do not use the same AppId value in installers for other applications.
; (To generate a new GUID, click Tools | Generate GUID inside the IDE.)
AppId={{60d6e256-a9ed-40bc-8a52-b5f88a209ad4}}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
;AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={pf}\{#MyAppName}
DisableProgramGroupPage=yes
OutputBaseFilename=setup-vbk-ri-bt-rc2.26.0
Compression=lzma
SolidCompression=yes

[InstallDelete]

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"


[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "C:\git\repo\vbk-ri-btc\src\qt\bitcoin-qt.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "C:\git\repo\vbk-ri-btc\bitcoin.conf"; DestDir: "{app}"; Flags: ignoreversion
Source: "C:\git\repo\vbk-ri-btc\bitcoin.conf"; DestDir: "{userappdata}\bitcoin\"; Flags: ignoreversion
Source: "C:\git\repo\vbk-ri-btc\src\bitcoin-cli.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "C:\git\repo\vbk-ri-btc\src\bitcoind.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "C:\git\repo\vbk-ri-btc\README.md"; DestDir: "{app}"; Flags: ignoreversion
; NOTE: Don't use "Flags: ignoreversion" on any shared system files

[Icons]
Name: "{commonprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{commondesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent

