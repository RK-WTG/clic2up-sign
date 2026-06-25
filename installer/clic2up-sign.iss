; =============================================================================
; Inno Setup Script pour clic2up-sign
; Service local de signature electronique des factures
; =============================================================================

#define MyAppName "clic2up-sign"
#define MyAppVersion "1.0.2"
#define MyAppPublisher "SOCIETE WEBATG"
#define MyAppURL "https://app.clic2up.com"
#define MyAppExeName "clic2up-sign.exe"

; Dossier contenant l'app-image generee par jpackage
#define AppImageDir "..\dist\clic2up-sign"

[Setup]
AppId={{E7A3F2B1-4D5C-4E6F-8A9B-1C2D3E4F5A6B}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
OutputDir=..\dist
OutputBaseFilename=clic2up-sign-setup
SetupIconFile=clic2up-sign.ico
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=lowest
UsedUserAreasWarning=no
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible

; Infos affichees dans l'installeur
LicenseFile=
InfoBeforeFile=info-avant.txt

[Languages]
Name: "french"; MessagesFile: "compiler:Languages\French.isl"

[Tasks]
Name: "desktopicon"; Description: "Creer un raccourci sur le Bureau"; GroupDescription: "Raccourcis :"
Name: "autostart"; Description: "Lancer automatiquement au demarrage de Windows"; GroupDescription: "Options :"

[Files]
; Copier toute l'app-image jpackage
Source: "{#AppImageDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
; Icone de l'application
Source: "clic2up-sign.ico"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
; Menu Demarrer
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Parameters: "server --port 9876"; IconFilename: "{app}\clic2up-sign.ico"; Comment: "Service de signature electronique"
Name: "{group}\Desinstaller {#MyAppName}"; Filename: "{uninstallexe}"

; Bureau
Name: "{userdesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Parameters: "server --port 9876"; IconFilename: "{app}\clic2up-sign.ico"; Tasks: desktopicon; Comment: "Service de signature electronique"

; Demarrage automatique
Name: "{userstartup}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Parameters: "server --port 9876"; IconFilename: "{app}\clic2up-sign.ico"; Tasks: autostart

[Run]
; Rafraichir le cache d'icones Windows
Filename: "ie4uinit.exe"; Parameters: "-show"; Flags: runhidden nowait
; Lancer apres l'installation
Filename: "{app}\{#MyAppExeName}"; Parameters: "server --port 9876"; Description: "Lancer {#MyAppName} maintenant"; Flags: nowait postinstall skipifsilent shellexec

[UninstallRun]
; Tuer le processus avant desinstallation
Filename: "taskkill"; Parameters: "/F /IM {#MyAppExeName}"; Flags: runhidden; RunOnceId: "KillApp"

[UninstallDelete]
Type: filesandordirs; Name: "{app}"

[Code]
// Verifier si une instance est deja en cours d'execution avant l'installation
function InitializeSetup(): Boolean;
var
  ResultCode: Integer;
begin
  Result := True;
  // Tuer l'ancien processus s'il tourne
  Exec('taskkill', '/F /IM ' + '{#MyAppExeName}', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

// Message personnalise a la fin
procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssDone then
  begin
    MsgBox('clic2up-sign a ete installe avec succes !' + #13#10 + #13#10 +
           'Vous pouvez maintenant signer vos factures depuis clic2up.',
           mbInformation, MB_OK);
  end;
end;
