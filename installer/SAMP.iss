; SAMP installer – Inno Setup 6.4 or newer (https://jrsoftware.org/isinfo.php).
; Build:  installer\build.ps1   (compiles with ISCC.exe)   ->  artifacts\SAMP-Setup-<version>.exe
; UNVERIFIED: this script has never been compiled or run in the development environment (Inno Setup is Windows-only).

#if VER < EncodeVer(6, 4, 0)
  #error This script needs Inno Setup 6.4 or newer.
#endif

#ifndef Version
  #define Version "1.0.0"
#endif
#ifndef PublishDir
  #define PublishDir "..\artifacts\publish"
#endif

[Setup]
; AppId must never change: it identifies the installation for upgrades and uninstall.
AppId={{6B8E1F3A-52C4-4D8B-9E37-0A1D5C7F2B94}
AppName=SAMP - USB Access Manager
AppVersion={#Version}
AppPublisher=SAMP
DefaultDirName={autopf}\SAMP
DisableProgramGroupPage=yes
DisableDirPage=auto
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
OutputDir=..\artifacts
OutputBaseFilename=SAMP-Setup-{#Version}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
SetupLogging=yes
UninstallDisplayName=SAMP - USB Access Manager
UninstallDisplayIcon={app}\SAMP.exe
; We stop and remove our own services and UI explicitly (see PrepareToInstall), so no Restart Manager prompts.
CloseApplications=no
RestartIfNeededByRun=no

[Files]
Source: "{#PublishDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\SAMP"; Filename: "{app}\SAMP.exe"

[Registry]
; Start the (unprivileged) UI at every logon for the tray icon and countdown.
Root: HKLM; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "SAMP"; \
  ValueData: """{app}\SAMP.exe"""; Flags: uninsdeletevalue

[Run]
Filename: "{app}\SAMP.exe"; Description: "Start SAMP now"; Flags: nowait postinstall skipifsilent runasoriginaluser

[Code]
const
  UninstallKey = 'Software\Microsoft\Windows\CurrentVersion\Uninstall\{6B8E1F3A-52C4-4D8B-9E37-0A1D5C7F2B94}_is1';
  MainService = 'SAMPService';
  MonitorService = 'SAMPMonitor';
  GuardExe = 'SAMP.UninstallGuard.exe';
  { Exit codes of SAMP.UninstallGuard.exe }
  GuardOk = 0;
  GuardWrong = 1;
  GuardLocked = 2;
  GuardUnreachable = 3;

var
  PasswordPage: TInputQueryWizardPage;
  MaintenanceOpen: Boolean;      { the service accepted the uninstall password }

{ ---------- helpers ---------------------------------------------------------------------------------------- }

function RunHidden(const FileName, Params: String): Integer;
var
  Code: Integer;
begin
  if not Exec(FileName, Params, '', SW_HIDE, ewWaitUntilTerminated, Code) then
    Code := -1;
  Log(FileName + ' ' + Params + ' -> ' + IntToStr(Code));
  Result := Code;
end;

function Sc(const Params: String): Integer;
begin
  Result := RunHidden(ExpandConstant('{sys}\sc.exe'), Params);
end;

function ServiceInstalled(const Name: String): Boolean;
begin
  { sc query: 0 = exists, 1060 = ERROR_SERVICE_DOES_NOT_EXIST }
  Result := Sc('query ' + Name) <> 1060;
end;

function ExistingAppDir: String;
begin
  if not RegQueryStringValue(HKLM, UninstallKey, 'Inno Setup: App Path', Result) then
    Result := '';
end;

function ParamOrEmpty(const Name: String): String;
begin
  Result := ExpandConstant('{param:' + Name + '|}');
end;

{ Reads /UNINSTPASSWORDFILE=<file> (preferred) or /UNINSTPASSWORD=<pw> for silent runs. }
function SilentPassword: String;
var
  FileName: String;
  Lines: TArrayOfString;
begin
  Result := '';
  FileName := ParamOrEmpty('UNINSTPASSWORDFILE');
  if (FileName <> '') and LoadStringsFromFile(FileName, Lines) and (GetArrayLength(Lines) > 0) then
    Result := Lines[0]
  else
    Result := ParamOrEmpty('UNINSTPASSWORD');
end;

procedure ShowError(const Msg: String);
begin
  SuppressibleMsgBox(Msg, mbError, MB_OK, IDOK);
end;

{ Asks the service to open a maintenance window. The password is handed over in a temporary file, never on a command line. }
function BeginMaintenance(const GuardPath, Password: String): Boolean;
var
  PwFile: String;
  Lines: TArrayOfString;
  Code: Integer;
begin
  Result := False;
  if not FileExists(GuardPath) then
  begin
    ShowError('The existing SAMP installation is damaged (the protection helper is missing), so the password cannot be checked.' + #13#10 +
              'Repair is not possible without it. Contact the administrator.');
    Exit;
  end;
  if Password = '' then
  begin
    ShowError('The uninstall password is required.');
    Exit;
  end;

  PwFile := ExpandConstant('{tmp}\samp-pw.tmp');
  SetArrayLength(Lines, 1);
  Lines[0] := Password;
  if not SaveStringsToUTF8File(PwFile, Lines, False) then
  begin
    ShowError('Could not prepare the password check.');
    Exit;
  end;

  Code := RunHidden(GuardPath, '--begin-maintenance --password-file "' + PwFile + '" --ui 2');
  DeleteFile(PwFile);   { the guard already wiped and deleted it; this is a safety net }

  if Code = GuardOk then
    Result := True
  else if Code = GuardWrong then
    ShowError('The uninstall password is incorrect.')
  else if Code = GuardLocked then
    ShowError('Too many wrong attempts. Try again in 15 minutes.')
  else if Code = GuardUnreachable then
    ShowError('The SAMP service is not running, so the password cannot be checked.' + #13#10 +
              'Start the "SAMP USB Access Service" service and try again.')
  else
    ShowError('The password check failed (code ' + IntToStr(Code) + ').');
end;

procedure StopAndRemoveServices;
begin
  { Disable first so the two services cannot restart each other while we stop them. }
  Sc('config ' + MainService + ' start= disabled');
  Sc('config ' + MonitorService + ' start= disabled');
  RunHidden(ExpandConstant('{sys}\net.exe'), 'stop ' + MonitorService);   { net stop waits until the service has stopped }
  RunHidden(ExpandConstant('{sys}\net.exe'), 'stop ' + MainService);
  Sc('delete ' + MonitorService);
  Sc('delete ' + MainService);
  RunHidden(ExpandConstant('{sys}\taskkill.exe'), '/F /IM SAMP.exe');
end;

procedure CreateService(const Name, DisplayName, Description, ExeName: String);
begin
  { Escaped quotes keep the quotes in the stored image path (paths with spaces). }
  Sc('create ' + Name + ' binPath= "\"' + ExpandConstant('{app}') + '\' + ExeName + '\"" start= auto obj= LocalSystem DisplayName= "' + DisplayName + '"');
  Sc('description ' + Name + ' "' + Description + '"');
  { Restart on every failure after 5 s; reset the failure count after one day. }
  Sc('failure ' + Name + ' reset= 86400 actions= restart/5000/restart/5000/restart/5000');
end;

{ ---------- install / upgrade ------------------------------------------------------------------------------ }

procedure InitializeWizard;
begin
  PasswordPage := CreateInputQueryPage(wpWelcome, 'Protected installation',
    'SAMP is already installed and protected.',
    'Enter the uninstall password to update or reinstall SAMP.');
  PasswordPage.Add('Uninstall password:', True);
end;

function ShouldSkipPage(PageID: Integer): Boolean;
begin
  Result := (PageID = PasswordPage.ID) and (ExistingAppDir = '');
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;
  if CurPageID = PasswordPage.ID then
  begin
    MaintenanceOpen := BeginMaintenance(ExistingAppDir + '\' + GuardExe, PasswordPage.Values[0]);
    PasswordPage.Values[0] := '';
    Result := MaintenanceOpen;
  end;
end;

function InitializeSetup: Boolean;
var
  Dir: String;
begin
  Result := True;
  Dir := ExistingAppDir;
  { Silent upgrades have no password page, so take the password from /UNINSTPASSWORDFILE= or /UNINSTPASSWORD=. }
  if (Dir <> '') and WizardSilent then
  begin
    MaintenanceOpen := BeginMaintenance(Dir + '\' + GuardExe, SilentPassword);
    Result := MaintenanceOpen;
  end;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := '';
  if ServiceInstalled(MainService) or ServiceInstalled(MonitorService) then
  begin
    if not MaintenanceOpen then
    begin
      Result := 'SAMP is installed and protected. The uninstall password was not accepted, so it cannot be changed.';
      Exit;
    end;
    StopAndRemoveServices;
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    CreateService(MainService, 'SAMP USB Access Service',
      'Enforces USB storage policy and the automatic re-block timer.', 'SAMP.Service.exe');
    CreateService(MonitorService, 'SAMP Device Monitor',
      'Records USB device connections for the SAMP tamper-evident log.', 'SAMP.Monitor.exe');
    Sc('start ' + MainService);
    Sc('start ' + MonitorService);
  end;
end;

{ ---------- uninstall -------------------------------------------------------------------------------------- }

function AskPassword(var Password: String): Boolean;
var
  Form: TSetupForm;
  Prompt: TNewStaticText;
  Edit: TPasswordEdit;
  OkButton, CancelButton: TNewButton;
begin
  Form := CreateCustomForm(ScaleX(400), ScaleY(165), False, True);
  try
    Form.Caption := 'SAMP - protected uninstall';
    Form.Position := poScreenCenter;

    Prompt := TNewStaticText.Create(Form);
    Prompt.Parent := Form;
    Prompt.Left := ScaleX(16);
    Prompt.Top := ScaleY(16);
    Prompt.Width := ScaleX(368);
    Prompt.AutoSize := False;
    Prompt.WordWrap := True;
    Prompt.Height := ScaleY(36);
    Prompt.Caption := 'SAMP is protected. Enter the uninstall password to remove it.';

    Edit := TPasswordEdit.Create(Form);
    Edit.Parent := Form;
    Edit.Left := ScaleX(16);
    Edit.Top := ScaleY(66);
    Edit.Width := ScaleX(368);

    OkButton := TNewButton.Create(Form);
    OkButton.Parent := Form;
    OkButton.Caption := 'Uninstall';
    OkButton.Left := ScaleX(216);
    OkButton.Top := ScaleY(116);
    OkButton.Width := ScaleX(80);
    OkButton.Height := ScaleY(26);
    OkButton.ModalResult := mrOk;
    OkButton.Default := True;

    CancelButton := TNewButton.Create(Form);
    CancelButton.Parent := Form;
    CancelButton.Caption := 'Cancel';
    CancelButton.Left := ScaleX(304);
    CancelButton.Top := ScaleY(116);
    CancelButton.Width := ScaleX(80);
    CancelButton.Height := ScaleY(26);
    CancelButton.ModalResult := mrCancel;
    CancelButton.Cancel := True;

    Form.ActiveControl := Edit;
    Result := Form.ShowModal = mrOk;
    if Result then
      Password := Edit.Text;
  finally
    Form.Free;
  end;
end;

function InitializeUninstall: Boolean;
var
  Password: String;
  Guard: String;
begin
  Result := False;
  Guard := ExpandConstant('{app}\' + GuardExe);

  if UninstallSilent then
    Password := SilentPassword
  else if not AskPassword(Password) then
    Exit;                                 { user cancelled }

  { Returning False aborts the uninstall before anything has been touched. }
  MaintenanceOpen := BeginMaintenance(Guard, Password);
  Password := '';
  Result := MaintenanceOpen;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then
  begin
    StopAndRemoveServices;
    { Take the PC out of lock-down: delete our device policy and re-enable devices we disabled. }
    RunHidden(ExpandConstant('{app}\' + GuardExe), '--restore-policy');
  end;
end;
