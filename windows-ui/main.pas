unit Main;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, Forms, Controls, Graphics, Dialogs, StdCtrls, ExtCtrls, Menus,
  IniFiles, dynlibs, process, LCLType;

type

  { TForm1 }

  TForm1 = class(TForm)
    btnConnect: TButton;
    edtServer: TEdit;
    edtUser: TEdit;
    edtPass: TEdit;
    lblServer: TLabel;
    lblUser: TLabel;
    lblPass: TLabel;
    lblStatus: TLabel;
    MenuItemExit: TMenuItem;
    PopupMenu1: TPopupMenu;
    Timer1: TTimer;
    TrayIcon1: TTrayIcon;
    procedure btnConnectClick(Sender: TObject);
    procedure FormCloseQuery(Sender: TObject; var CanClose: Boolean);
    procedure FormCreate(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure MenuItemExitClick(Sender: TObject);
    procedure Timer1Timer(Sender: TObject);
    procedure TrayIcon1DblClick(Sender: TObject);
  private
    FIsConnected: Boolean;
    FTrueExit: Boolean;
    FTempDir: String;
    FDLLHandle: TLibHandle;
    procedure UpdateStatus;
    procedure ExtractResources;
    procedure LoadDLL;
    procedure LoadConfig;
    procedure SaveConfig;
    procedure ForceKillGhostService;
  public

  end;

var
  Form1: TForm1;

// DLL Function Pointers
type
  TWgLogin = function(username, password, server_url: PAnsiChar): Integer; stdcall;
  TWgLogout = function(): Integer; stdcall;
  TWgGetStatus = function(out_status: PAnsiChar; max_len: Integer): Integer; stdcall;
  TWgSetInsecure = procedure(insecure: Integer); stdcall;

var
  WgLogin: TWgLogin = nil;
  WgLogout: TWgLogout = nil;
  WgGetStatus: TWgGetStatus = nil;
  WgSetInsecure: TWgSetInsecure = nil;

{$R *.lfm}
{$R resources.rc}

implementation

{ TForm1 }

procedure TForm1.ForceKillGhostService;
var
  AProcess: TProcess;
begin
  // Quietly uninstall any existing ghost wg-vpn service on startup
  AProcess := TProcess.Create(nil);
  try
    AProcess.Executable := FTempDir + 'wireguard.exe';
    AProcess.Parameters.Add('/uninstalltunnelservice');
    AProcess.Parameters.Add('wg-vpn');
    AProcess.Options := [poWaitOnExit, poNoConsole];
    AProcess.Execute;
  except
    // ignore
  end;
  AProcess.Free;
end;

procedure TForm1.ExtractResources;
var
  ResStream: TResourceStream;
  GUID: TGUID;
  GUIDStr: String;
begin
  // Use a random unique directory to prevent DLL planting attacks
  CreateGUID(GUID);
  GUIDStr := GUIDToString(GUID);
  // Remove braces from GUID string
  GUIDStr := StringReplace(GUIDStr, '{', '', [rfReplaceAll]);
  GUIDStr := StringReplace(GUIDStr, '}', '', [rfReplaceAll]);
  FTempDir := GetTempDir(False) + 'AuthWG_' + GUIDStr + PathDelim;
  ForceDirectories(FTempDir);

  // Extract authwg.dll - always overwrite
  try
    // Delete old file if it exists
    if FileExists(FTempDir + 'authwg.dll') then
      DeleteFile(FTempDir + 'authwg.dll');
    ResStream := TResourceStream.Create(HInstance, 'AUTHWG_DLL', RT_RCDATA);
    try
      ResStream.SaveToFile(FTempDir + 'authwg.dll');
    finally
      ResStream.Free;
    end;
  except
    on E: Exception do
    begin
      ShowMessage('Failed to extract authwg.dll: ' + E.Message);
      Application.Terminate;
      Exit;
    end;
  end;

  // Extract wireguard.exe - always overwrite
  try
    if FileExists(FTempDir + 'wireguard.exe') then
      DeleteFile(FTempDir + 'wireguard.exe');
    ResStream := TResourceStream.Create(HInstance, 'WIREGUARD_EXE', RT_RCDATA);
    try
      ResStream.SaveToFile(FTempDir + 'wireguard.exe');
    finally
      ResStream.Free;
    end;
  except
    on E: Exception do
    begin
      ShowMessage('Failed to extract wireguard.exe: ' + E.Message);
      Application.Terminate;
      Exit;
    end;
  end;
end;

procedure TForm1.LoadDLL;
begin
  FDLLHandle := LoadLibrary(FTempDir + 'authwg.dll');
  if FDLLHandle <> 0 then
  begin
    Pointer(WgLogin) := GetProcAddress(FDLLHandle, 'WgLogin');
    Pointer(WgLogout) := GetProcAddress(FDLLHandle, 'WgLogout');
    Pointer(WgGetStatus) := GetProcAddress(FDLLHandle, 'WgGetStatus');
    Pointer(WgSetInsecure) := GetProcAddress(FDLLHandle, 'WgSetInsecure');
  end
  else
  begin
    ShowMessage('Critical Error: Failed to load authwg.dll from temp directory!');
    Application.Terminate;
  end;
end;

procedure TForm1.LoadConfig;
var
  Ini: TIniFile;
begin
  Ini := TIniFile.Create(ExtractFilePath(Application.ExeName) + 'config.ini');
  try
    edtServer.Text := Ini.ReadString('Auth', 'Server', 'https://198.51.100.1:8443');
    edtUser.Text := Ini.ReadString('Auth', 'Username', '');

  finally
    Ini.Free;
  end;
end;

procedure TForm1.SaveConfig;
var
  Ini: TIniFile;
begin
  Ini := TIniFile.Create(ExtractFilePath(Application.ExeName) + 'config.ini');
  try
    Ini.WriteString('Auth', 'Server', edtServer.Text);
    Ini.WriteString('Auth', 'Username', edtUser.Text);

  finally
    Ini.Free;
  end;
end;

procedure TForm1.FormCreate(Sender: TObject);
begin
  FIsConnected := False;
  FTrueExit := False;
  
  TrayIcon1.Icon.Assign(Application.Icon);
  
  ExtractResources;
  ForceKillGhostService;
  LoadDLL;
  LoadConfig;

  Timer1.Interval := 1000;
  Timer1.Enabled := True;
end;

procedure TForm1.FormDestroy(Sender: TObject);
begin
  if FDLLHandle <> 0 then
    UnloadLibrary(FDLLHandle);
  // Clean up temp directory
  if FTempDir <> '' then
  begin
    DeleteFile(FTempDir + 'authwg.dll');
    DeleteFile(FTempDir + 'wireguard.exe');
    RemoveDir(FTempDir);
  end;
end;

procedure TForm1.UpdateStatus;
var
  StatusBuf: array[0..255] of Char;
  StatusStr: String;
begin
  if not Assigned(WgGetStatus) then Exit;

  if WgGetStatus(StatusBuf, SizeOf(StatusBuf)) = 0 then
  begin
    StatusStr := StrPas(StatusBuf);
    lblStatus.Caption := 'Status: ' + StatusStr;

    if (Pos('Connected', StatusStr) > 0) and (Pos('Disconnecting', StatusStr) = 0) then
    begin
      FIsConnected := True;
      btnConnect.Caption := 'Disconnect';
      edtServer.Enabled := False;
      edtUser.Enabled := False;
      edtPass.Enabled := False;
      lblStatus.Font.Color := clGreen;
    end
    else
    begin
      FIsConnected := False;
      btnConnect.Caption := 'Connect';
      edtServer.Enabled := True;
      edtUser.Enabled := True;
      edtPass.Enabled := True;
      if Pos('Error', StatusStr) > 0 then
        lblStatus.Font.Color := clRed
      else if Pos('Failed', StatusStr) > 0 then
        lblStatus.Font.Color := clRed
      else
        lblStatus.Font.Color := clGray;
    end;
  end;
end;

procedure TForm1.btnConnectClick(Sender: TObject);
var
  Res: Integer;
begin
  if not Assigned(WgLogin) then Exit;

  if not FIsConnected then
  begin
    if (edtServer.Text = '') or (edtUser.Text = '') then
    begin
      ShowMessage('Please fill in server and username.');
      Exit;
    end;

    SaveConfig;

    lblStatus.Caption := 'Status: Connecting...';
    lblStatus.Font.Color := clBlue;
    Application.ProcessMessages;

    Res := WgLogin(PAnsiChar(edtUser.Text), PAnsiChar(edtPass.Text), PAnsiChar(edtServer.Text));
    if Res < 0 then
    begin
      UpdateStatus; 
    end;
  end
  else
  begin
    WgLogout();
  end;
end;

procedure TForm1.Timer1Timer(Sender: TObject);
begin
  try
    UpdateStatus;
  except
  end;
end;

procedure TForm1.FormCloseQuery(Sender: TObject; var CanClose: Boolean);
begin
  if not FTrueExit then
  begin
    CanClose := False;
    Hide;
    TrayIcon1.ShowBalloonHint;
  end
  else
    CanClose := True;
end;

procedure TForm1.MenuItemExitClick(Sender: TObject);
begin
  FTrueExit := True;
  if FIsConnected and Assigned(WgLogout) then
  begin
    WgLogout();
  end;
  Application.Terminate;
end;

procedure TForm1.TrayIcon1DblClick(Sender: TObject);
begin
  Show;
  WindowState := wsNormal;
  BringToFront;
end;

end.
