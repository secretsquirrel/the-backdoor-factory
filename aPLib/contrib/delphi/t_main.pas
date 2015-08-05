unit t_main;

interface

uses
  Windows, Messages, SysUtils, Classes, Graphics, Controls, Forms, Dialogs,
  aPLib, ExtCtrls, StdCtrls, ComCtrls;

type
  TfrmMain = class(TForm)
    aPLib: TaPLib;
    Button1: TButton;
    Button2: TButton;
    Panel1: TPanel;
    OD: TOpenDialog;
    GroupBox1: TGroupBox;
    PB: TProgressBar;
    Label3: TLabel;
    Label4: TLabel;
    Label1: TLabel;
    Label2: TLabel;
    Label5: TLabel;
    CancelBtn: TButton;
    procedure Button1Click(Sender: TObject);
    procedure Button2Click(Sender: TObject);
    procedure CancelBtnClick(Sender: TObject);
  private
    { Private declarations }
  public
    Cancel   : Boolean;
    FileSize : DWORD;
  end;

(*$IFDEF DYNAMIC_VERSION*)
  function CallBack(w0, w1, w2 : DWORD; cbparam : Pointer) : DWORD;stdcall;
(*$ELSE*)
  function CallBack(w0, w1, w2 : DWORD; cbparam : Pointer) : DWORD;cdecl;
(*$ENDIF*)

var
  frmMain: TfrmMain;

implementation

{$R *.DFM}

function CallBack(w0, w1, w2 : DWORD; cbparam : Pointer) : DWORD;
begin
  with frmMain do
  begin
    Label4.Caption := FormatFloat('##%', ((FileSize - (w1-w2))/FileSize) * 100);
    PB.Position    := Round(w1/FileSize*100);

    Application.ProcessMessages;

    if Cancel then Result := aP_pack_break
              else Result := aP_pack_continue;
  end;
end;

procedure TfrmMain.Button1Click(Sender: TObject);
var
  FileIn,
  FileOut : TFileStream;
  Length  : DWORD;
  Buffer  : Pointer;
begin
  if not OD.Execute then Exit;

  FileIn := TFileStream.Create(OD.FileName,fmOpenRead or fmShareDenyWrite);
  GetMem(Buffer, FileIn.Size);
  Length := FileIn.Size;
  FileIn.Read(Buffer^, Length);

  aPLib.Source   := Buffer;
  aPLib.Length   := Length;

  aPlib.CallBack := @CallBack;

  FileSize          := FileIn.Size;
  Cancel            := False;
  CancelBtn.Enabled := True;

  aPLib.Pack;

  FileIn.Destroy;

  if aPLib.Length = 0 then Exit;

  FileOut := TFileStream.Create(ExtractFilePath(OD.FileName)+'out.apk', fmCreate);
  FileOut.Write(aPLib.Destination^, aPLib.Length);
  FileOut.Destroy;

  CancelBtn.Enabled := False;

  ShowMessage('Packed file name is out.apk !');

end;

procedure TfrmMain.Button2Click(Sender: TObject);
var
  FileIn,
  FileOut : TFileStream;
  Length  : DWORD;
  Buffer  : Pointer;
begin
  if not OD.Execute then Exit;

  FileIn := TFileStream.Create(OD.FileName,fmOpenRead or fmShareDenyWrite);
  GetMem(Buffer, Length);
  Length := FileIn.Size;
  FileIn.Read(Buffer^, Length);

  aPLib.Source := Buffer;
  aPLib.Length := Length;

  aPLib.DePack;

  FileIn.Destroy;

  FileOut := TFileStream.Create(ExtractFilePath(OD.FileName)+'out.dat', fmCreate or fmOpenWrite);
  FileOut.Write(aPLib.Destination^, aPLib.Length);
  FileOut.Destroy;

  ShowMessage('Original file name is out.dat !');
end;

procedure TfrmMain.CancelBtnClick(Sender: TObject);
begin
  Cancel := True;
end;

end.
