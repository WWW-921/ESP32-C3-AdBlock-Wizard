program ESP32AdBlockWizard;

{$IFDEF FPC}{$MODE DELPHIUNICODE}{$CODEPAGE UTF8}{$ENDIF}
{$APPTYPE GUI}
{$IFDEF EMBEDDED}{$R payload.res}{$ENDIF}

uses Windows, Messages, SysUtils, Classes, ShellApi, CommCtrl, CommDlg;

function ChooseFileW(var D: TOpenFilenameW): BOOL; stdcall; external 'comdlg32.dll' name 'GetOpenFileNameW';
type TBlob=record Size:DWORD;Data:Pointer;end;
function Unprotect(var Input:TBlob;Description:Pointer;Entropy,Reserved,Prompt:Pointer;Flags:DWORD;var Output:TBlob):BOOL;stdcall;external 'crypt32.dll' name 'CryptUnprotectData';

const WM_JOBDONE = WM_APP+10;
type
  TWorker = class(TThread)
  public
    RequestFile, ResultFile, LogFile, Action, Password: UnicodeString;
    Code: DWORD;
    ErrorText: UnicodeString;
    procedure Execute; override;
  end;

var Main: HWND; Pages: array[0..4] of HWND; Nav: array[0..4] of HWND;
  PortBox, DeviceBox, GatewayBox, PassBox, PlanBox, OutputBox, StatusBox: HWND;
  AppFont, HeadFont: HFONT; Busy: Boolean=False; ActivePage: Integer=0;
  RuntimeDir, StateDir: UnicodeString;
  ActiveWorker: TWorker;
  OldPageProc: Pointer;
  UIScale: Double=1.0;

function Px(Value:Integer):Integer;
begin Result:=Round(Value*UIScale);end;

function PageProc(H:HWND;Msg:UINT;WP:WPARAM;LP:LPARAM):LRESULT;stdcall;
begin
 if Msg=WM_COMMAND then Result:=SendMessage(Main,Msg,WP,LP)
 else Result:=CallWindowProcW(OldPageProc,H,Msg,WP,LP);
end;

function U(const S: UnicodeString): PWideChar;
begin Result:=PWideChar(S); end;

function TextOf(H: HWND): UnicodeString;
var N: Integer;
begin N:=GetWindowTextLengthW(H); SetLength(Result,N+1); GetWindowTextW(H,U(Result),N+1);SetLength(Result,N);end;

procedure Put(H: HWND; const S: UnicodeString);
begin SetWindowTextW(H,U(S));end;

function ReadUTF8(const FileName: UnicodeString): UnicodeString;
var F:TFileStream; B:UTF8String;
begin F:=TFileStream.Create(FileName,fmOpenRead or fmShareDenyNone);try SetLength(B,F.Size);if Length(B)>0 then F.ReadBuffer(B[1],Length(B));Result:=UTF8Decode(B);finally F.Free;end;end;

procedure WriteUTF8(const FileName, Value: UnicodeString);
var F:TFileStream; B:UTF8String;
begin B:=UTF8Encode(Value);F:=TFileStream.Create(FileName,fmCreate);try if Length(B)>0 then F.WriteBuffer(B[1],Length(B));finally F.Free;end;end;

function ReadResult(const FileName:UnicodeString):UnicodeString;
var F:TFileStream;B:RawByteString;Input,Output:TBlob;D:UTF8String;
begin
 F:=TFileStream.Create(FileName,fmOpenRead or fmShareDenyNone);
 try SetLength(B,F.Size);if Length(B)>0 then F.ReadBuffer(B[1],Length(B));finally F.Free;end;
 if Copy(B,1,6)<>'DPAPI1' then raise Exception.Create('操作结果未加密，已拒绝读取。');
 Input.Size:=Length(B)-6;Input.Data:=@B[7];FillChar(Output,SizeOf(Output),0);
 if not Unprotect(Input,nil,nil,nil,nil,1,Output) then RaiseLastOSError;
 try SetLength(D,Output.Size);if Output.Size>0 then Move(Output.Data^,D[1],Output.Size);Result:=UTF8Decode(D);finally LocalFree(HLOCAL(Output.Data));end;
end;

function EscapeJSON(const S: UnicodeString): UnicodeString;
var I:Integer;C:WideChar;
begin
 Result:='';for I:=1 to Length(S) do begin C:=S[I];case C of
  '"':Result:=Result+'\"'; '\':Result:=Result+'\\';
  #8:Result:=Result+'\b';#9:Result:=Result+'\t';#10:Result:=Result+'\n';#13:Result:=Result+'\r';
  else if Ord(C)<32 then Result:=Result+'\u'+IntToHex(Ord(C),4) else Result:=Result+C;
 end;end;
end;

function Field(const K,V:UnicodeString):UnicodeString;
begin Result:='"'+K+'":"'+EscapeJSON(V)+'"';end;

function Control(const Kind, Caption: UnicodeString; Style: DWORD; X,Y,W,H:Integer; Parent:HWND; Id:Integer=0):HWND;
begin
 Result:=CreateWindowExW(0,U(Kind),U(Caption),WS_CHILD or WS_VISIBLE or Style,Px(X),Px(Y),Px(W),Px(H),Parent,HMENU(Id),HInstance,nil);
 SendMessage(Result,WM_SETFONT,WPARAM(AppFont),1);
end;

procedure LabelAt(Parent:HWND;const S:UnicodeString;X,Y,W,H:Integer);
begin Control('STATIC',S,0,X,Y,W,H,Parent);end;

function ButtonAt(Parent:HWND;const S:UnicodeString;Id,X,Y,W:Integer):HWND;
begin Result:=Control('BUTTON',S,WS_TABSTOP or BS_PUSHBUTTON,X,Y,W,34,Parent,Id);end;

procedure OpenURL(const URL:UnicodeString);
begin ShellExecuteW(Main,'open',U(URL),nil,nil,SW_SHOWNORMAL);end;

function BrowseBackup(const Filter: UnicodeString):UnicodeString;
var D:TOpenFilenameW;B:array[0..2047] of WideChar;F:UnicodeString;
begin
 Result:='';FillChar(D,SizeOf(D),0);FillChar(B,SizeOf(B),0);F:=Filter;
 D.lStructSize:=SizeOf(D);D.hwndOwner:=Main;D.lpstrFilter:=U(F);D.lpstrFile:=@B[0];D.nMaxFile:=Length(B);D.Flags:=OFN_FILEMUSTEXIST or OFN_PATHMUSTEXIST or OFN_NOCHANGEDIR;
 if ChooseFileW(D) then Result:=UnicodeString(B);
end;

procedure ExtractResource(const Name,FileName:UnicodeString);
var R:TResourceStream;
begin
 {$IFDEF EMBEDDED}
 R:=TResourceStream.Create(HInstance,Name,RT_RCDATA);try R.SaveToFile(FileName);finally R.Free;end;
 {$ELSE}
 if not FileExists(FileName) then raise Exception.Create('开发模式缺少组件：'+FileName);
 {$ENDIF}
end;

procedure PrepareRuntime;
var B:array[0..2047] of WideChar;
begin
 GetEnvironmentVariableW('LOCALAPPDATA',@B[0],Length(B));StateDir:=UnicodeString(B)+'\ESP32AdBlockWizard\';
 RuntimeDir:=StateDir+'1.0\';ForceDirectories(RuntimeDir+'firmware');ForceDirectories(StateDir+'jobs');ForceDirectories(StateDir+'logs');
 ExtractResource('ENGINE',RuntimeDir+'engine.exe');
 ExtractResource('BOOT',RuntimeDir+'firmware\bootloader.bin');
 ExtractResource('PARTITIONS',RuntimeDir+'firmware\partitions.bin');
 ExtractResource('OTA',RuntimeDir+'firmware\boot_app0.bin');
 ExtractResource('APP',RuntimeDir+'firmware\firmware.bin');
 ExtractResource('FILESYSTEM',RuntimeDir+'firmware\littlefs.bin');
 ExtractResource('FWMANIFEST',RuntimeDir+'firmware\manifest.json');
end;

procedure TWorker.Execute;
var SI:Windows.TStartupInfoW;PI:Windows.TProcessInformation;Cmd:UnicodeString;
 SA:Windows.TSecurityAttributes;ReadPipe,WritePipe:THandle;Bytes:DWORD;Secret:UTF8String;
begin
 Code:=1;ReadPipe:=0;WritePipe:=0;
 try
  FillChar(SA,SizeOf(SA),0);SA.nLength:=SizeOf(SA);SA.bInheritHandle:=True;
  if not CreatePipe(ReadPipe,WritePipe,@SA,0) then RaiseLastOSError;
  SetHandleInformation(WritePipe,HANDLE_FLAG_INHERIT,0);
  FillChar(SI,SizeOf(SI),0);SI.cb:=SizeOf(SI);FillChar(PI,SizeOf(PI),0);
  SI.dwFlags:=STARTF_USESTDHANDLES;SI.hStdInput:=ReadPipe;
  Cmd:='"'+RuntimeDir+'engine.exe" --secret-stdin --protect-result --request "'+RequestFile+'" --result "'+ResultFile+'" --log "'+LogFile+'"';
  UniqueString(Cmd);
  if not CreateProcessW(nil,U(Cmd),nil,nil,True,CREATE_NO_WINDOW,nil,U(RuntimeDir),SI,PI) then RaiseLastOSError;
  CloseHandle(ReadPipe);ReadPipe:=0;
  try
   Secret:=UTF8Encode(Password);if Length(Secret)>0 then WriteFile(WritePipe,Secret[1],Length(Secret),Bytes,nil);
   Password:='';Secret:='';CloseHandle(WritePipe);WritePipe:=0;
   WaitForSingleObject(PI.hProcess,INFINITE);GetExitCodeProcess(PI.hProcess,Code);
  finally CloseHandle(PI.hThread);CloseHandle(PI.hProcess);end;
 except on E:Exception do ErrorText:=E.Message;end;
 if ReadPipe<>0 then CloseHandle(ReadPipe);if WritePipe<>0 then CloseHandle(WritePipe);
 PostMessage(Main,WM_JOBDONE,0,LPARAM(Self));
end;

procedure StartJob(const Action:UnicodeString; Confirmed:Boolean=False);
var W:TWorker;Id,S:UnicodeString;
begin
 if Busy then Exit;
 if (Action='flash') or (Action='probe') or (Action='serial') then
  if Trim(TextOf(PortBox))='' then begin MessageBoxW(Main,'请先选择或填写串口。','需要串口',MB_OK or MB_ICONINFORMATION);Exit;end;
 Id:=IntToHex(GetTickCount,8)+'-'+IntToHex(GetCurrentProcessId,8);
 S:='{'+Field('action',Action)+','+Field('port',Trim(TextOf(PortBox)))+','+Field('device',Trim(TextOf(DeviceBox)))+','+Field('gateway',Trim(TextOf(GatewayBox)))+','+Field('plan',TextOf(PlanBox))+',';
 if Confirmed then S:=S+'"confirmed":true}' else S:=S+'"confirmed":false}';
 W:=TWorker.Create(True);W.FreeOnTerminate:=False;W.Action:=Action;
 if (Action='preview') or (Action='apply') or (Action='restore') then W.Password:=TextOf(PassBox);
 W.RequestFile:=StateDir+'jobs\'+Id+'.request';W.ResultFile:=StateDir+'jobs\'+Id+'.result';W.LogFile:=StateDir+'logs\'+Id+'.log';
 try WriteUTF8(W.RequestFile,S);except W.Free;raise;end;
 Busy:=True;ActiveWorker:=W;Put(StatusBox,'正在执行，请稍候。刷写过程中不要拔出 USB，也不要关闭窗口。');Put(OutputBox,'处理中……');SetTimer(Main,1,800,nil);W.Start;
end;

procedure Finished(W:TWorker);
var S:UnicodeString;Lines:TStringList;I:Integer;L:UnicodeString;
begin
 KillTimer(Main,1);Busy:=False;ActiveWorker:=nil;
 try
  S:=W.ErrorText;if FileExists(W.ResultFile) then S:=ReadResult(W.ResultFile);
  if S='' then S:='操作引擎未返回结果，请重试环境检查。';
  Lines:=TStringList.Create;try Lines.Text:=S;
   for I:=Lines.Count-1 downto 0 do begin
    L:=Lines[I];
    if Copy(L,1,8)='@device=' then begin Put(DeviceBox,Copy(L,9,MaxInt));Lines.Delete(I);end
    else if Copy(L,1,9)='@gateway=' then begin Put(GatewayBox,Copy(L,10,MaxInt));Lines.Delete(I);end
    else if Copy(L,1,6)='@plan=' then begin Put(PlanBox,Copy(L,7,MaxInt));Lines.Delete(I);end;
   end;
   Put(OutputBox,Lines.Text);
  finally Lines.Free;end;
  if W.Code=0 then Put(StatusBox,'本项操作完成。请根据结果继续下一步。') else Put(StatusBox,'本项尚未通过，请查看结果中的原因。');
  if (W.Action='apply') or (W.Action='restore') then Put(PassBox,'');
 finally
  DeleteFileW(U(W.RequestFile));DeleteFileW(U(W.ResultFile));W.Free;
 end;
end;

procedure ShowPage(N:Integer);
var I:Integer;
begin
 ActivePage:=N;
 for I:=0 to 4 do begin ShowWindow(Pages[I],SW_HIDE);EnableWindow(Nav[I],True);end;
 ShowWindow(Pages[N],SW_SHOW);EnableWindow(Nav[N],False);
end;

procedure BuildUI;
var I:Integer;P:HWND;Names:array[0..4] of UnicodeString;B:array[0..255] of WideChar;Port:UnicodeString;
begin
 AppFont:=CreateFontW(-Px(17),0,0,0,FW_NORMAL,0,0,0,DEFAULT_CHARSET,0,0,5,0,'Microsoft YaHei UI');
 HeadFont:=CreateFontW(-Px(25),0,0,0,FW_SEMIBOLD,0,0,0,DEFAULT_CHARSET,0,0,5,0,'Microsoft YaHei UI');
 P:=Control('STATIC','ESP32 广告过滤 · 安装向导',0,24,16,700,38,Main);SendMessage(P,WM_SETFONT,WPARAM(HeadFont),1);
 LabelAt(Main,'家庭网络助手  /  ESP32-C3 · 4MB · DIO 40MHz',25,57,900,25);
 Names[0]:='1  准备';Names[1]:='2  刷写';Names[2]:='3  配网';Names[3]:='4  路由器';Names[4]:='5  验收';
 for I:=0 to 4 do Nav[I]:=ButtonAt(Main,Names[I],10+I,24+I*197,92,185);
 LabelAt(Main,'串口',24,145,45,25);PortBox:=Control('COMBOBOX','',WS_TABSTOP or CBS_DROPDOWN or WS_VSCROLL,70,140,130,220,Main,200);
 for I:=1 to 64 do begin Port:='COM'+IntToStr(I);if QueryDosDeviceW(U(Port),@B[0],Length(B))>0 then SendMessageW(PortBox,CB_ADDSTRING,0,LPARAM(U(Port)));end;
 if SendMessage(PortBox,CB_GETCOUNT,0,0)>0 then SendMessage(PortBox,CB_SETCURSEL,0,0);
 LabelAt(Main,'设备 IP',235,145,70,25);DeviceBox:=Control('EDIT','',WS_BORDER or WS_TABSTOP or ES_AUTOHSCROLL,312,140,190,29,Main,201);
 ButtonAt(Main,'打开设备面板',103,530,138,150);
 for I:=0 to 4 do begin
  Pages[I]:=CreateWindowExW(WS_EX_CONTROLPARENT,'STATIC','',WS_CHILD,Px(24),Px(184),Px(970),Px(232),Main,0,HInstance,nil);
  if I=0 then OldPageProc:=Pointer(SetWindowLongPtrW(Pages[I],GWLP_WNDPROC,LONG_PTR(@PageProc)))
  else SetWindowLongPtrW(Pages[I],GWLP_WNDPROC,LONG_PTR(@PageProc));
 end;
 P:=Pages[0];
 LabelAt(P,'准备一块 ESP32-C3（4MB Flash）和支持数据传输的 USB 线。',8,5,930,28);
 LabelAt(P,'工具先识别硬件并备份原固件，之后再写入通用固件。用户无需安装 Python。',8,38,940,28);
 LabelAt(P,'不要重复刷写已经正常运行的设备；可直接进入“配网 / 路由器 / 验收”。',8,72,940,28);
 LabelAt(P,'过滤范围：独立广告和追踪域名。不能可靠去除 YouTube 片头及视频内嵌广告。',8,106,940,28);
 ButtonAt(P,'检查环境与网络',101,8,156,200);ButtonAt(P,'发现已联网设备',105,228,156,200);
 P:=Pages[1];
 LabelAt(P,'插入开发板，选择上方串口。先识别芯片，再备份与刷写。',8,5,930,28);
 LabelAt(P,'仅支持 ESP32-C3 / 4MB。备份失败、固件校验失败或型号不符时自动停止。',8,40,940,28);
 LabelAt(P,'原固件保存到本机 AppData\Local\ESP32AdBlockWizard\backups。',8,75,940,28);
 LabelAt(P,'若无法连接，关闭其它串口软件；按住 BOOT，按一下 RESET，再松开 BOOT。',8,110,940,28);
 ButtonAt(P,'识别芯片',106,8,158,160);ButtonAt(P,'备份并刷写',107,188,158,190);ButtonAt(P,'打开备份目录',115,398,158,190);
 P:=Pages[2];
 LabelAt(P,'① USB 仍连接电脑时，读取设备热点名称和每台设备独立的管理密码。',8,5,940,28);
 LabelAt(P,'② 打开 Windows Wi-Fi，用读取到的 ap_password 连接 C3-AdBlock-* 热点。',8,40,940,28);
 LabelAt(P,'③ 在配网页输入家庭 2.4GHz Wi-Fi 和密码。不要选择仅 5GHz 的网络。',8,75,940,28);
 LabelAt(P,'④ 配网后，电脑重新连接家庭 Wi-Fi，点击“发现设备”自动填写设备 IP。',8,110,940,28);
 ButtonAt(P,'读取设备信息',108,8,158,175);ButtonAt(P,'打开 Wi-Fi 设置',109,198,158,175);ButtonAt(P,'打开配网页',110,388,158,175);ButtonAt(P,'发现设备',105,578,158,160);
 P:=Pages[3];
 LabelAt(P,'小米自动配置：先预览，核对备份与变更，再确认应用。其它路由器使用手动引导。',8,2,940,28);
 LabelAt(P,'网关 IP',8,43,100,25);GatewayBox:=Control('EDIT','',WS_BORDER or WS_TABSTOP or ES_AUTOHSCROLL,115,38,190,29,P,202);
 LabelAt(P,'路由器管理密码',330,43,150,25);PassBox:=Control('EDIT','',WS_BORDER or WS_TABSTOP or ES_PASSWORD or ES_AUTOHSCROLL,490,38,250,29,P,203);SendMessageW(PassBox,EM_SETPASSWORDCHAR,Ord('*'),0);
 LabelAt(P,'配置备份',8,85,100,25);PlanBox:=Control('EDIT','',WS_BORDER or WS_TABSTOP or ES_AUTOHSCROLL,115,80,625,29,P,204);ButtonAt(P,'选择备份',116,755,78,170);
 ButtonAt(P,'登录并预览',111,8,133,175);ButtonAt(P,'确认应用',112,198,133,175);ButtonAt(P,'恢复原 DNS',113,388,133,175);ButtonAt(P,'手动配置引导',114,578,133,175);
 LabelAt(P,'保存 DHCP 设置可能短暂断网。不会修改上网方式、网段或关闭 DHCP。',8,181,930,28);
 P:=Pages[4];
 LabelAt(P,'① 从电脑移到路由器 USB 口供电；USB 仅供电，设备通过 Wi-Fi 工作。',8,5,940,28);
 LabelAt(P,'② 更新 DHCP 租约，或让手机、电脑、电视重新连接家庭 Wi-Fi。',8,40,940,28);
 LabelAt(P,'③ 完整验收同时检查规则、广告拦截、正常域名和本机实际 DNS。',8,75,940,28);
 LabelAt(P,'使用私人 DNS、VPN、浏览器安全 DNS 的客户端可能绕过过滤。',8,110,940,28);
 ButtonAt(P,'更新网络租约',117,8,158,200);ButtonAt(P,'执行完整验收',118,228,158,200);ButtonAt(P,'打开诊断报告目录',119,448,158,220);
 LabelAt(Main,'操作结果（管理密码只显示在此窗口，不写入操作日志）',24,422,950,25);
 OutputBox:=Control('EDIT','欢迎使用。请选择第 1 步，或直接检查已经安装好的设备。',WS_BORDER or WS_VSCROLL or ES_MULTILINE or ES_READONLY or ES_AUTOVSCROLL,24,450,970,176,Main,210);
 StatusBox:=Control('STATIC','就绪',0,24,638,970,28,Main);
 ShowPage(0);
end;

function WindowProc(H:HWND;Msg:UINT;WP:WPARAM;LP:LPARAM):LRESULT;stdcall;
var Id:Integer;W:TWorker;S:UnicodeString;
begin
 Result:=0;
 try
 case Msg of
 WM_CREATE:begin Main:=H;BuildUI;end;
 WM_COMMAND:begin
  Id:=LOWORD(WP);
  if (Id>=10) and (Id<=14) then begin if not Busy then ShowPage(Id-10);Exit;end;
  if Busy then Exit;
  case Id of
   101:StartJob('inspect');105:StartJob('discover');106:StartJob('probe');108:StartJob('serial');
   107:if MessageBoxW(Main,'将完整备份该开发板，然后擦除并写入通用广告过滤固件。请确认选对串口，且不要拔出 USB。继续？','确认刷写',MB_YESNO or MB_ICONWARNING or MB_DEFBUTTON2)=IDYES then StartJob('flash',True);
   103:begin if Trim(TextOf(DeviceBox))='' then MessageBoxW(Main,'请先发现或填写设备 IP。','设备 IP',MB_OK) else OpenURL('http://'+Trim(TextOf(DeviceBox))+'/');end;
   109:OpenURL('ms-settings:network-wifi');110:OpenURL('http://192.168.4.1/');
   111:StartJob('preview');
   112:if MessageBoxW(Main,'请先核对预览内容。将应用 IP 绑定与 DHCP DNS 设置，可能短暂断网。确认修改？','确认路由器变更',MB_YESNO or MB_ICONWARNING or MB_DEFBUTTON2)=IDYES then StartJob('apply',True);
   113:if MessageBoxW(Main,'将还原选定备份中的 DNS。保留现有网段、租约和设备 IP 绑定。继续？','确认恢复 DNS',MB_YESNO or MB_ICONWARNING or MB_DEFBUTTON2)=IDYES then StartJob('restore',True);
   114:Put(OutputBox,'手动配置：'+#13#10+'1. 将设备 MAC 与上方设备 IP 做 DHCP 静态绑定。MAC 可在“发现设备”结果中查看。'+#13#10+'2. 局域网 / DHCP 的 DNS1 填设备 IP，DNS2 留空。默认网关保持原样。'+#13#10+'3. 若局域网没有 DNS 字段，在“上网设置”中查找手动 DNS；保持原上网方式。'+#13#10+'4. 保存后让客户端重新连接 Wi-Fi，进入第 5 步验收。IPv6 DNS 也需要核对。');
   115:OpenURL(StateDir+'backups');
   116:begin S:=BrowseBackup('路由器备份 (*.json)'#0'*.json'#0#0);if S<>'' then Put(PlanBox,S);end;
   117:if MessageBoxW(Main,'将更新本机 DHCP 租约，可能短暂中断网络。其它设备请自行重新连接 Wi-Fi。继续？','更新网络',MB_YESNO or MB_DEFBUTTON2)=IDYES then StartJob('renew');
   118:StartJob('diagnose');119:OpenURL(StateDir+'reports');
  end;
 end;
 WM_TIMER:begin if Busy then begin
  // Read only the safe phase log; credential-bearing results are loaded at completion.
  if (ActiveWorker<>nil) and FileExists(ActiveWorker.LogFile) then
   try Put(OutputBox,ReadUTF8(ActiveWorker.LogFile));except end;
  Put(StatusBox,'正在执行……请勿关闭窗口。');
 end;end;
 WM_JOBDONE:begin W:=TWorker(Pointer(LP));Finished(W);end;
 WM_CLOSE:begin if Busy then begin MessageBoxW(Main,'当前操作仍在执行，刷写时关闭可能损坏设备。请等待完成。','请等待',MB_OK or MB_ICONINFORMATION);Exit;end;DestroyWindow(Main);end;
 WM_DESTROY:begin DeleteObject(AppFont);DeleteObject(HeadFont);PostQuitMessage(0);end;
 else Result:=DefWindowProcW(H,Msg,WP,LP);
 end;
 except on E:Exception do MessageBoxW(Main,U(E.Message),'操作提示',MB_OK or MB_ICONERROR);end;
end;

var WC:TWndClassW;Msg:TMsg;Init:TInitCommonControlsEx;TestWorker:TWorker;TestResult:UnicodeString;Area:TRect;
begin
 if (ParamCount>0) and (ParamStr(1)='--self-test') then begin
  if EscapeJSON('a"b\c'+#10)<>'a\"b\\c\n' then Halt(2);
  if ParamCount>1 then if ReadResult(ParamStr(2))<>'中文 DPAPI roundtrip' then Halt(3);
  Halt(0);
 end;
 try
  PrepareRuntime;
  if (ParamCount>0) and (ParamStr(1)='--engine-test') then begin
   TestWorker:=TWorker.Create(True);
   TestWorker.RequestFile:=StateDir+'jobs\integration.request';
   TestWorker.ResultFile:=StateDir+'jobs\integration.result';
   TestWorker.LogFile:=StateDir+'logs\integration.log';
   WriteUTF8(TestWorker.RequestFile,'{"action":"inspect"}');
   TestWorker.Start;TestWorker.WaitFor;
   if TestWorker.ErrorText<>'' then Halt(4);
   if TestWorker.Code<>0 then Halt(5);
   TestResult:=ReadResult(TestWorker.ResultFile);
   DeleteFileW(U(TestWorker.ResultFile));
   TestWorker.Free;
   if Pos('"firmware": "1.0"',TestResult)=0 then Halt(6);
   Halt(0);
  end;
  Init.dwSize:=SizeOf(Init);Init.dwICC:=ICC_STANDARD_CLASSES;InitCommonControlsEx(Init);
  if not SystemParametersInfoW(SPI_GETWORKAREA,0,@Area,0) then begin Area.Left:=0;Area.Top:=0;Area.Right:=GetSystemMetrics(SM_CXSCREEN);Area.Bottom:=GetSystemMetrics(SM_CYSCREEN);end;
  if Area.Right-Area.Left-20<1040 then UIScale:=(Area.Right-Area.Left-20)/1040;
  if (Area.Bottom-Area.Top-20)/720<UIScale then UIScale:=(Area.Bottom-Area.Top-20)/720;
  FillChar(WC,SizeOf(WC),0);WC.lpfnWndProc:=@WindowProc;WC.hInstance:=HInstance;WC.hCursor:=LoadCursor(0,IDC_ARROW);WC.hbrBackground:=COLOR_WINDOW+1;WC.lpszClassName:='ESP32WizardNative';RegisterClassW(WC);
  Main:=CreateWindowExW(0,WC.lpszClassName,'ESP32 广告过滤安装向导 1.0',WS_OVERLAPPED or WS_CAPTION or WS_SYSMENU or WS_MINIMIZEBOX,Area.Left+(Area.Right-Area.Left-Px(1040)) div 2,Area.Top+(Area.Bottom-Area.Top-Px(720)) div 2,Px(1040),Px(720),0,0,HInstance,nil);
  if Main=0 then RaiseLastOSError;
  ShowWindow(Main,SW_SHOWNORMAL);UpdateWindow(Main);
  while GetMessageW(Msg,0,0,0) do begin if not IsDialogMessageW(Main,Msg) then begin TranslateMessage(Msg);DispatchMessageW(Msg);end;end;
 except on E:Exception do begin MessageBoxW(0,U(E.Message),'无法启动',MB_OK or MB_ICONERROR);Halt(1);end;end;
end.
