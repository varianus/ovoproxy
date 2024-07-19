program ovoproxy;

{$mode objfpc}{$H+}

uses {$IFDEF UNIX}
  cthreads,
  baseunix, {$ENDIF}
  syncobjs,
  Classes,
  IdContext,
  IdGlobal,
  IdSchedulerOfThreadPool,
  IdHTTPProxyServer,
  inifiles,
  EventLog,
  base64,
  indylaz,
  SysUtils,
  types,
  interfaces;

type
  ComputedNet = record
    dwMaskedNet: uint32;
    dwMask: uint32;
    Allow: boolean;
  end;

  { TOvoProxy }

  TOvoProxy = class
  private
    Stopped: TEventObject;
    ThreadPool: TIdSchedulerOfThreadPool;
    FProxy: TIdHTTPProxyServer;
    sa, osa: sigactionrec;
    Ini: TIniFile;
    IPRules: array of ComputedNet;
    Users: TStringDynArray;
    HaveDenyRules, HaveAllowRules, HaveAuthentication: boolean;
    procedure OnConnect(AContext: TIdContext);
    procedure OnHTTPBeforeCommand(AContext: TIdHTTPProxyServerContext);
    procedure RegisterSignalHandler;
  public
    constructor Create;
    destructor Destroy; override;
    procedure Run;
    procedure Stop;
    procedure LoadConfig;
    procedure Reload;
  end;

var
  Proxy: TOvoProxy;
  Log: TEventLog;


  function GetNetMask(AIPRange: string): ComputedNet;
  var
    dwNet, dwMask: uint32;
    sTmpRange, sTmp: string;
    Err: boolean;
  begin
    Result.dwMaskedNet := 0;
    Result.dwMask := $ffffffff;

    if Pos('/', AIPRange) = 0 then
      sTmpRange := AIPRange + '/32'
    else
      sTmpRange := AIPRange;
    sTmp := Copy(sTmpRange, 1, Pos('/', sTmpRange) - 1);
    dwNet := IPv4ToUInt32(sTmp, Err);
    if (not err) and (dwnet <> 0) then
    begin
      // get the mask from the range
      sTmp := Copy(sTmpRange, Pos('/', sTmpRange) + 1, 2);
      dwMask := DWORD(StrToIntDef(sTmp, 32));
      dwMask := not ((1 shl (32 - dwMask)) - 1);
      Result.dwMaskedNet := (dwNet and dwMask);
      Result.dwMask := dwMask;
    end;
  end;

  procedure handleSigTerm(signum: cInt; siginfo: psiginfo; sigcontext: psigcontext); cdecl;
  begin
    case signum of
      SIGTERM:
      begin
        Proxy.Stop;
      end;
      SIGHUP:
      begin
        Proxy.Reload;
      end
      else
        Log.Info('Get signal ' + IntToStr(signum));
    end;

  end;

  { TOvoProxy }

  procedure TOvoProxy.RegisterSignalHandler;

    procedure installhandler(aSig: cInt);
    var
      new: SigactionRec;
      res: cint;
    begin

      fpsigemptyset(new.sa_mask);
      new.sa_flags := 0;
      New.sa_handler := sigactionhandler(@handleSigTerm);
      res := fpSigaction(aSig, @New, nil);
    end;

  begin
    installhandler(SIGTERM);
    installhandler(SIGHUP);

  end;



  constructor TOvoProxy.Create;
  begin
    RegisterSignalHandler;
    Stopped := TEventObject.Create(nil, False, False, 'OvoProxyStopped');
    Stopped.ResetEvent;
    ThreadPool := TIdSchedulerOfThreadPool.Create(nil);
    ThreadPool.PoolSize := 10;
    ThreadPool.MaxThreads := 0;
    FProxy := TIdHTTPProxyServer.Create(nil);
    FProxy.DefaultPort := 8118;
    FProxy.DefaultTransferMode := tmStreaming;
    FProxy.Scheduler := ThreadPool;
    fproxy.OnConnect := @OnConnect;
    FProxy.OnHTTPBeforeCommand := @OnHTTPBeforeCommand;

  end;

  destructor TOvoProxy.Destroy;
  begin
    if Assigned(FProxy) then
    begin
      FProxy.Active := False;
      FProxy.Free;
    end;
    ThreadPool.Free;
    inherited Destroy;
  end;

  procedure TOvoProxy.OnHTTPBeforeCommand(
    AContext: TIdHTTPProxyServerContext);
  var
    ValidUser: boolean;
    Header: string;
    i: SizeInt;
  begin
    if HaveAuthentication then
    begin
      ValidUser := False;
      if AContext.Headers.IndexOfName('Proxy-Authorization') > 0 then
      begin
        Header := AContext.Headers.Values['Proxy-Authorization'];
        if Header.StartsWith('Basic') then
        begin
          Header := Header.Substring(6);
          for i := 0 to Length(Users) - 1 do
            if Users[i] = Header then
            begin
              ValidUser := True;
              Break;
            end;
        end;
      end;
      if not ValidUser then
      begin
        AContext.Connection.IOHandler.WriteLn('HTTP/1.1 407 Proxy Authentication Required'); {do not localize}
        AContext.Connection.IOHandler.WriteLn('Proxy-Authenticate: Basic realm="ovoproxy"'); {do not localize}
        AContext.Connection.IOHandler.WriteLn;
        abort;
      end;

    end;

  end;

  procedure TOvoProxy.OnConnect(AContext: TIdContext);
  var
    dwIP: uint32;
    Err: boolean;
    Allowed: boolean;
    i: integer;
  begin
    if not (HaveAllowRules or HaveDenyRules) then
      Exit;
    dwIP := IPv4ToUInt32(AContext.Connection.Socket.Binding.PeerIP, Err);
    Allowed := (not err) and (dwip <> 0);
    if Allowed and HaveAllowRules then
    begin
      Allowed := False;
      for i := 0 to Length(IPRules) - 1 do
        if IPRules[i].Allow then
        begin
          Allowed := (dwIP and IPRules[i].dwMask) = IPRules[i].dwMaskedNet;
          if Allowed then Break;
        end;
    end;

    if Allowed and HaveDenyRules then
    begin
      for i := 0 to Length(IPRules) - 1 do
        if not IPRules[i].Allow then
        begin
          Allowed := not ((dwIP and IPRules[i].dwMask) = IPRules[i].dwMaskedNet);
          if not Allowed then
          begin
            //log.info ('ip   '+ IntToHex(dwip));
            //log.info ('mask '+ IntToHex(IPRules[i].dwMaskedNet));
            //log.info ('res  '+ IntToHex(dwIP and IPRules[i].dwMask));
            Break;
          end;
        end;
    end;

    if not Allowed then
    begin
      Log.Warning('Reject connection from ' + AContext.Connection.Socket.Binding.PeerIP);
      begin
        //AContext.Connection.IOHandler.WriteLn('HTTP/1.0 403 Connection refused'); {do not localize}
        //AContext.Connection.IOHandler.WriteLn('Proxy-agent: OvoProxy/1.1'); {do not localize}
        //AContext.Connection.IOHandler.WriteLn;
        AContext.Connection.Disconnect;

      end;

    end;

  end;

  procedure TOvoProxy.Run;
  begin
    Log.Info('Starting ovoproxy on port ' + IntToStr(FProxy.DefaultPort));
    FProxy.Active := True;
    while Stopped.WaitFor(1000) = wrTimeout do ;
    FProxy.Active := False;
  end;

  procedure TOvoProxy.Stop;
  begin
    Log.Info('Got Stop event');
    Stopped.SetEvent;

  end;

  procedure TOvoProxy.LoadConfig;
  var
    Values: TStringList;
    i: integer;
    offset, j: integer;
    str, FConfigFile: string;
  begin

    FConfigFile := '';
    if ParamCount > 0 then
      FConfigFile := ParamStr(1);

    if not FileExists(FConfigFile) then
    begin
      FConfigFile := GetAppConfigFile(False, True);
      FConfigFile := ChangeFileExt(FConfigFile, '.conf');
    end;
  //  log.Info('try config from '+FConfigFile);

    if not FileExists(FConfigFile) then
    begin
      FConfigFile := '/etc/ovoproxy.conf';
    end;
    log.Info('Reading config from '+FConfigFile);
    Ini := TIniFile.Create(FConfigFile, [ifoStripComments, ifoStripInvalid]);
    Log.active := False;
    str := lowercase(Ini.ReadString('Config', 'LogType', 'syslog'));
    if str = 'syslog' then
      log.LogType := ltSystem
    else
    if str = 'logfile' then
    begin
      log.LogType := ltFile;
      log.FileName := Ini.ReadString('Config', 'LogFile', '/var/log/ovoproxy.log');
      ForceDirectories(ExtractFileDir(log.filename));
    end
    else
      log.logtype := ltStdOut;
    Log.Active := True;

    fProxy.DefaultPort := ini.ReadInteger('Network', 'DefaultPort', 8118);

    Values := TStringList.Create;
    ini.ReadSectionValues('Allow', Values);
    SetLength(IPRules, Values.Count);
    for i := 0 to Values.Count - 1 do
    begin
      IPRules[i] := GetNetMask(Values.ValueFromIndex[i]);
      IPRules[i].Allow := True;
      HaveAllowRules := True;
      ;
    end;

    Offset := Length(IPRules);
    ini.ReadSectionValues('Deny', Values);
    SetLength(IPRules, Offset + Values.Count);
    for i := 0 to Values.Count - 1 do
    begin
      IPRules[Offset + i] := GetNetMask(Values.ValueFromIndex[i]);
      IPRules[Offset + i].Allow := False;
      HaveDenyRules := True;
    end;

    Values.Clear;
    ini.ReadSectionValues('Authorization', Values);
    HaveAuthentication:= Values.Count > 0;
    SetLength(Users, Values.Count);
    j:=0;
    for i := 0 to Values.Count - 1 do
    begin
      if Pos(':', Values.Names[i] ) > 0 then
        log.Error('Invalid user name "%s"',[Values.Names[i]])
      else
        begin
         Users[j] := EncodeStringBase64(Values.Names[i] + ':' + Values.ValueFromIndex[i]);
         inc(j)
        end;
    end;
    SetLength(Users,j);
    Values.Free;
    Log.info('Loaded config');

  end;

  procedure TOvoProxy.Reload;
  begin
    Log.Info('Reloading config');
    FProxy.Active := False;
    LoadConfig;
    Log.Info('Starting ovoproxy on port ' + IntToStr(FProxy.DefaultPort));
    FProxy.Active := True;
  end;

begin
  Log := TEventLog.Create(nil);
  // Log.LogType := ltStdOut;
  Log.LogType := ltSystem;
  Proxy := TOvoProxy.Create;
  Proxy.LoadConfig;
  Proxy.Run;
  Proxy.Free;
  Log.Info('ovoproxy successfully stopped');
  Log.active := False;
  Log.Free;
end.
