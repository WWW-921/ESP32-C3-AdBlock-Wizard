"""Local operation engine. No telemetry; request files are deleted after reading."""
import argparse, contextlib, concurrent.futures, ctypes, hashlib, io, ipaddress
import json, os, pathlib, re, secrets, socket, struct, subprocess, sys, time
import urllib.parse
import requests

ROOT = pathlib.Path(sys.executable if getattr(sys,'frozen',False) else __file__).resolve().parent
STATE = pathlib.Path(os.environ.get('LOCALAPPDATA',str(pathlib.Path.home()))) / 'ESP32AdBlockWizard'
LOG = None
RFC1918 = [ipaddress.ip_network(x) for x in ['10.0.0.0/8','172.16.0.0/12','192.168.0.0/16']]
EXPECTED_IMAGES={'bootloader.bin':0,'partitions.bin':0x8000,'boot_app0.bin':0xe000,'firmware.bin':0x10000,'littlefs.bin':0x2f0000}

def log(s):
    if LOG:
        with LOG.open('a',encoding='utf-8') as f:f.write(time.strftime('%H:%M:%S ')+s+'\n')

def private_ip(value):
    ip=ipaddress.IPv4Address(value.strip())
    if not any(ip in n for n in RFC1918):raise ValueError('仅支持家庭/局域网 IPv4 地址。')
    return str(ip)

def redact(s,values):
    for k,v in values.items():
        if any(x in k.lower() for x in ['pass','token','nonce']) and isinstance(v,str) and v:s=s.replace(v,'[已隐藏]')
    return re.sub(r';stok=[a-fA-F0-9]+',';stok=[已隐藏]',s)

def validate_chip(name,size):
    if name!='ESP32-C3' or size!=4194304:raise ValueError('此固件仅适用于 ESP32-C3 / 4MB Flash，已停止写入。')

def verify_images(directory):
    directory=pathlib.Path(directory);m=json.loads((directory/'manifest.json').read_text(encoding='utf-8'))
    for item in m['images']:
        name=item['file']
        if pathlib.Path(name).name!=name:raise ValueError('固件清单包含无效文件名。')
        p=directory/name
        if hashlib.sha256(p.read_bytes()).hexdigest()!=item['sha256']:raise ValueError('固件校验失败：'+name)
        if not 0<=int(item['offset'])<4194304 or item['offset']+p.stat().st_size>4194304:raise ValueError('固件地址越界。')
    return m

def dhcp_change(info,device):
    ip=ipaddress.IPv4Address(private_ip(device));lan=info['lanIp'][0]
    net=ipaddress.IPv4Network(lan['ip']+'/'+lan['mask'],strict=False)
    if net.prefixlen!=24 or len(info['lanIp'])!=1:raise ValueError('自动配置仅支持单个 /24 家庭网段；请改用手动引导。')
    if ip not in net or ip in [net.network_address,net.broadcast_address,ipaddress.IPv4Address(lan['ip'])]:raise ValueError('设备 IP 与路由器网段不匹配或存在地址冲突。')
    if str(info.get('ignore'))!='0':raise ValueError('路由器未开启 DHCP，自动配置已停止。')
    start=int(info['start']);limit=int(info['limit']);end=start+limit-1
    if not 1<=start<=end<=254 or not re.fullmatch(r'\d+[mhd]',str(info['leasetime'])):raise ValueError('无法识别当前 DHCP 范围或租约。')
    return {'start':start,'end':end,'limit':limit,'leasetime':info['leasetime'],'ignore':'0','dns1':str(ip),'dns2':'','router':info.get('router','')}

def dns_packet(name,qtype,tid):
    return struct.pack('!6H',tid,0x100,1,0,0,0)+b''.join(bytes([len(x)])+x.encode('ascii') for x in name.split('.'))+b'\0'+struct.pack('!HH',qtype,1)

def dns_answers(b,tid):
    if len(b)<12:raise ValueError('DNS 响应不完整。')
    ident,flags,qd,an,ns,ar=struct.unpack('!6H',b[:12])
    if ident!=tid or not flags&0x8000 or flags&15 or flags&0x200 or qd!=1:raise ValueError('DNS 响应事务、状态或长度异常。')
    def skip(p):
        for _ in range(128):
            if p>=len(b):raise ValueError('DNS 名称越界。')
            n=b[p];p+=1
            if n==0:return p
            if n&192==192:
                if p>=len(b):raise ValueError('DNS 指针越界。')
                return p+1
            if n>63 or p+n>len(b):raise ValueError('DNS 标签无效。')
            p+=n
        raise ValueError('DNS 名称过长。')
    p=skip(12)+4;answers=[]
    if p>len(b):raise ValueError('DNS 问题不完整。')
    for _ in range(an):
        p=skip(p)
        if p+10>len(b):raise ValueError('DNS 记录不完整。')
        typ,cls,ttl,n=struct.unpack('!HHIH',b[p:p+10]);p+=10
        if p+n>len(b):raise ValueError('DNS 数据不完整。')
        if typ==1 and n==4:answers.append(socket.inet_ntop(socket.AF_INET,b[p:p+n]))
        if typ==28 and n==16:answers.append(socket.inet_ntop(socket.AF_INET6,b[p:p+n]))
        p+=n
    return answers

def dns_test(ip,name,qtype=1):
    ip=private_ip(ip) if ip!='127.0.0.1' else ip
    for attempt in range(3):
        tid=secrets.randbelow(65536)
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
            s.settimeout(2)
            try:
                s.sendto(dns_packet(name,qtype,tid),(ip,53));b,peer=s.recvfrom(4096)
                if peer[0]!=ip:raise ValueError('DNS 响应地址不一致。')
                return dns_answers(b,tid)
            except (socket.timeout,OSError):
                if attempt==2:raise ValueError('DNS 查询超时：'+name)

def ps(script):
    # Every script is application-owned; user values never become PowerShell code.
    wrapped="[Console]::OutputEncoding=[Text.UTF8Encoding]::new();"+script
    p=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',wrapped],capture_output=True,timeout=40,creationflags=0x08000000)
    if p.returncode:raise ValueError('读取 Windows 网络配置失败。')
    return p.stdout.decode('utf-8-sig','replace').strip()

def network():
    raw=ps("$a=@(Get-NetIPConfiguration | Where-Object {$_.IPv4DefaultGateway} | ForEach-Object {[pscustomobject]@{name=$_.InterfaceAlias;index=$_.InterfaceIndex;ip=$_.IPv4Address.IPAddress;gateway=$_.IPv4DefaultGateway.NextHop;dns=@($_.DNSServer.ServerAddresses)}});ConvertTo-Json -InputObject $a -Compress -Depth 4")
    rows=json.loads(raw or '[]')
    return rows if isinstance(rows,list) else [rows]

def http_session():
    s=requests.Session();s.trust_env=False
    return s

def stats(ip):
    ip=private_ip(ip)
    r=http_session().get('http://'+ip+'/stats.json',timeout=3,allow_redirects=False)
    if r.status_code!=200 or len(r.content)>262144:raise ValueError('无法读取 ESP32 状态。')
    d=r.json()
    if not isinstance(d,dict) or not {'domains','blocking','heap','ip','blocked','allowed'}<=d.keys():raise ValueError('目标不是兼容的 C3 AdBlock 设备。')
    return d

def device_check(ip):
    d=stats(ip)
    if int(d['domains'])<=0 or not d['blocking']:raise ValueError('设备未加载规则或已暂停过滤。')
    tests={}
    for name in ['doubleclick.net','pagead2.googlesyndication.com']:
        tests[name]=dns_test(ip,name)
        if tests[name]!=['0.0.0.0']:raise ValueError('广告域名未被屏蔽：'+name)
    tests['doubleclick.net/AAAA']=dns_test(ip,'doubleclick.net',28)
    if tests['doubleclick.net/AAAA']:raise ValueError('广告 IPv6 记录未被屏蔽。')
    for name in ['www.baidu.com','github.com']:
        tests[name]=dns_test(ip,name)
        if not tests[name] or '0.0.0.0' in tests[name]:raise ValueError('正常域名解析失败：'+name)
    return {'domains':d['domains'],'ip':ip,'tests':tests}

def mac_address(ip):
    ip=private_ip(ip);buf=ctypes.create_string_buffer(6);n=ctypes.c_ulong(6)
    dest=struct.unpack('<I',socket.inet_aton(ip))[0]
    if ctypes.windll.iphlpapi.SendARP(dest,0,buf,ctypes.byref(n))!=0:raise ValueError('无法取得设备 MAC；请确认电脑与设备在同一局域网。')
    return ':'.join(f'{x:02X}' for x in buf.raw[:6])

def espcmd(args,timeout=60):
    prefix=[sys.executable,'--esptool'] if getattr(sys,'frozen',False) else [sys.executable,str(pathlib.Path(__file__).resolve()),'--esptool']
    p=subprocess.run(prefix+args,capture_output=True,timeout=timeout,creationflags=0x08000000)
    text=(p.stdout+p.stderr).decode('utf-8','replace')
    if p.returncode:raise ValueError('串口操作失败。请检查 USB 数据线、串口占用与 BOOT 键。\n'+text[-1800:])
    return text

def probe(port):
    if not re.fullmatch(r'COM\d{1,3}',port.upper()):raise ValueError('请输入正确串口，例如 COM3。')
    t=espcmd(['--port',port,'flash-id'])
    m=re.search(r'Chip type:\s*(ESP32[-A-Za-z0-9]*)',t);f=re.search(r'Detected flash size:\s*(\d+)MB',t)
    if not m or not f:raise ValueError('无法确认芯片与 Flash 容量，停止刷写。')
    validate_chip(m.group(1),int(f.group(1))*1024*1024)
    mac=re.search(r'MAC:\s*([0-9a-f:]{17})',t,re.I)
    return {'chip':m.group(1),'flash':int(f.group(1))*1024*1024,'mac':mac.group(1) if mac else ''}

def flash(req):
    if req.get('confirmed') is not True:raise ValueError('刷写需要用户确认。')
    m=verify_images(ROOT/'firmware')
    if m.get('chip')!='ESP32-C3' or m.get('flash_bytes')!=4194304 or len(m['images'])!=5 or {i['file']:i['offset'] for i in m['images']}!=EXPECTED_IMAGES:raise ValueError('固件包不完整或不是受支持的 C3 分区布局。')
    port=req['port'];log('识别芯片与容量');d=probe(port)
    folder=STATE/'backups';folder.mkdir(parents=True,exist_ok=True)
    backup=folder/('flash-'+time.strftime('%Y%m%d-%H%M%S')+'-'+secrets.token_hex(3)+'.bin')
    log('读取完整 4MB 原固件备份，请勿拔出 USB')
    espcmd(['--port',port,'--baud','460800','read-flash','0','0x400000',str(backup)],120)
    if backup.stat().st_size!=4194304:raise ValueError('原固件备份长度错误；未开始擦除。')
    (backup.with_suffix('.sha256')).write_text(hashlib.sha256(backup.read_bytes()).hexdigest(),encoding='ascii')
    log('备份完成；开始擦除并写入通用固件')
    espcmd(['--port',port,'erase-flash'],90)
    args=['--chip','esp32c3','--port',port,'--baud','460800','write-flash','--flash-mode','dio','--flash-freq','40m','--flash-size','4MB']
    for item in m['images']:args.extend([hex(item['offset']),str(ROOT/'firmware'/item['file'])])
    t=espcmd(args,180)
    if t.count('Hash of data verified')!=len(m['images']):raise ValueError('写入校验不完整；备份保留于 '+str(backup))
    log('全部镜像写入校验通过')
    return '刷写完成。原固件备份：'+str(backup)+'\n请进入第 3 步读取设备的配网热点和独立密码。'

def serial_info(port):
    import serial
    if not re.fullmatch(r'COM\d{1,3}',port.upper()):raise ValueError('串口无效。')
    log('读取启动信息，最多等待 35 秒')
    data=bytearray()
    with serial.Serial(port,115200,timeout=.3) as s:
        s.dtr=False;s.rts=False;end=time.monotonic()+40;sent=0
        while time.monotonic()<end:
            if time.monotonic()-sent>2:s.write(b'WIZARD_INFO\n');sent=time.monotonic()
            data.extend(s.read(4096))
            if b'[wizard] info_end' in data:break
    t=data.decode('utf-8','replace')
    # Passwords are shown only in the transient result, never written into operation logs.
    useful=[x.strip() for x in t.splitlines() if any(k in x for k in ['[wizard]','[setup]','WiFi up:','blocklist:','DNS :53'])]
    if not useful:raise ValueError('没有读取到兼容固件信息；请确认串口，按一下 RESET 后重试。')
    return '\n'.join(useful)+'\n\n配网步骤：使用上方 ap_password 连接 C3-AdBlock-* 热点，打开 http://192.168.4.1 输入家庭 2.4GHz Wi-Fi；保存后重新连接家庭 Wi-Fi，再点击发现设备。'

def discover():
    nets=network();candidates=[]
    try:candidates.append(socket.gethostbyname('c3adblock.local'))
    except OSError:pass
    for n in nets:
        ips=n.get('ip',[]);ips=[ips] if isinstance(ips,str) else ips
        for ip in ips:
            try:
                private_ip(ip);net=ipaddress.IPv4Network(ip+'/24',strict=False)
                candidates.extend(str(x) for x in net.hosts())
            except ValueError:continue
    if len(set(candidates))>1024:raise ValueError('活动网段过多，请手动填写设备 IP。')
    found=[]
    def check(ip):
        try:
            d=stats(ip)
            return {'ip':ip,'domains':d['domains'],'mac':mac_address(ip)}
        except Exception:return None
    with concurrent.futures.ThreadPoolExecutor(max_workers=40) as pool:
        for d in pool.map(check,dict.fromkeys(candidates)):
            if d:found.append(d)
    if not found:raise ValueError('未发现设备。请确认已完成配网、电脑与设备连接同一路由器，或手动填写 IP。')
    return found

class Xiaomi:
    def __init__(self,gateway,password):
        self.gateway=private_ip(gateway);self.s=http_session();self.base='http://'+self.gateway+'/cgi-bin/luci'
        page=self.s.get(self.base+'/web',timeout=8,allow_redirects=False).text
        k=re.search(r"key:\s*'([a-fA-F0-9]{32})'",page);mac=re.search(r"deviceId\s*=\s*'([a-fA-F0-9:]{17})'",page)
        if not k or not mac:raise ValueError('不是兼容的小米路由器登录页面；请使用手动配置。')
        init=self.s.get(self.base+'/api/xqsystem/init_info',timeout=8).json()
        if init.get('code')!=0:raise ValueError('读取小米路由器版本失败。')
        h=hashlib.sha256 if init.get('newEncryptMode')==1 else hashlib.sha1
        nonce='0_'+mac.group(1)+'_'+str(int(time.time()))+'_'+str(secrets.randbelow(10000))
        hashed=h((nonce+h((password+k.group(1)).encode()).hexdigest()).encode()).hexdigest()
        r=self.s.post(self.base+'/api/xqsystem/login',data={'username':'admin','password':hashed,'nonce':nonce,'logtype':'2'},timeout=8,allow_redirects=False).json()
        token=r.get('token','')
        if r.get('code')!=0 or not re.fullmatch('[a-fA-F0-9]{32}',token):raise ValueError('路由器登录失败，请检查管理密码。它可能与 Wi-Fi 密码不同。')
        self.base+='/;stok='+token

    def api(self,name,params=None,post=False):
        method=self.s.post if post else self.s.get
        kw={'data':params} if post else {'params':params}
        r=method(self.base+'/api/xqnetwork/'+name,timeout=15,allow_redirects=False,**kw)
        d=r.json()
        if r.status_code!=200 or d.get('code')!=0:raise ValueError('小米路由器操作失败：'+name+'（未确认变更成功，请检查后台）')
        return d

def plan_router(req):
    gateway=private_ip(req['gateway']);ip=private_ip(req['device']);device_check(ip);mac=mac_address(ip)
    x=Xiaomi(gateway,req['password']);info=x.api('lan_dhcp')['info'];bindings=x.api('macbind_info')['list'];params=dhcp_change(info,ip)
    if info['lanIp'][0]['ip']!=gateway:raise ValueError('网关与 DHCP 配置不一致。')
    for b in bindings:
        if b['ip']==ip and b['mac'].upper()!=mac:raise ValueError('目标 IP 已被其它设备绑定。')
        if b['mac'].upper()==mac and b['ip']!=ip:raise ValueError('设备已有不同 IP 的绑定，请先在路由器后台核对。')
    plan={'gateway':gateway,'device':ip,'mac':mac,'before':info,'bindings':bindings,'after':params,'created':time.time(),'applied':False}
    folder=STATE/'backups';folder.mkdir(parents=True,exist_ok=True);path=folder/('router-'+time.strftime('%Y%m%d-%H%M%S')+'-'+secrets.token_hex(3)+'.json')
    path.write_text(json.dumps(plan,ensure_ascii=False,indent=2),encoding='utf-8')
    return {'plan':str(path),'preview':f"将为设备 {mac} 保留 IP {ip}，把 DHCP DNS1 改为 {ip}，DNS2 留空。\n保留当前网段、DHCP 开关、地址范围、租约与其它设备绑定。\n原配置备份：{path}\n点击“确认应用”才会修改路由器；保存可能短暂中断网络。"}

def load_plan(req):
    p=pathlib.Path(req['plan']).resolve();root=(STATE/'backups').resolve()
    if p.parent!=root:raise ValueError('请使用本工具生成的路由器备份文件。')
    d=json.loads(p.read_text(encoding='utf-8'))
    if d['gateway']!=private_ip(req['gateway']) or d['device']!=private_ip(req['device']):raise ValueError('预览配置与当前输入不同，请重新预览。')
    return p,d

def apply_router(req):
    if req.get('confirmed') is not True:raise ValueError('需要明确确认路由器变更。')
    path,plan=load_plan(req)
    if time.time()-plan['created']>1800:raise ValueError('预览超过 30 分钟，请重新预览。')
    ip=plan['device'];device_check(ip)
    if mac_address(ip)!=plan['mac']:raise ValueError('设备 MAC 发生变化。')
    x=Xiaomi(req['gateway'],req['password']);current=x.api('lan_dhcp')['info'];bindings=x.api('macbind_info')['list']
    if current!=plan['before'] or bindings!=plan['bindings']:raise ValueError('路由器配置已变化；请重新预览，避免覆盖其它修改。')
    params=dhcp_change(current,ip)
    if not any(b['mac'].upper()==plan['mac'] for b in bindings):
        new=[{'mac':b['mac'],'ip':b['ip'],'name':b.get('name',b['mac'])} for b in bindings]+[{'mac':plan['mac'],'ip':ip,'name':'C3-AdBlock'}]
        x.api('mac_bind',{'data':json.dumps(new,ensure_ascii=False)},post=True);plan['binding_added']=True
        path.write_text(json.dumps(plan,ensure_ascii=False,indent=2),encoding='utf-8')
    x.api('set_lan_dhcp',params);plan['applied']=True;path.write_text(json.dumps(plan,ensure_ascii=False,indent=2),encoding='utf-8')
    time.sleep(3)
    check=x.api('lan_dhcp')['info']
    if check.get('dns1')!=ip or check.get('dns2',''):raise ValueError('DNS 保存后回读不一致，请检查路由器后台。')
    after=x.api('macbind_info')['list']
    if not any(b['mac'].upper()==plan['mac'] and b['ip']==ip for b in after):raise ValueError('未确认静态 IP 绑定，请检查后台。')
    return '路由器 IP 绑定和 DHCP DNS 保存并回读通过。\n请进入第 5 步更新网络租约，然后执行完整验收。\n备份：'+str(path)

def restore_router(req):
    if req.get('confirmed') is not True:raise ValueError('恢复配置需要确认。')
    path,plan=load_plan(req);x=Xiaomi(req['gateway'],req['password']);cur=x.api('lan_dhcp')['info']
    if cur.get('dns1')!=plan['device'] or cur.get('dns2','')!='':raise ValueError('DNS 已被其它操作修改，停止自动恢复，请手动核对。')
    p=dhcp_change(cur,plan['device'])
    for k in ['dns1','dns2']:p[k]=plan['before'].get(k,'')
    x.api('set_lan_dhcp',p)
    time.sleep(3);check=x.api('lan_dhcp')['info']
    if any(check.get(k,'')!=p[k] for k in ['dns1','dns2','router']):raise ValueError('恢复后回读不一致。')
    # Keep the harmless reserved address; deleting it could disrupt a running device.
    return '原 DNS 已恢复并回读通过。当前默认网关选项与设备 IP 绑定保留。请更新网络租约。'

def system_answers(name):
    if name not in ['doubleclick.net','pagead2.googlesyndication.com','www.baidu.com','github.com']:raise ValueError('无效的系统测试域名。')
    # No -Server argument: exercise the actual Windows DNS resolver and policies.
    raw=ps("$ErrorActionPreference='Stop';$a=@(Resolve-DnsName '"+name+"' -Type A -DnsOnly -NoHostsFile | Where-Object {$_.Type -eq 'A'} | Select-Object -ExpandProperty IPAddress);ConvertTo-Json -InputObject $a -Compress")
    return json.loads(raw or '[]')

def diagnose(req):
    ip=private_ip(req['device']);result=device_check(ip);nets=network();default=[]
    for n in nets:default.extend(n.get('dns',[]))
    default=list(dict.fromkeys(default));system_ok=bool(default) and all(x==ip for x in default)
    if system_ok:
        for name in ['doubleclick.net','pagead2.googlesyndication.com']:
            if system_answers(name)!=['0.0.0.0']:system_ok=False
        for name in ['www.baidu.com','github.com']:
            a=system_answers(name)
            if not a or '0.0.0.0' in a:system_ok=False
    result['system_dns']=default;result['system_dns_ok']=system_ok
    folder=STATE/'reports';folder.mkdir(parents=True,exist_ok=True);p=folder/('verify-'+time.strftime('%Y%m%d-%H%M%S')+'.json');p.write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    text=f"设备在线，规则 {result['domains']} 条。广告 A/AAAA 与正常域名解析测试通过。\n系统 DNS：{', '.join(default) or '未读取到'}\n"
    text+=('完整验收通过：本机 DNS 已指向 ESP32。' if system_ok else '尚未全网生效：本机 DNS 未完全指向 ESP32。请更新租约，并检查 IPv6/备用 DNS。')
    text+='\n报告：'+str(p)+'\nYouTube 视频广告无法通过 DNS 可靠过滤；手机/电视须重新连接 Wi-Fi，私人 DNS/VPN 可能绕过过滤。'
    return text,system_ok

def dispatch(req):
    action=req.get('action');log('开始操作：'+str(action))
    if action=='inspect':
        from serial.tools import list_ports
        data={'ports':[{'port':p.device,'description':p.description} for p in list_ports.comports()],'network':network(),'firmware':verify_images(ROOT/'firmware').get('version','1.0')}
        text=json.dumps(data,ensure_ascii=False,indent=2)
        if data['network']:text+='\n@gateway='+str(data['network'][0]['gateway'])
        return text
    if action=='probe':return json.dumps(probe(req['port']),ensure_ascii=False,indent=2)
    if action=='flash':return flash(req)
    if action=='serial':return serial_info(req['port'])
    if action=='discover':
        found=discover();text=json.dumps(found,ensure_ascii=False,indent=2)
        if len(found)==1:text+='\n@device='+found[0]['ip']
        return text
    if action=='preview':
        p=plan_router(req);return p['preview']+'\n@plan='+p['plan']
    if action=='apply':return apply_router(req)
    if action=='restore':return restore_router(req)
    if action=='diagnose':
        text,ok=diagnose(req)
        if not ok:raise ValueError(text)
        return text
    if action=='renew':
        r=subprocess.run(['ipconfig.exe','/renew'],capture_output=True,timeout=50,creationflags=0x08000000)
        if r.returncode:raise ValueError('更新租约未成功；请断开并重新连接家庭 Wi-Fi，或以管理员身份运行工具后重试。')
        subprocess.run(['ipconfig.exe','/flushdns'],capture_output=True,timeout=10,creationflags=0x08000000)
        return '已请求更新 DHCP 租约并清除 DNS 缓存。请点击完整验收确认是否生效。'
    raise ValueError('未知操作。')

def main():
    global LOG
    ap=argparse.ArgumentParser();ap.add_argument('--request',required=True);ap.add_argument('--result',required=True);ap.add_argument('--log');ap.add_argument('--secret-stdin',action='store_true');ap.add_argument('--protect-result',action='store_true');a=ap.parse_args()
    req={};code=0
    try:
        request=pathlib.Path(a.request)
        try:req=json.loads(request.read_text(encoding='utf-8-sig'))
        finally:request.unlink(missing_ok=True)
        if a.secret_stdin:req['password']=sys.stdin.buffer.read(4096).decode('utf-8')
        LOG=pathlib.Path(a.log) if a.log else None
        text=dispatch(req);log('操作完成')
    except Exception as e:
        code=1;text='未完成：'+redact(str(e),req);log('操作未完成；请查看结果和重试说明')
    if a.protect_result:pathlib.Path(a.result).write_bytes(b'DPAPI1'+protect(text.encode('utf-8')))
    else:pathlib.Path(a.result).write_text(text,encoding='utf-8')
    return code

class Blob(ctypes.Structure):
    _fields_=[('size',ctypes.c_ulong),('data',ctypes.c_void_p)]

def protect(data):
    buf=ctypes.create_string_buffer(data);src=Blob(len(data),ctypes.cast(buf,ctypes.c_void_p));dst=Blob()
    if not ctypes.windll.crypt32.CryptProtectData(ctypes.byref(src),None,None,None,None,1,ctypes.byref(dst)):raise ctypes.WinError()
    try:return ctypes.string_at(dst.data,dst.size)
    finally:ctypes.windll.kernel32.LocalFree(ctypes.c_void_p(dst.data))

if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='--esptool':
        import esptool
        esptool.main(sys.argv[2:])
    else:sys.exit(main())
