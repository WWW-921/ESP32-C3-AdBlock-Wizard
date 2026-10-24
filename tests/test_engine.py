import sys, pathlib, unittest, struct, tempfile, json
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
import engine

class SafetyTests(unittest.TestCase):
    def test_apply_preserves_existing_bindings_and_rejects_stale_plan(self):
        from unittest.mock import patch
        import time,copy
        info={'lanIp':[{'ip':'192.168.3.1','mask':'255.255.255.0'}],'start':'5','limit':'250','ignore':'0','leasetime':'12h','dns1':'','dns2':''}
        bindings=[{'mac':'AA:BB:CC:DD:EE:01','ip':'192.168.3.20','name':'Existing'}]
        plan={'device':'192.168.3.165','mac':'90:64:9B:46:25:DC','before':copy.deepcopy(info),'bindings':copy.deepcopy(bindings),'created':time.time()}
        writes=[]
        class Router:
            def api(self,name,params=None,post=False):
                if name=='lan_dhcp':return {'info':info}
                if name=='macbind_info':return {'list':bindings}
                writes.append((name,params))
                if name=='mac_bind':bindings[:]=json.loads(params['data'])
                if name=='set_lan_dhcp':info.update(params)
                return {'code':0}
        with tempfile.TemporaryDirectory() as d,patch.object(engine,'load_plan',return_value=(pathlib.Path(d)/'plan.json',plan)),patch.object(engine,'Xiaomi',return_value=Router()),patch.object(engine,'device_check'),patch.object(engine,'mac_address',return_value=plan['mac']),patch.object(engine.time,'sleep'):
            engine.apply_router({'confirmed':True,'gateway':'192.168.3.1','password':'test'})
            self.assertEqual(bindings[0],plan['bindings'][0]);self.assertEqual(len(bindings),2)
            self.assertEqual(info['dns1'],plan['device'])
            writes.clear()
            with self.assertRaises(ValueError):engine.apply_router({'confirmed':True,'gateway':'192.168.3.1','password':'test'})
            self.assertEqual(writes,[])

    def test_restore_preserves_gateway_and_rejects_secondary_dns_conflict(self):
        from unittest.mock import patch
        info={'lanIp':[{'ip':'192.168.3.1','mask':'255.255.255.0'}],'start':'5','limit':'250','ignore':'0','leasetime':'12h','dns1':'192.168.3.165','dns2':'','router':'192.168.3.2'}
        before=dict(info,dns1='1.1.1.1',dns2='8.8.8.8',router='')
        plan={'device':'192.168.3.165','before':before};captured=[]
        class Router:
            def api(self,name,params=None):
                if params:captured.append(params);info.update(params)
                return {'info':info}
        with patch.object(engine,'load_plan',return_value=(pathlib.Path('unused'),plan)),patch.object(engine,'Xiaomi',return_value=Router()),patch.object(engine.time,'sleep'):
            engine.restore_router({'confirmed':True,'gateway':'192.168.3.1','password':'test'})
            self.assertEqual(captured[0]['router'],'192.168.3.2')
            self.assertEqual(captured[0]['dns1'],'1.1.1.1')
            info['dns1']='192.168.3.165';info['dns2']='9.9.9.9';captured.clear()
            with self.assertRaises(ValueError):engine.restore_router({'confirmed':True,'gateway':'192.168.3.1','password':'test'})
            self.assertEqual(captured,[])

    def test_diagnosis_does_not_trust_adapter_config_alone(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as d,patch.object(engine,'STATE',pathlib.Path(d)),patch.object(engine,'device_check',return_value={'domains':10}),patch.object(engine,'network',return_value=[{'dns':['192.168.3.165']}]),patch.object(engine,'system_answers',return_value=['8.8.8.8']):
            text,ok=engine.diagnose({'device':'192.168.3.165'})
            self.assertFalse(ok);self.assertIn('尚未全网生效',text)

    def test_protected_result_contains_no_plaintext(self):
        payload='中文 DPAPI roundtrip'.encode()
        encrypted=engine.protect(payload)
        self.assertNotIn(payload,encrypted)
        buf=engine.ctypes.create_string_buffer(encrypted);src=engine.Blob(len(encrypted),engine.ctypes.cast(buf,engine.ctypes.c_void_p));dst=engine.Blob()
        self.assertTrue(engine.ctypes.windll.crypt32.CryptUnprotectData(engine.ctypes.byref(src),None,None,None,None,1,engine.ctypes.byref(dst)))
        try:self.assertEqual(engine.ctypes.string_at(dst.data,dst.size),payload)
        finally:engine.ctypes.windll.kernel32.LocalFree(engine.ctypes.c_void_p(dst.data))
    def test_flash_rejects_incomplete_bundle_before_port_access(self):
        from unittest.mock import patch
        with patch.object(engine,'verify_images',return_value={'images':[]}),patch.object(engine,'probe') as probe,patch.object(engine,'espcmd'):
            with self.assertRaises(ValueError):engine.flash({'confirmed':True,'port':'COM3'})
            probe.assert_not_called()

    def test_backup_failure_never_erases_flash(self):
        from unittest.mock import patch
        import hashlib
        m={'chip':'ESP32-C3','flash_bytes':4194304,'images':[{'file':f,'offset':o} for f,o in engine.EXPECTED_IMAGES.items()]}
        calls=[]
        def cmd(args,timeout=60):
            calls.append(args)
            raise ValueError('simulated read failure')
        with tempfile.TemporaryDirectory() as d,patch.object(engine,'STATE',pathlib.Path(d)),patch.object(engine,'verify_images',return_value=m),patch.object(engine,'probe',return_value={'chip':'ESP32-C3','flash':4194304}),patch.object(engine,'espcmd',side_effect=cmd):
            with self.assertRaises(ValueError):engine.flash({'confirmed':True,'port':'COM3'})
        self.assertEqual(len(calls),1)
        self.assertIn('read-flash',calls[0]);self.assertFalse(any('erase-flash' in c for c in calls))

    def test_only_private_ipv4_targets(self):
        self.assertEqual(engine.private_ip('192.168.3.165'),'192.168.3.165')
        for v in ['8.8.8.8','127.0.0.1','169.254.1.1','224.0.0.1','http://192.168.1.1/x','192.168.1.1:80']:
            with self.subTest(v=v),self.assertRaises(ValueError):engine.private_ip(v)

    def test_dhcp_preserves_range_and_lease(self):
        info={'lanIp':[{'ip':'192.168.3.1','mask':'255.255.255.0'}], 'start':'5','limit':'250','ignore':'0','leasetime':'12h'}
        p=engine.dhcp_change(info,'192.168.3.165')
        self.assertEqual((p['start'],p['end'],p['limit'],p['leasetime']),(5,254,250,'12h'))
        self.assertEqual((p['dns1'],p['dns2']),('192.168.3.165',''))
        for bad in ['192.168.4.165','192.168.3.1','192.168.3.255']:
            with self.assertRaises(ValueError):engine.dhcp_change(info,bad)
        info['lanIp'][0]['mask']='255.255.0.0'
        with self.assertRaises(ValueError):engine.dhcp_change(info,'192.168.3.165')

    def test_dns_parser_validates_transaction_and_truncation(self):
        q=engine.dns_packet('doubleclick.net',1,123)
        response=struct.pack('!HHHHHH',123,0x8180,1,1,0,0)+q[12:]+b'\xc0\x0c'+struct.pack('!HHIH',1,1,60,4)+b'\0\0\0\0'
        self.assertEqual(engine.dns_answers(response,123),['0.0.0.0'])
        for b,tid in [(response,124),(response[:8],123),(response[:-2],123)]:
            with self.assertRaises(ValueError):engine.dns_answers(b,tid)

    def test_chip_and_capacity_gate(self):
        engine.validate_chip('ESP32-C3',4194304)
        for chip,size in [('ESP32',4194304),('ESP32-S3',4194304),('ESP32-C3',2097152)]:
            with self.assertRaises(ValueError):engine.validate_chip(chip,size)

    def test_manifest_rejects_modified_image(self):
        import hashlib
        with tempfile.TemporaryDirectory() as d:
            p=pathlib.Path(d);(p/'app.bin').write_bytes(b'firmware')
            (p/'manifest.json').write_text(json.dumps({'images':[{'file':'app.bin','sha256':hashlib.sha256(b'firmware').hexdigest(),'offset':65536}]}))
            engine.verify_images(p)
            (p/'app.bin').write_bytes(b'changed')
            with self.assertRaises(ValueError):engine.verify_images(p)

    def test_no_credentials_in_redacted_result(self):
        out=engine.redact('problem MySecret and RouterToken',{'password':'MySecret','token':'RouterToken'})
        self.assertNotIn('MySecret',out);self.assertNotIn('RouterToken',out)

if __name__=='__main__':unittest.main()
