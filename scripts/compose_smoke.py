#!/usr/bin/env python3
"""Authenticated HTTP checks. Creates/deletes one disabled account if none exist."""
import base64, hashlib, http.cookiejar, json, os, re, secrets, subprocess, sys, urllib.request, urllib.error
BASE=sys.argv[1] if len(sys.argv)>1 else 'http://127.0.0.1:8080'
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*args,**kwargs):return None
jar=http.cookiejar.CookieJar()
op=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar),NoRedirect)
def req(method,path,data=None,headers=None):
 h=headers or {}
 if isinstance(data,dict):data=json.dumps(data).encode();h={**h,'Content-Type':'application/json'}
 try:r=op.open(urllib.request.Request(BASE+path,data=data,method=method,headers=h),timeout=30)
 except urllib.error.HTTPError as e:r=e
 return r.status,r.headers,r.read()
def check(label,condition):
 if not condition:raise AssertionError(label)
 print('PASS',label)
check('anonymous page',req('GET','/akun')[0]==303)
check('anonymous certificate',req('GET','/unduh/akun/1/vpnaas-ca.crt')[0]==401)
s,h,b=req('POST','/login',b'username=admin&password=admin',{'Origin':BASE,'Content-Type':'application/x-www-form-urlencoded'})
check('login default admin',s==303 and 'HttpOnly' in h['Set-Cookie'] and 'SameSite=Strict' in h['Set-Cookie'])
csrf=None
keypath=os.environ.get('SMOKE_API_KEY_FILE','/etc/vpnaas/api.key')
key=open(keypath,'rb').read().strip() if os.path.exists(keypath) else None
for path in ['/ringkasan','/akun','/koneksi','/kebijakan','/status','/audit']:
 s,h,b=req('GET',path)
 check(path+' 200 no-store no key',s==200 and h['Cache-Control']=='no-store' and (not key or key not in b))
 csrf=csrf or re.search(rb'name="csrf-token" content="([^"]+)"',b).group(1).decode()
safe={'Origin':BASE,'X-CSRF-Token':csrf}
check('reject missing CSRF',req('POST','/api/users',{}, {'Origin':BASE})[0]==403)
check('reject bad Origin',req('POST','/api/users',{}, {**safe,'Origin':'http://evil.invalid'})[0]==403)
s,h,b=req('GET','/api/users');check('live backend users',s==200)
users=json.loads(b);created=None
try:
 if not users:
  name='compose-check-'+secrets.token_hex(4)
  s,h,b=req('POST','/api/users',{'username':name,'password':secrets.token_urlsafe(24),'enabled':False,'allowed_cidrs':['10.20.0.0/24'],'traffic_mode':'split'},safe)
  check('create temporary disabled account',s in (200,201))
  users=json.loads(req('GET','/api/users')[2]);created=next(u['id'] for u in users if u['username']==name)
 uid=str(users[0]['id'])
 s,h,ca=req('GET',f'/unduh/akun/{uid}/vpnaas-ca.crt')
 check('certificate attachment no-store',s==200 and h['Cache-Control']=='no-store' and h['Content-Type']=='application/x-x509-ca-cert' and 'attachment' in h['Content-Disposition'])
 subprocess.run(['openssl','x509','-noout','-subject'],input=ca,stdout=subprocess.DEVNULL,check=True)
 profile=json.loads(req('GET',f'/api/users/{uid}/profile')[2])
 check('certificate equals profile CA',ca.strip()==profile['ca_certificate'].encode().strip())
 ps=req('GET',f'/unduh/akun/{uid}/windows.ps1')[2]
 check('Windows contains same CA',base64.b64encode(profile['ca_certificate'].encode()) in ps)
 check('certificate no password',not profile.get('password') or profile['password'].encode() not in ca)
 s,h,b=req('GET',f'/akun/{uid}/sesi',headers={'HX-Request':'true'})
 check('session popup',s==200 and b'role="dialog"' in b)
 page=req('GET','/akun')[2]
 check('split full menu retained',b'popover' in page and b'vpnaas-ca.crt' in page)
 for asset in ['/static/vpn-logo.png','/static/app.css','/static/app.js','/static/htmx.min.js']:
  check(asset,req('GET',asset)[0]==200)
finally:
 if created is not None:check('cleanup temporary account',req('DELETE',f'/api/users/{created}',headers=safe)[0] in (200,204))
if os.environ.get('SMOKE_RESTART')=='1':
 # Executed only on the deployment host; hash stays in process, never printed.
 def state():
  return subprocess.check_output(['docker','compose','exec','-T','ui','sha256sum','/var/lib/vpnaas-ui/session.key']).split()[0]
 before=state();backend=hashlib.sha256(open(keypath,'rb').read()).digest()
 subprocess.run(['docker','compose','restart','ui'],check=True)
 import time;time.sleep(1)
 check('session key preserved after restart',before==state())
 check('API key preserved',backend==hashlib.sha256(open(keypath,'rb').read()).digest())
 check('existing authenticated session survives',req('GET','/akun')[0]==200)
 mode=subprocess.check_output(['docker','compose','exec','-T','ui','stat','-c','%a','/var/lib/vpnaas-ui/session.key']).strip()
 check('session mode 600',mode==b'600')
print('All checks passed')
