import os,json,requests
for r,d,fs in os.walk('.'):
    d[:]=[x for x in d if x not in{'.git','node_modules','__pycache__','.venv'}]
    for f in fs:
        if not f.endswith(('.py','.js','.ts','.java')):continue
        p=os.path.join(r,f)
        c=open(p,errors='ignore').read()
        if len(c.strip())<10:continue
        try:
            v=requests.post('http://localhost:8080/v2/scan',json={'code':c,'language':f.rsplit('.',1)[-1]},timeout=30).json()['finding']
            if v.get('cwe'):print(f'\033[91m🔴 {p}\033[0m\n   {v["vulnerability"]} | {v["cwe"]} | {v["severity"]}')
        except:pass
