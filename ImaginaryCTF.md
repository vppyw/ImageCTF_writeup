---
tags: CTF, ImaginaryCTF
---
# ImaginaryCTF

## Rotating Secret Assembler

```python=
#!/usr/bin/env python3

from Crypto.Util.number import *

class Rotator:
    QUEUE_LENGTH = 10

    def __init__(self):
        self.e = 65537
        self.m = bytes_to_long(open('flag.txt', 'rb').read())
        self.queue = [getPrime(512) for i in range(self.QUEUE_LENGTH)]

    def get_new_primes(self):
        ret = self.queue[-2:]
        self.queue.pop()
        while(len(self.queue) < self.QUEUE_LENGTH):
            self.queue = [getPrime(512)] + self.queue
        return tuple(ret)

    def enc_flag(self):
        p, q = self.get_new_primes()
        n = p*q
        print(f"Public key: {(n, self.e)}")
        print(f"Your encrypted flag: {pow(self.m, self.e, n)}")

rot = Rotator()

print('='*80)
print(open(__file__).read())
print('='*80)

while True:
    inp = input("Would you like an encrypted flag (y/n)? ")
    if 'y' in inp.lower():
        rot.enc_flag()
        print()
    else:
        break
```

從程式碼知道有重複使用質數，把兩個大數做 GCD ，讓質因數分解變得很容易

```python=
N1 = input('N1')
enc = input('enc flag')
N2 = input('N2')
e = 65537
from Crypto.Util.number import *

p = GCD(N1, N2)
q = N1 // p
d = inverse(e, (p - 1) * (q - 1))
print(long_to_bytes(pow(enc, d, N1)))
```

## Relatively Small Arguments

```python=
#!/usr/bin/env python3

from Crypto.Util.number import *

p = getPrime(512)
q = getPrime(512)
n = p*q
phi = (p-1)*(q-1)
d = getPrime(32)
e = pow(d, -1, phi)
m = bytes_to_long(open('flag.txt', 'rb').read())
c = pow(m, e, n)

print(f'{n = }')
print(f'{e = }')
print(f'{c = }')
```

d 很小，嘗試用 Wiener's attack
<https://en.wikipedia.org/wiki/Wiener%27s_attack>
<https://github.com/orisano/owiener>

```python=
from Crypto.Util.number import long_to_bytes
import owiener

n = 134872711253918655399533296784203466697159038260837702891888089821702090938512308686613559851138816682269099219724900870388583883202954112422023894133671598222066489215524613014212242490437041258588247678792591072443719118562580052842727775772283919113007499992167089258075609504428713653013187230671841726369
e = 50920242742169837294267124730818234703309561711363177522992049271988492365017092545331352650316729342598781520444569769450329777448285534584484096179230968844630486688656705514759778561817709539781927624692111848722199024819005269510690240743887870339853351421726436719236180272680237157536332997570569192069
c = 133155317855020316110137499609990113815646625767974277474197900721563685454745247616867035013963212538345727281661922602291072931578581035070345294335733120033652413487827994383327148598029065495228796201084369245315585407592741900307825557286213370482646401885352854920924352919398804532780740979273692054391
d = owiener.attack(e, n)
print(long_to_bytes(pow(c, d, n)))
```

## Pickle

直接 load 檔案會
`AttributeError: Can't get attribute 'FlagPrinter' on <module '__main__' (built-in)>`
自己建一個`class FlagPrinter`

```python=
import pickle

class FlagPrinter():
    def __init__(self):
        pass

with open('out.pickle', 'rb') as f:
    p = pickle.load(f)
    print("".join([chr(c) for c in p.flag]))
```

## Unchained

```python=
from django.shortcuts import render
from django.http import HttpResponse, FileResponse

from requests import get

# at /
def index(request):
    return HttpResponse(open(__file__, 'r').read(), content_type='text/plain')

# at /flag
def flag(request):
    user = request.GET.get('user', '')
    if user == 'admin':
        return HttpResponse("Hey, no impersonating admin!")
    url = request.build_absolute_uri().replace(request.build_absolute_uri('/'), '')
    r = get('http://0.0.0.0:1337/'+url)
    return HttpResponse(r.content)

# definitely not at /nothing_important_dont_look_here
def nothing_important_dont_look_here(request):
    return HttpResponse(get('http://0.0.0.0:1337').content, content_type='text/plain')

```

利用`replace`跳掉對 admin 的檢查

<http://puzzler7.imaginaryctf.org:3006/flag?user=adminhttp://puzzler7.imaginaryctf.org:3006/>

## xorrot

```python=
#!/usr/bin/env python3

flag = open('flag.txt', 'rb').read()
key = open('/dev/urandom','rb').read(1)[0]
out = []

for c in flag:
    out.append(c^key)
    key = c

print(f'{bytes(out).hex() = }')

# bytes(out).hex() = '970a17121d121d2b28181a19083b2f021d0d03030e1526370d091c2f360f392b1c0d3a340e1c263e070003061711013b32021d173a2b1c090f31351f06072b2b1c0d3a390f1b01072b3c0b09132d33030311'
```

暴力搜

```python=
enc = bytes.fromhex('970a17121d121d2b28181a19083b2f021d0d03030e1526370d091c2f360f392b1c0d3a340e1c263e070003061711013b32021d173a2b1c090f31351f06072b2b1c0d3a390f1b01072b3c0b09132d33030311')
for key in range(256):
    x = ""
    for b in enc:
        x += chr(b ^ key)
        key = b ^ key
    if x.find("ictf") != -1:
        print(x)
```

## Lost Flag

從`.DS_Store`恢復檔案
<https://suip.biz/?act=dsstore>

## Age

先 decompile `gen.cpython-310.pyc`
<https://tool.lu/en_US/pyc/>

```python=
from zipfile import ZipFile
from hashlib import sha256
from time import time
from os import system
unixtime = int(time())
password = sha256(str(unixtime).encode()).hexdigest()
print('Writing with time', unixtime, 'and password', password)
system(f'''zip --password {password} inner.zip flag.txt''')
```

暴力搜，用一下 mod 到各個 processes 比較容易

```python=
#! /usr/bin/python
import zipfile
from hashlib import sha256
from tqdm import tqdm
import sys

with zipfile.ZipFile("inner.zip") as zip_file:
    start = int(sys.argv[1])
    for i in tqdm(range(start, 0, -1)):
        pwd = sha256(str(i).encode()).hexdigest().encode()
        try:
            zip_file.extractall(pwd=pwd)
            print(i, pwd)
            with open("passwd.txt", "w") as f:
                f.write(f"{i} {pwd}\n")
            break
        except:
            continue
```

password: `ba2fe6b52f7610a6ddc4ce405d302e0eb93223b3b0c4d833895fe3ae68f0c0fe`

## Replacement

用 burp suite 抓封包。
用`ictf`跟`f2e8b632f71c2cab`登錄。
再到<http://puzzler7.imaginaryctf.org:4003/totallynottheflag> 一個一個的讓封包過去。

## Personalized

暴搜 seed 到 e 夠小，用 boardcast attack

```python=
import pwn
import owiener
from Crypto.Util.number import long_to_bytes
from random import seed, getrandbits
from sympy.ntheory.modular import crt
from gmpy2 import iroot
from tqdm import tqdm

key = 0
mn = float('inf')
for i in tqdm(range(1, 100000000)):
    key = i
    seed(key)
    tmp = getrandbits(32)
    if mn > tmp:
        key = 0
        mn = tmp

print(key, mn)
n = []
c = []
for _ in range(3):
    r = pwn.remote("puzzler7.imaginaryctf.org", "4002")
    r.sendlineafter(b"What's your name?\n>>> ", long_to_bytes(key))
    _ = r.recvline()
    n.append(int(r.recvline().split(b' ')[-1].decode()))
    e = int(r.recvline().split(b' ')[-1].decode())
    c.append(int(r.recvline().split(b' ')[-1].decode()))
    r.close()

m, _ = crt(n, c)
m, b = iroot(m, e)
if b:
    print(long_to_bytes(m))
```

## same

common modulus attack

```python=
from Crypto.Util.number import long_to_bytes, inverse
n = 88627598925887227793409704066287679810103408445903546693879278352563489802835708613718629728355698762251810901364530308365201192197988674078034209878433048946797619290221501750862580914894979204943093716650072734138749420932619469204815802746273252727013183568196402223549961607284086898768583604510696483111
c0 = 45254947860172381004009381991735702721210786277711531577381599020185600496787746985669891424940792336396574951744089759764874889285927022268694128526139687661305707984329995359802337446670063047702309778972385903473896687843125261988493615328641864610786785749566148338268077425756876069789788618208807001704
e0 = 1337
c1 = 16054811947596452078263236160429328686151351092304509270058479526590947874445940946506791900760052230887962479603369427120610506778471930164144528718052332194666418267005043709704814833963217926271924910466448499814399455203725279998913865531351070938872586642424346857094632491904168889134624707595846754719
e1 = 31337

while e1 != 1:
    e1 -= e0
    c1 = (c1 * inverse(c0, n)) % n
    if e0 > e1:
        e0, e1 = e1, e0
        c0, c1 = c1, c0

print(long_to_bytes(c1))
```

## aes

暴搜`rockyou.txt`