# wavcrypt

将任意类型的普通文件加密为可正常播放的 WAV 音频，并可从该 WAV 解密还原原文件。程序为 Linux 命令行交互式工具，使用 C11 编写。

## 1. 需要的开发库

只需要 **OpenSSL 的开发文件（libcrypto）**：

- C 编译器：GCC 或 Clang（支持 C11）
- GNU Make（可选，也可直接使用下面的 gcc 命令）
- OpenSSL 开发包：**OpenSSL >= 1.1.1**，使用其中的 `libcrypto`
  - Debian / Ubuntu：`libssl-dev`
  - Fedora / RHEL / CentOS：`openssl-devel`
  - Arch Linux：`openssl`
  - Alpine：`openssl-dev`
- 运行期共享库：`libcrypto.so`（由 OpenSSL 运行包提供）

Debian / Ubuntu 安装示例：

```bash
sudo apt update
sudo apt install build-essential libssl-dev
```

## 2. 编译

```bash
cd wavcrypt
make
```

等价的手动编译命令：

```bash
gcc -O2 -std=c11 -Wall -Wextra -Wpedantic -D_FILE_OFFSET_BITS=64 \
    -o wavcrypt wavcrypt.c -lcrypto
```

## 3. 运行

```bash
./wavcrypt
```

程序首先询问模式：

- `0`：加密模式
- `1`：解密模式

### 加密模式

1. 输入要加密的普通文件路径。
2. 设置密钥（输入时终端不回显），并再次输入确认。
3. 生成输出文件：`<原文件路径>.wav`。

例如输入 `/home/user/photo.jpg`，输出为 `/home/user/photo.jpg.wav`。

### 解密模式

1. 输入待解密的 WAV 文件路径。
2. 输入该文件对应的密钥。
3. 校验成功后，原文件会被还原到 **该 WAV 所在目录**，文件名使用加密时保存的原文件名。

如果目标文件已存在，程序会询问是否覆盖。密钥错误、WAV 被篡改或损坏时不会留下解密结果。

## 4. WAV 格式与加密设计

- WAV：标准 RIFF/WAVE，PCM 16-bit、单声道、44100 Hz。
- 密文直接写入 `data` 块的 PCM 采样字节中，因此 WAV 可被普通播放器正常打开；播放内容是噪声，这是正常现象。
- 自定义 `ENCV` 块保存公开的 KDF/GCM 参数；主流播放器会忽略这个辅助块。
- 原始文件名和原始文件大小与文件内容一起加密，不直接暴露在 WAV 中。
- 密钥派生：PBKDF2-HMAC-SHA256，随机 16 字节盐，600,000 次迭代，派生 256 位密钥。
- 加密：AES-256-GCM，随机 96 位 nonce，128 位认证标签。
- `ENCV` 块的公开参数作为 GCM 的 AAD 参与认证，改动盐、nonce、迭代次数或密文长度都会导致解密失败。
- 解密先写入同目录的临时文件，GCM 认证通过后才原子重命名为最终文件；认证失败会删除临时文件。
- 输出文件权限由 `mkstemp` 创建，通常为 `0600`（仅文件所有者可读写）。

### 注意事项

- 只能解密由本程序生成的、未经修改或重新编码的 WAV。用音频软件另存、转码、剪辑或修改采样后，密文会被破坏。
- RIFF/WAVE 的 32 位长度字段限制单文件约为 **4 GiB**（含加密元数据），超过会拒绝加密。
- 解密只依赖 WAV 本身，不依赖原文件或额外密钥文件；密钥一旦丢失无法恢复。
- 加密保护的是文件内容；WAV 时长/大小仍会大致暴露原文件大小。
- 请使用足够强的密钥。密钥少于 8 个字符时程序会提示安全性较弱，但不会阻止继续。

## 5. 可选自测

如果系统安装了 Python 3，可运行：

```bash
make test
# 或
bash smoke_test.sh
```

自测会覆盖文本、空文件、5 MiB 随机二进制、中文/空格文件名、错误密钥、篡改认证标签、覆盖确认以及临时文件清理等场景。

## 6. 文件说明

- `wavcrypt.c`：程序源码
- `Makefile`：构建脚本
- `smoke_test.sh`：可选自动化测试脚本
