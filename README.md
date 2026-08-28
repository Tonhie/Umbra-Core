# Umbra-Core

基于 C++17 与 NTL 的现代密码学课程设计实现。项目以模块化方式实现 RSA、Elgamal、SHA-256、简单证书方案、层次化简易 PKI 以及无需网络传输的安全邮件流程。

> 本项目用于课程学习、算法演示和单元测试，不是生产级密码库。实现使用教学目的的裸 RSA/Elgamal 分组加密与签名方案，未提供 OAEP、PSS、混合加密、密钥保护或完整的证书撤销机制。请勿直接用于保护真实敏感数据。

## 功能概览

- RSA：密钥生成、分组加密/解密、SHA-256 摘要签名与验证、密钥文本序列化。
- Elgamal：密钥生成、分组加密/解密、签名与验证、密钥文本序列化。
- SHA-256：基于 FIPS 180-4 的哈希实现，支持文件/字符串场景所需的摘要计算。
- 简单证书：TA 为用户签发证书，证书支持 RSA 与 Elgamal 公钥以及“加密/签名”用途标记。
- 简易 PKI：根 CA 自签名、下级 CA 签发用户证书、证书库查询和证书链验证。
- 安全邮件：发送方对邮件摘要签名，再使用接收方加密公钥加密 `m || s`；接收方解密并验证发送方证书链和签名。

## 项目结构

```text
src/
├── crypto/                 RSA、Elgamal 与密码引擎抽象接口
├── hash/                   SHA-256
├── certificate/            证书、TA、CA、证书库与证书链验证
├── pki/                    PKI 用户对象
├── mail/                   安全邮件收发流程
└── demo/                   完整流程演示程序
tests/                      各模块独立测试
docs/                       课程设计说明书
third_party/                GMP/NTL 源码及本地静态库安装目录
scripts/build_deps.sh       从源码构建 GMP 与 NTL
```

库之间的依赖关系如下：

```text
umbra_mail → umbra_certificate → umbra_crypto → umbra_hash
```

PKI 演示采用如下证书层次：

```text
CA_root（自签名）
├── CA1 ── Alice、Eve
└── CA2 ── Bob
```

## 环境要求

- CMake 3.23 或更高版本
- Ninja
- 支持 C++17 的编译器
- GMP 6.3.0
- NTL 11.6.0

项目默认从 `third_party/local` 查找 NTL/GMP 的头文件和静态库。仓库通常已包含可用的本地依赖构建结果；如果当前平台不兼容，可按下节重新构建依赖。

## 构建

在项目根目录执行：

```bash
# Debug 构建
cmake --preset debug
cmake --build --preset debug

# Release 构建
cmake --preset release
cmake --build --preset release
```

如果需要从仓库中的源码重新构建 GMP 和 NTL：

```bash
./scripts/build_deps.sh
cmake --preset debug
cmake --build --preset debug
```

`build_deps.sh` 会删除并重新生成 `third_party/build` 与 `third_party/local`，执行前请确认其中没有需要保留的本地文件。

Windows（VS2022）可在“开发者 PowerShell for VS 2022”中自动安装 MSVC 依赖并编译：

```powershell
.\scripts\build_windows.ps1
```

脚本会自动下载/初始化 vcpkg，安装 GMP，并检查 vcpkg 是否提供 NTL port，随后使用 VS2022 生成器构建 `build/windows-x64-debug`。如果 vcpkg 没有 NTL port，脚本会明确提示并停止，不会误用 Unix 的 `.a` 库。发布构建或 x86 架构示例：

```powershell
.\scripts\build_windows.ps1 -Configuration Release
.\scripts\build_windows.ps1 -Architecture x86
```

## 运行测试

```bash
ctest --preset debug
```

测试覆盖以下模块：

| 测试目标 | 覆盖内容 |
| --- | --- |
| `crypto.rsa_engine` | RSA 加解密、签名和验证正反例 |
| `crypto.elgamal_engine` | Elgamal 加解密、签名和验证正反例 |
| `hash.sha_256` | SHA-256 标准向量和流式一致性 |
| `certificate.certificate` | 证书序列化、公钥转换、证书签名验证 |
| `certificate.trusted_authority` | TA 签发 RSA/Elgamal 证书及篡改拒绝 |
| `certificate.certificate_authority` | 根 CA 自签名和下级证书签发 |
| `certificate.certificate_library` | 证书库存储、路径查询和链验证 |
| `pki.pki_user` | 用户双证书申请、签名和验证 |
| `mail.secure_mail` | 安全邮件往返及异常输入拒绝 |

## 运行演示

演示程序会依次运行 RSA、Elgamal、简单证书、简易 PKI 和安全邮件流程：

```bash
# 使用内置示例邮件，输出到 ./demo_output
./build/debug/umbra_demo

# 使用指定文件作为明文/邮件内容，并指定输出目录
./build/debug/umbra_demo path/to/plaintext.txt path/to/output
```

演示会在输出目录生成密钥、证书、证书链、密文、签名和恢复后的邮件等文件，例如：

```text
demo_output/
├── rsa/
│   ├── rsa_public_key.txt
│   ├── rsa_private_key.txt
│   ├── rsa_ciphertext.txt
│   └── rsa_signature.txt
├── elgamal/
├── certificates/
├── pki/
│   ├── root.cert
│   ├── ca1.cert
│   ├── alice_chain.txt
│   └── ...
└── mail/
    ├── mail_ciphertext.txt
    └── mail_recovered.txt
```

演示程序中的 Elgamal 使用 512 位参数以缩短运行时间；库的默认 Elgamal 参数规模为 2048 位。RSA 演示使用两个 1024 位素数。

## 证书与安全邮件格式

证书为文本格式，结构示例：

```text
BEGIN UMBRA CERTIFICATE
ISSUER:TA
SUBJECT:Alice
ALGORITHM:RSA
PURPOSE:Encryption
PUBLIC_KEY:RSA <n> <e>
SIGNATURE:
<signature>
END UMBRA CERTIFICATE
```

证书签名覆盖主题身份与公钥文本，即课程设计中的 `ID(subject) || ver_subject`。证书路径按“根证书 → 下级 CA 证书 → 叶证书”排列，并逐级验证签名。

安全邮件流程为：

```text
邮件 m
  └─ SHA-256(m) + 发送方签名 → s
       └─ 拼接 m || s
            └─ 接收方加密公钥加密 → 密文 c
```

接收方使用自己的加密私钥解密，再从证书库查询并验证发送方的签名公钥证书链，最后验证邮件签名。

## API 模块

主要公共接口位于以下头文件：

- `src/crypto/crypto_engine.h`：密码引擎、密钥和算法工厂。
- `src/hash/sha_256.h`：SHA-256 接口。
- `src/certificate/certificate.h`：证书对象、公钥转换和证书链验证。
- `src/certificate/trusted_authority.h`：简单 TA。
- `src/certificate/certificate_authority.h`：层次 PKI 中的 CA。
- `src/certificate/certificate_library.h`：证书存储与路径查询。
- `src/pki/pki_user.h`：PKI 用户及密钥/证书管理。
- `src/mail/secure_mail.h`：签名、加密、解密和安全邮件收发流程。

## 课程设计文档

更完整的算法说明、设计决策、文件格式和测试结果见：[课程设计说明书](docs/课程设计说明书.md)。对应 PDF 版本位于 `docs/课程设计说明书.pdf`。

## 许可证

本项目采用 MIT License，详见 [LICENCE](LICENCE)。
