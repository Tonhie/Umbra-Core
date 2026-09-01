# Umbra-Core

基于 C++17、NTL 和 GMP 的现代密码学课程设计实现。项目包含 RSA、ElGamal、SHA-256、证书方案、严格层次 PKI 和安全邮件模块。

## 依赖与构建

- CMake 3.23+
- Ninja
- C++17 编译器
- GMP 6.3.0 与 NTL 11.6.0

Linux（GCC/Clang）：

```bash
./scripts/build_deps.sh
cmake --preset debug
cmake --build --preset debug
ctest --preset debug
```

Windows 推荐使用 MSYS2 UCRT64。PowerShell 脚本会优先复用已安装的 MSYS2，缺失时才尝试通过 winget 安装，并自动安装或准备 GMP/NTL：

```powershell
.\scripts\build_windows.ps1
.\scripts\build_windows.ps1 -Configuration Release
```

依赖安装到 `third_party/local-msys2`，项目输出到 `build/windows-mingw-debug` 或 `build/windows-mingw-release`。MinGW 构建默认将编译器运行时静态链接进可执行文件，因此生成的 `umbra_demo.exe` 可直接从普通 PowerShell 启动，不需要复制 DLL 或修改 PATH。如果依赖已经准备好，也可直接使用 CMake 预设：

```powershell
cmake --preset windows-mingw-debug
cmake --build --preset windows-mingw-debug
```

注意：`cmake --build` 只执行已有构建目录的编译；第一次构建必须先执行 `cmake --preset`，并且当前 PowerShell 必须能找到 MSYS2 UCRT64 的 `gcc`、`g++` 和 `ninja`。最省事的方式是直接运行上面的 `build_windows.ps1`。如果要手动使用预设，请先在当前窗口加入工具路径：

```powershell
$env:Path = "C:\msys64\ucrt64\bin;C:\msys64\usr\bin;$env:Path"
cmake --preset windows-mingw-debug
cmake --build --preset windows-mingw-debug
```

若 MSYS2 安装在其他目录，请相应替换路径；也可以给脚本传入 `-MsysRoot`。

本项目只维护 GCC/Clang 和 MSYS2 UCRT64 MinGW 两类构建，不提供 MSVC、x86 或单独的 x64 预设。若确实需要动态运行时，可配置 `-DUMBRA_MINGW_STATIC_RUNTIME=OFF`，CMake 会把所需 DLL 复制到 exe 旁边。

## 演示程序

无参数启动进入交互式 ASCII TUI 邮箱（不需要网络或 GUI）：

```powershell
.\build\windows-mingw-debug\umbra_demo.exe
```

左栏是操作界面（启动时默认选中 Alice），右栏是紧凑的后台加密过程日志。可以切换 Alice、Bob、Eve，查看收件箱，撰写多行邮件（单独输入 `.` 结束正文），发送并阅读邮件。发送也可直接输入 `s`/`send`/`compose`。发送和阅读会在后台线程执行，右栏会实时显示密钥生成、证书签发与入库、证书链查询/验证、摘要计算、签名、`m || s` 组装、加密、投递、解密和验签等步骤，并仅显示算法、对象名称和长度等元数据；不会输出密钥、证书、明文、签名或密文的实际内容。输入 `[6]` 可查看完整过程日志，`[7]` 清空日志。邮件密文只在本地内存传输队列中流转。

原来的五任务批处理演示仍可用：

```powershell
umbra_demo.exe --batch [input.txt] [output-dir]
```

批处理依次演示 RSA、ElGamal、简单证书、严格层次 PKI 和安全邮件，并把密钥、证书、密文和恢复后的邮件写入输出目录。省略 `input.txt` 时使用内置示例，省略输出目录时使用 `demo_output`。

## 项目结构

```text
src/crypto/       RSA 与 ElGamal 引擎
src/hash/         SHA-256
src/certificate/  证书、TA、CA、证书库与链验证
src/pki/          PKI 用户对象
src/mail/         安全邮件协议
src/demo/         交互式与批处理演示
tests/            各模块单元测试
docs/             课程设计报告、历史材料与任务书
```

库依赖方向为 `umbra_mail -> umbra_certificate -> umbra_crypto -> umbra_hash`。安全邮件协议不依赖网络：发送端对邮件摘要签名，再用接收端加密公钥加密 `m || s`；接收端解密后验证发送者证书链和签名。

## 测试

```bash
ctest --preset debug
```

测试覆盖 RSA/ElGamal 加解密与签名、SHA-256、证书序列化与验证、证书库路径、PKI 用户以及安全邮件的篡改和错误密钥拒绝场景。

## 说明

这是用于课程学习和算法演示的实现，不是生产级密码库；未提供 OAEP、PSS、密钥保护、证书有效期或吊销机制。

课程设计报告见 `docs/现代密码学课程设计报告.md`；任务分解和演示要求以 `docs/2026现代密码学课程设计任务书新版本.ppt` 为准。仓库中的旧 PDF 仅作为历史材料保留，不作为新报告的章节依据。
