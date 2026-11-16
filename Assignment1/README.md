# Assignment1：目录与开发安排

## 文件怎么分

```text
Assignment1/
├── doc/                         老师提供的原始资料（已齐全）
├── py-http-server/              开发与运行目录（服务器底座已准备）
│   ├── py_http_server/
│   │   └── middlewares/
│   │       ├── digest_auth.py             已实现：安全认证
│   │       └── digest_auth_subverted.py   已实现：后门版认证
│   ├── client.py                         已实现：安全客户端
│   ├── client_subverted.py               已实现：后门版客户端
│   ├── passwords.txt                     测试用密码文件
│   ├── start_server_digest.py            老师提供的安全版启动脚本
│   └── start_server_subverted.py         老师提供的后门版启动脚本
├── tests/                       检查程序和测试记录
├── report/                      报告草稿及最终 report.pdf
├── submission/                  最终打包副本（恰好五个文件）
├── tmp/                         临时文件，例如 PDF 页面预览
└── .venv/                       本机 Python 运行环境
```

安全版、后门版认证及两个客户端均已实现。其余服务器文件省略显示。

## 文件栏显示

用 VS Code 打开 `Assignment1` 文件夹时，项目设置会隐藏运行环境、临时文件和本阶段无需编辑的服务器底层文件，并合并单分支文件夹显示。`basic_auth.py` 保留显示作为现有中间件的参考，`middlewares/__init__.py` 保留显示用于之后接入新模块。文件实际位置和程序运行不受影响。

需要查看所有文件时，在 `.vscode/settings.json` 的 `files.exclude` 中将对应项改为 `false`。这只是编辑器的显示设置，隐藏文件仍可通过完整路径访问。

## 模块职责

- `digest_auth.py`：读取用户名和 SHA256 密码哈希，验证摘要，失败时返回 401，成功时交给文件路由。
- `client.py`：交互输入凭据，计算密码摘要并请求资源，显示状态码和页面内容。按课程简化协议实现，不进行挑战—响应。
- `digest_auth_subverted.py`：独立实现正常认证及课程要求的后门。
- `client_subverted.py`：提供正常访问与课程实验的后门触发方式，并显示结果。

四个提交代码文件不额外依赖自定义辅助模块。尤其是后门版中间件应能独立使用，不能依赖安全版：作业 Part 2 只会分发后门认证的源代码。开发时可以使用服务器已有模块。

## 来源与当前状态

- 2026-11-14 检查作业指定地址 `https://github.com/tan-nayir/py-http-server`，Git 返回 `Repository not found`。
- 本地底座来自 Lab 1 已保存的 `D:\Information Security\Lab 1\py-http-server-main (2).zip`，沿用已用于实验课的项目版本。它与当前无法访问的远端版本是否完全一致，暂时无法确认。
- 原压缩包 SHA256：`DFDF95DA634E09691ED35FFB50F0BE41C14C75CD551FCDD38857725CE00865B1`。
- 提取保留源文件，略去压缩包里的 `__pycache__`、`.pyc` 及 `.vscode` 编辑器配置。
- 底座声明 Python >= 3.9 和 `urllib3 >= 2.3.0`；Windows 环境放在 `.venv/`。
- 三个作业运行辅助文件从 `doc/` 复制到服务器根目录。
- 已将老师提供的 `doc/__init__.py` 原样用于 `py_http_server/middlewares/__init__.py`，两个认证模块均已接入。
- 安全版和后门版启动脚本都使用本机 8080 端口，应分别启动。
- 安全版、后门版、两个客户端及自动化测试均已完成；报告待填写团队信息后生成。
- 已核对提取的 42 个源文件，内容与 Lab 1 压缩包逐项一致。
- Windows Python 3.13.1 独立环境已安装 urllib3 2.8.0，服务器底座检查通过：HTTP 200 且返回内容与文件一致。
- Ubuntu 已另建 `/var/tmp/assignment1-secure-venv` 独立环境，使用 Python 3.12.3 和 urllib3 2.8.0。Windows 与 Ubuntu 均通过全部 22 项安全版测试，IPv6 测试未跳过。
- 2026-11-15 将实验客户端改为 `--precision BITS`，移除旧客户端兼容说法；Windows 完整测试套件共 53 项全部通过。报告原理草稿位于 `report/report_draft.md`，团队信息补齐后再制作一页 PDF。
- 2026-11-15 后续复核：新增启动脚本兼容性、摘要前缀碰撞及取整边界测试；Windows 与 Ubuntu 各通过全部 57 项测试，无跳过。最新证据与限制见 `tests/verification.md`。报告 PDF 和最终打包按用户要求暂缓。
- 2026-11-15 客户端健壮性修复：两个客户端均修复 GBK 终端输出 emoji 时崩溃、输出管道关闭时异常退出的问题。Windows 与 Ubuntu 各通过全部 67 项测试，无跳过；包含真实子进程退出检查。

## 运行安全版

在 `Assignment1` 文件夹打开两个终端。第一个终端启动：

```powershell
.\.venv\Scripts\python.exe -B .\tests\run_secure_server.py
```

第二个终端运行客户端：

```powershell
.\.venv\Scripts\python.exe -B .\py-http-server\client.py
```

输入 `alice` / `mushroom` 或 `root` / `password`，应显示 `HTTP 200 OK` 和 README 内容。输入错误密码应显示 `HTTP 401 UNAUTHORIZED`（状态描述的大小写以服务器为准）。密码输入时不显示字符。结束服务器按 Ctrl+C。

可以提供其他资源地址，例如：

```powershell
.\.venv\Scripts\python.exe -B .\py-http-server\client.py http://127.0.0.1:8080/missing.txt
```

正确凭据访问不存在的资源返回 404。客户端不跟随重定向；HTTP 非 2xx 或连接失败时退出码为 1，2xx 时为 0。普通用户名需为可打印 ASCII（服务器底座按 ASCII 解析请求头）；密码按 UTF-8 计算哈希，支持非 ASCII 密码。

响应正文按服务端声明的字符集解码；未知或非文本字符集回退到 UTF-8，非法字节使用替代字符。终端不支持的字符以转义形式显示，例如 GBK 终端中的 emoji 显示为 `\U0001f600`，其余可显示文字保持原样。输出写入或刷新失败时会报告 `Output failed` 并返回退出码 1；只有成功显示 2xx 响应才返回 0。

密码文件在启动时读取，修改后需要重启服务器。缺失、重复账号或格式错误的密码文件会明确报错，避免带着不明确的凭据配置运行。

上面的辅助启动器使用绝对路径，可从其他工作目录启动。老师原来的两个启动脚本也已可用，但需要在 `py-http-server` 目录运行，以便读取 `passwords.txt` 和受保护资源。启动器和测试均不属于提交文件。

## 使用老师的启动脚本

在 `Assignment1` 目录进入服务器目录，并选择其中一个服务器启动：

```powershell
Set-Location .\py-http-server
..\.venv\Scripts\python.exe -B .\start_server_digest.py
```

实验版将最后一项换为 `start_server_subverted.py`。两者使用相同端口，不要同时运行。在另一个终端进入同一目录后，可运行：

```powershell
..\.venv\Scripts\python.exe -B .\client_subverted.py --precision 3
```

实验版服务端下，输入已登记账号和错误密码可取得资源；省略 `--precision 3` 时，同一错误密码返回 401。安全版服务端在两种情况下都拒绝错误密码。客户端与实验服务端现统一允许 1–256 位，0 和大于 256 的值会被拒绝。但范围检查约束的是位数，1–3 除以 4 取整后仍会得到零字符比较。这是已记录的实验漏洞，不是安全精度协商；参数范围一致不代表已证明更难发现。

## 运行安全版测试

```powershell
.\.venv\Scripts\python.exe -B -W error -m unittest discover -s .\tests -p test_secure_auth.py -v
```

Ubuntu 独立环境的复验命令：

```bash
/var/tmp/assignment1-secure-venv/bin/python -B -W error -m unittest discover -s '/mnt/d/Information Security/Assignment1/tests' -p test_secure_auth.py -v
```

2026-11-15：两个环境各通过 22 项测试，覆盖合法/非法凭据、认证头解析、空密码文件、新账号、空密码、UTF-8 密码、真实 HTTP 传输、约 340 KB 正文、401 后继续访问、404、IPv4/IPv6、客户端交互及错误提示、重定向不跟随。测试将 Python 警告视作错误，并逐项核对 42 个服务器原始文件与 Lab 1 压缩包一致。Ubuntu 为本机 WSL 环境，并非学校 QMB PC 的原机验收。

本项目使用课程简化 Digest：`response = SHA256(password)`。没有 nonce 或挑战—响应，截获的摘要可被重放；这与课程基线一致，不应视为完整 RFC 7616 实现。

完整测试（当前共 67 项）在 `Assignment1` 目录运行：

```powershell
.\.venv\Scripts\python.exe -B -W error -m unittest discover -s .\tests -v
```

Ubuntu 完整复验：

```bash
/var/tmp/assignment1-secure-venv/bin/python -B -W error -m unittest discover -s '/mnt/d/Information Security/Assignment1/tests' -v
```

## 检查服务器底座

在 `Assignment1` 目录运行：

```powershell
.\.venv\Scripts\python.exe .\tests\check_base_server.py
```

这个检查会临时启动一个仅监听本机的服务器，读取服务器 README 并确认 HTTP 200 和文件内容一致，随后关闭检查启动的服务器。它只验证服务器底座；摘要认证由上面的完整测试验证。

Ubuntu 可以另建 Linux 虚拟环境，并用其 Python 运行同一个检查；不要直接使用 Windows 的 `.venv`。

## 最终提交

从开发目录和报告目录复制最终版本到 `submission/`，其中只放：

```text
digest_auth.py
client.py
digest_auth_subverted.py
client_subverted.py
report.pdf
```

以团队名称命名 ZIP，将这五个文件直接放在 ZIP 根目录。不要打包整个项目、资料、测试、环境或老师提供的辅助文件。报告最多一页，包含团队名称、成员、漏洞位置、触发步骤、隐蔽性说明，以及为高分准备的方案研究与比较。

先完成并测试安全版，再完成后门版，最后整理报告并检查提交清单。
