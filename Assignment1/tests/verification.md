# 验证记录 — 2026-11-15

## 本次结果

| 环境 | 测试数 | 失败 / 错误 / 跳过 | 结果 |
| --- | ---: | --- | --- |
| Windows，本项目 `.venv` | 67 | 0 / 0 / 0 | 通过 |
| 本机 WSL Ubuntu，独立 Linux 环境 | 67 | 0 / 0 / 0 | 通过 |

两个环境都使用 `-B -W error -m unittest discover -s tests -v`（Ubuntu 使用测试目录的绝对路径），将 Python 警告作为错误。最新完整控制台输出分别保存于 `verification_windows.txt` 和 `verification_ubuntu.txt`，两次进程退出码均为 0。

## 客户端修复及回归验证

先添加针对性测试，原实现确实出现 GBK 输出 emoji 的 `UnicodeEncodeError`，以及输出写入失败的未处理 `BrokenPipeError`。两个客户端均作如下修复：

- 正文先按响应字符集解码，终端无法编码的字符转义显示；不强制修改终端编码。GBK 测试确认中文保持原样、emoji 转为 `\U0001f600`。
- 输出写入和刷新都纳入错误处理，失败返回 1，避免把未成功显示的响应报成执行成功。
- 命令行入口处理关闭管道后的退出刷新，避免解释器结束时再次产生异常。真实子进程测试在关闭输出管道后检查退出码 1、错误提示，以及不存在 traceback / shutdown exception；Windows 和 Ubuntu 都通过。
- 另行验证未知字符集、非文本编码标签、Latin-1 正文、空正文及响应读取中断后的连接关闭。

以上 5 类测试分别运行于两个独立客户端，因此完整测试数由 57 增至 67。后续又统一了实验服务端的输入位数范围，并更新已有边界测试，测试方法数量仍为 67。

## 新增的有意义检查

- **老师的启动脚本兼容性**：确认两个脚本与 `doc/` 原件字节一致，执行脚本并仅拦截阻塞运行入口，将所构建的真实处理链放到本机临时端口；正确密码返回 200 且正文逐字节一致，错误密码返回 401。此项不验证原脚本的固定 8080 端口能否在当前机器上绑定；独立网络测试另行覆盖 IPv4/IPv6。
- **接近正确的错误摘要**：构造前 63 个十六进制字符全部正确、最后一位错误的响应。安全版始终拒绝，包括客户端声明低精度的情况；实验版默认或完整精度拒绝，252 位模式会接受。这确认短前缀本身也不安全。
- **输入与取整边界**：正确凭据配合每一个整数 1–256 都通过；负数、0、257–259、260 和 264 被拒绝。1–3 的零长度绕过、未知账号拒绝、完整响应格式仍由测试覆盖。范围一致不消除位数转字符数的取整缺陷。
- **源码约束**：后门认证源码三个计数字符合计 61（`(` 为 29、`:` 为 11、`,` 为 21），统计包含注释和字符串；可独立于安全认证模块加载。（此为本日快照；2026-11-18 起改为 53，见文末复验小节。）
- **底座完整性**：检查归档中的 42 个原文件；初始化文件与老师给定文件一致，其余与 Lab 1 原始归档一致。

## 适用边界

这是一套课程简化认证及其故意植入漏洞的测试，不是生产安全认证评估。实验版触发字段的调整不构成隐蔽性保证。测试使用可打印 ASCII 用户名（底座以 ASCII 解析请求头），同时覆盖 UTF-8 密码；不据此宣称支持所有 Unicode 用户名。

WSL Ubuntu 通过不等于已在学校 QMB PC 验收。65 字符以内不保证最高分，评分仍包含相对长度排名、报告质量及其他条件。按用户要求，本轮没有生成最终 PDF 或 ZIP。

## 2026-11-18 落地 C_lean 后的复验

| 项目 | 结果 |
| --- | --- |
| 完整测试套件 | `python -B -W error -m unittest discover -s tests` → 67 项 OK（skipped=1） |
| 跳过原因 | 本机缺 Lab 1 原始归档，`test_original_server_files_unchanged` 跳过；与代码无关 |
| 源码约束 | 53（`(` 26、`:` 11、`,` 16），含注释与字符串；新增断言确认源码不含 `"bits"` 字段 |
| 针对性验证 | `design/verify_candidates.py` 中六个候选全部 PASS |

本轮把后门触发从自定义 `bits` 字段改为协议已有的 `algorithm` 字段：`--precision 1` 生成 `algorithm=SHA-1`，服务端按算法名推导位数并除以 4 得到零宽度。同步改动了 `client_subverted.py`、`test_subverted_auth.py`、`test_secure_auth.py`（共享基类里的中性额外字段）、`README.md`、`report/report_draft.md` 与本文件。上方「252 位模式」「输入 1–256 位」等表述属于 11-15 的历史快照，现对应 `algorithm=SHA-252` 与算法标识位数；字符数 61 已由 53 取代。Windows 与 Ubuntu 各 67 项无跳过的结论属于 11-15 版本，本轮未在 WSL 复跑。（本节的 `--precision 1` 为 11-18 写法；2026-11-20 起客户端主推 `--algorithm SHA-1`，同日后续已彻底移除 `--precision`，实验 token 改由 `ASSIGNMENT1_TRIGGER_TOKEN` 启用。）

## 2026-11-18 21:35 修复下游异常被误报为 401 后的复验

| 项目 | 结果 |
| --- | --- |
| 完整测试套件 | `python -B -W error -m unittest discover -s tests` → **68 项 OK**（skipped=1） |
| 新增回归测试 | `test_downstream_exceptions_reach_the_connection_layer`：正确凭据与 `algorithm=SHA-1` 后门两条成功路径下，下游抛 `RuntimeError` 都必须传播，不得变成 401 |
| 源码约束 | 53（`(` 26、`:` 11、`,` 16），与修复前一致；E_fix 的 MD5 为 `a7e5e497…8805`。**当前提交文件另已落地 D_facade，MD5 为 `da5c0ab9…`**，见文末 2026-11-20 复验 |
| 针对性验证 | `design/verify_candidates.py` 八个候选全部 PASS；`current` 纳入「downstream exception propagates」断言 |
| 回归探针 | `design/check_downstream_exception.py`：`current` 对 `RuntimeError` / `KeyError` / `OSError` 均为 propagated，安全版同样传播 |

修复方式：把 `return self.next(...)` 移出 `try`，`try` 只覆盖凭据解析与比较；认证结果存为 `allowed`，`except Exception` 里置 `False`，`try` 外再调用下游。（2026-11-20 更正：当前提交文件并非 E_fix，而是 D_facade，MD5 `da5c0ab9…`；行号为 31 / 32 / 33 / 34–35 / 38 / 39，变量名为 `algorithm` / `bits` / `width` / `expected` / `supplied`，报告中的漏洞位置已按此重写。）修复前的 53 字符版备份于 `design/backup/digest_auth_subverted.c_lean53.py`（MD5 `912d82d7…730c`）。本机未在 WSL 复跑。

## 2026-11-20 全面复核后的复验

| 项目 | 结果 |
| --- | --- |
| 完整测试套件 | `python -B -W error -m unittest discover -s tests -v` → **75 项 OK**（skipped=1，缺 Lab 1 归档），6.950s，Python 3.13.14 |
| 源码约束 | `python -B tests/check_source_constraints.py` → 53（`(` 26、`:` 11、`,` 16），无 `exec` / `eval` / `bits` 字段 |
| 当前提交文件 | `digest_auth_subverted.py` 与 `design/candidate_d_facade.py` 字节一致，MD5 `da5c0ab9a5d3c2d09c3e0868aec64759`，44 行 |
| 资源隔离 | `tests/run_secure_server.py` 改用 `Assignment1/docroot/`；实测 `/README.md` → 200，`/passwords.txt`、`/client_subverted.py`、后门源码 → 404 |

本轮新增覆盖：前导零算法标识与短比较宽度、`--algorithm` 注入与 CLI 参数互斥、密码文件格式差异的行为记录、失败日志不泄露凭据、两个客户端行为等价、包级 star-import 的已知行为。评分字符断言已从 unittest 套件移到 `tests/check_source_constraints.py`。老师提供的启动脚本、底座 42 个源文件与 `middlewares/__init__.py` 因字节一致性约束未改动；`design/` 的 Git 跟踪状态未改，需另行确认分发范围。

## 2026-11-20 L2 加固层落地后的复验

| 项目 | 结果 |
| --- | --- |
| 完整测试套件 | `python -B -W error -m unittest discover -s tests` → **93 项 OK**（skipped=1，缺 Lab 1 归档） |
| 源码约束 | `check_source_constraints.py` → 53；后门源码 MD5 仍 `da5c0ab9a5d3c2d09c3e0868aec64759`，44 行，未改动 |
| 报告同步 | `python -B tools/check_report_sync.py` → PASS；行号 31/32/33/34/35/38/39、变量名、字符预算 53、MD5 前缀全部由 AST 与文件字节自动提取后断言 |
| 触发面收敛 | 错误摘要下直接调用后门中间件有 7 个确定性绕过 token；经 `AlgorithmGuard` 后收敛为 `SHA-1/2/3` 三个，前导零与超长 token 返回 401 |
| 凭据文件 | 缺冒号、重复账号、短哈希、非 UTF-8、文件缺失均抛 `PasswordFileError` 并带路径与行号 |
| 客户端 | `--precision` 已移除；`--algorithm` 默认只允许 `SHA-256`，实验 token 由 `ASSIGNMENT1_TRIGGER_TOKEN` 启用，`--help` 不含触发值 |

本轮改动只涉及 `Assignment1/tools/`（新增 4 个文件）、`client_subverted.py`、两个测试文件与文档/CI；`digest_auth_subverted.py`、老师提供的启动脚本、底座 42 个源文件与 `middlewares/__init__.py` 均未改动。性能微基准在本机噪声过大（同一实现在 14–30 µs 间宽幅波动，且交替测量出现负值增量），不据此判定「优于 / 不劣于」；L2 层属额外评测配置，常规运行不启用时无开销增量。`design/` 的 Git 跟踪状态与仓库可见性仍未改动，需另行确认。
