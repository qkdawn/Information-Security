# Information Security — Assignment1

本仓库保存 Assignment1 的课程资料、HTTP 服务器、认证模块、客户端、测试和报告草稿。使用与运行说明见 [Assignment1/README.md](Assignment1/README.md)。

Lab 1、Lab 2、课件、本机虚拟环境和临时文件不纳入仓库。

## 安装与测试

建议使用 Python 3.12 或更高版本（已有 Windows Python 3.13 与 Ubuntu Python 3.12 测试记录）。在仓库根目录运行：

```powershell
python -m venv Assignment1/.venv
Assignment1/.venv/Scripts/python.exe -m pip install -e ./Assignment1/py-http-server
Assignment1/.venv/Scripts/python.exe -B -W error -m unittest discover -s Assignment1/tests -v
```

Linux / macOS 使用 `Assignment1/.venv/bin/python` 替换上述虚拟环境解释器路径。

测试共 93 项。其中一项源码完整性检查需要本地另存的 Lab 1 原始服务器压缩包；从本仓库克隆后，该项会自动跳过，其余 92 项可正常运行。归档路径与期望文件数可通过 `ASSIGNMENT1_LAB_ARCHIVE` / `ASSIGNMENT1_LAB_FILE_COUNT` 覆盖。

认证和实验后门用于课程作业；`passwords.txt` 中是随作业提供的测试账号。**该实现无 nonce、无 TLS、无速率限制，摘要可重放，禁止用于任何真实部署。** 报告仍为草稿，最终一页 PDF 和提交压缩包尚未生成。

服务器底座及其中第三方代码的许可见 `Assignment1/py-http-server/LICENSE`、`Assignment1/py-http-server/py_http_server/common/requests.LICENSE` 和 `requests.NOTICE`。

## 工程化检查

```powershell
Assignment1/.venv/Scripts/python.exe -m pip install -r Assignment1/requirements-dev.txt
Assignment1/.venv/Scripts/python.exe -B -W error -m unittest discover -s Assignment1/tests -v
Assignment1/.venv/Scripts/python.exe -B Assignment1/tests/check_source_constraints.py
Assignment1/.venv/Scripts/python.exe -m coverage run -m unittest discover -s Assignment1/tests
```

评分字符约束已从功能测试移到 `check_source_constraints.py`；`.github/workflows/ci.yml` 在 Python 3.12 / 3.13 上运行同一套测试。

## 分发范围

`Assignment1/design/` 含后门的候选实现、触发值和行号，且已被 Git 跟踪。Part 2 分发前必须排除该目录；`.gitignore` 无法取消已跟踪文件，需要另行确认 `git rm --cached` 或仓库可见性。
