# 后门设计说明（实验候选，非提交文件）

本目录是**独立实验区**（11-17 建立时未改动 `report/`、`submission/` 或任何待提交文件；2026-11-18 起 C_lean 已落地，见第 9 节）。
用途：为课程作业的"隐蔽后门"提供原理讲解、两个更优候选实现、可运行验证脚本。

## 1. 现有方案为什么能工作

现有 `digest_auth_subverted.py` 的核心是**"零长度比较恒真"**：

```python
width = bits // 4
hmac.compare_digest(stored[:width], response[:width])
```

`hmac.compare_digest("", "")` 返回 `True`。当 `bits` 取 1、2、3 时，整数除法 `bits // 4 == 0`，
两个切片都变成空串，于是任意 64 位 response 都被接受。断言 `0 < bits <= 256` 允许这三个值，
而用户名仍从密码文件查表，所以必须是已注册用户——正好满足 R4。

这是**整数除法下取整 + 空串比较**的组合，本质是类型/边界条件的逻辑缺陷，不是密码学破解。

## 2. 现有方案的两个弱点

1. **隐蔽性**：`bits` 是自定义字段，源码里 `bits // 4` 紧挨着比较，审查者一眼就能定位逻辑异常；
   报告草稿也承认"客户端可选精度本身可疑"。
2. **字符预算**：`( : ,` 合计 61，刚低于及格线 65。评分按该字符数从短到长排名，61 不占优。
   注意：用 HEX 字符串等明显混淆会掉到 6 分档，所以压缩必须保持代码自然可读。

## 3. 两个改进候选

两个候选都保留"零长度比较"的数学核心，但换掉显眼的触发面，并把字符数压到 52/53。

### 候选 A：`candidate_a_compact.py`（推荐，可直接替换）

- 触发字段仍是 `bits`（保持与现有 `client_subverted.py` 兼容），但去掉中间变量、合并 import、
  用 `except Exception` 收敛异常分支，字符数 **61 → 52**。
- 功能与现有实现完全一致；已用项目自带的 **67 项测试套件验证通过**（skipped=1，
  仅因本机缺 Lab 1 原始归档，与代码无关）。
- 提升点：字符排名更靠前；代码更短反而更不像"精心措辞的注释在解释后门"。

### 候选 B：`candidate_b_nonce.py`（隐蔽性更强，需配套客户端）

- 把触发藏进 **RFC 7616 的标准字段 `nc`（nonce count）** 与 `qop=auth`：
  当 `nc` 为偶数时宽度取 0，奇数时取 64。
- 表面上是在做"qop/nc 兼容性处理"，审查者不会像看到 `bits` 那样立刻警觉；
  而且 `nc` 是真实 Digest 协议里本就存在的字段，伪装空间更大。
- 字符数 53。因为它改变了触发字段，**不通过针对 `bits=3` 的现有测试**，
  需要配套修改 `client_subverted.py` 与相应测试后才能替换。

## 4. 触发步骤（以候选 A 为例）

1. 在 `py-http-server` 目录启动 `start_server_subverted.py`。
2. 用任意**已注册**用户名（如 `alice`）和**任意错误密码**发起请求。
3. 在 Authorization 头追加 `bits=3`，例如：

   ```
   Digest username="alice", algorithm=SHA-256,
          response="5e8848...（任意合法 64 位十六进制）", bits=3
   ```

4. 服务器返回 `200 OK` 与资源内容。未注册用户即使带 `bits=3` 仍返回 401。

候选 B 改为追加 `nc="00000002", qop=auth`（偶数 nc）触发。

## 5. 为什么难发现（可用于报告的隐蔽性论证）

- **触发器伪装成正常元数据**：`bits` 被包装成"比较精度协商"，`nc/qop` 本就是 Digest 标准字段。
- **默认值行为完全正常**：不带触发字段时走完整 64 字符比较，合法登录与失败登录都符合预期。
- **输入检查看似严谨**：检查算法、摘要格式、字段数量、数值范围，且用常量时间比较，
  容易让审查者误以为这是安全实现。
- **缺陷藏在实际语义里**：单位从"位"到"十六进制字符"的换算（除以 4）让 1–3 位落到 0，
  这是审查者最不会怀疑的边界。

## 6. 修复建议（蓝队视角）

- 不要相信客户端传来的比较长度； digest 必须**始终**完整比较 64 字符。
- 移除 `bits` / 基于 `nc` 的可变宽度逻辑；`nc` 只应参与规范定义的摘要计算。
- 对"输入范围合法但语义退化到零长度"的比较加断言：宽度必须等于摘要全长。

## 7. 复现命令

```bash
cd Information-Security/Assignment1/design
python verify_candidates.py
```

原始源码的 MD5 为 `bd6f63de55976cad600f121adebf4445`，实验前后一致，提交文件未被改动。

## 8. 隐蔽性提升：把触发器搬进标准字段（C 系列）

### 战场是静态源码审查

Part 2 只分发 `digest_auth_subverted.py` 一个文件，审查者看不到安全版、客户端和测试。所以"代码写得多短"不是隐蔽性的主因，**源码里有没有多余的东西**才是。原方案有三处近乎自白：

1. `bits` 是协议里凭空多出的自定义字段；让客户端决定"比较多少位"本身就是红旗。
2. `width = bits // 4` 紧挨 `[:width]`，注释还写明"把位数换算成 hex 宽度"。
3. 触发值 1/2/3 是小整数边界，做边界测试很容易撞到。

改进原则：触发器放进**必填标准字段**且取值看起来完全正常；缺陷来自"对标准数据一个合理但错误的假设"，而不是为后门新增的分支；保留零长度比较的数学核心，但让 `// 4` 有正当理由；不用 HEX 串等明显混淆（评分封顶 6 分）。

### C 系列：算法名位数推导

```python
bits = int(re.sub("[^0-9]", "", algorithm))
width = bits // 4
```

**注意：这不是 RFC 7616 行为**（2026-11-18 21:50 更正，见第 12 节）。RFC 7616 §3.2 按算法明确给出十六进制长度（MD5 32、SHA-256 与 SHA-512/256 64），§6.1 在 IANA 注册表里把「Hash Algorithm」与「Digest Size」分列登记，§3.4 要求客户端沿用服务端 `WWW-Authenticate` 挑战里给出的 `algorithm`（§3.3 中该指令可省略、默认 MD5）。所以「从算法名提取位数再除以 4」只是本简化实现里一个看起来合理的启发式解析，不是标准做法。但 `SHA-1` / `SHA-2` / `SHA-3` 里的数字是**家族/版本标签，不是位数**，也不是 RFC 7616 注册的 Digest 算法标识：`1 // 4 == 0`，两个切片都变空串，`compare_digest("", "")` 恒真。范围检查 `0 < bits <= 256` 校验的是位数而不是比较宽度——和原方案同构，但外表完全不同。

触发：把 `algorithm=SHA-256` 换成 `algorithm=SHA-1`，其余字段不变，任意已注册用户 + 任意错误密码 → 200。默认 `SHA-256` 仍是完整 64 字符比较。

审查者视角的掩护：没有自定义字段；`SHA-1` 是真实世界常见的哈希算法名（虽非 RFC 7616 注册 token），在只做格式检查的简化实现里看着无害；"算法名末位数字 = 摘要位数"是真实世界常见的解析 bug；`// 4` 是位→hex 的正常换算；`re.fullmatch("sha-?[0-9]+", ...)`、字段数校验、范围校验、常量时间比较看起来都很严谨。**固有弱点**：熟悉 RFC 7616 的审查者会把"客户端自选算法""宽松的 `sha-?[0-9]+` 模式""`SHA-1` 不是注册 token"视为线索，隐蔽性论证不能建立在"这是标准做法"之上。

| 文件 | 触发面 | 字符预算 | 落地代价 |
| --- | --- | --- | --- |
| `candidate_c_algorithm.py` | `algorithm=SHA-1`，无 `bits` | 62 | 需改客户端、测试、报告 |
| `candidate_c_lean.py` | 同上，紧凑写法 | **53** | 同上（推荐） |
| `candidate_c_compat.py` | `algorithm=SHA-1` 或 `bits=3` | 64 | 可直接替换，不动任何其他文件 |

`C_compat` 已临时替换进提交位置跑过完整测试：**67 项 OK（skipped=1，缺 Lab 1 归档）**，随后立即恢复，提交文件 MD5 仍为 `bd6f63de…4445`。它的 `bits` 字段还在，所以隐蔽性提升有限（主要是代码自然度），优势只是零成本落地。

彻底版需要同步改三处：`client_subverted.py`（把 `--precision 3` 翻译成 `algorithm=SHA-1` 或新增 `--algorithm`）、`test_subverted_auth.py` 里针对 `bits=3` 的用例、`report/report_draft.md` 的漏洞位置与触发步骤。这是隐蔽性与改动量的直接权衡，没有两全的写法。

### 还能往哪走

- **触发完全藏进 `response` 内容**：利用 `str.strip(chars)` 的字符集语义——若客户端摘要覆盖 `0-9a-f` 全部 16 种字符，`s.strip(response)` 会把两侧的 hex 摘要都清成空串。字段一个都不用加，动态 fuzz 几乎撞不到，但 `strip(response)` 这行在静态审查下反而显眼，适合黑盒场景。
- **用 `nc` / `qop` 伪装重放检测**：必须避免 `w = 64 if n & 1 else 0` 这种一眼可见的二元分支，最好让退化来自标准取值本身。
- **别追求"零多余代码"**：Part 2 是逐行读 40 行源码，任何一行语义突兀的代码都会被盯上；让每一行都像"本来就该有的校验"比藏得更深更有效。

### 复现

```bash
cd Information-Security/Assignment1/design
python verify_candidates.py
```

已覆盖正确/错误密码、缺失头、未注册用户、多个已注册用户绕过、非触发值、短摘要、MD5 拒绝、`SHA-2`/`SHA-3` 触发、旧 `bits=3` 兼容、字符预算与无 `exec/eval`。

## 9. 2026-11-18 落地状态

用户选择 **C_lean + 配套改动**。已执行：

- `candidate_c_lean.py` 替换 `py-http-server/py_http_server/middlewares/digest_auth_subverted.py`；原 61 字符版备份为 `design/backup/digest_auth_subverted.orig61.py`（MD5 `bd6f63de…4445`），新文件 MD5 `912d82d7…730c`，字符预算 **53**。
- 触发值统一为 `algorithm=SHA-1`。`client_subverted.py` 的 `--precision N` 改为生成 `algorithm=SHA-N`（默认 `SHA-256`），不再追加 `bits=` 字段。
- `test_subverted_auth.py` 全部 `bits=` 用例改为 `with_algorithm()` 重写算法标识，并新增源码不含 `"bits"` 的断言；`test_secure_auth.py` 共享基类里的额外字段改为中性字段。
- `report/report_draft.md`、`README.md`、`tests/verification.md` 已同步；本目录 `verify_candidates.py` 的 `current` 触发器也改为 `SHA-1`。
- Windows 完整套件 **67 项 OK（skipped=1，缺 Lab 1 归档）**；六个候选针对性验证全部 PASS。未在本机 WSL 复跑。

因此第 1–8 节中「提交文件未被改动」、MD5 `bd6f63de…4445`、字符数 61、`bits=3` 触发等表述，均为 **11-17 / 11-18 早些时候的历史快照**，描述的是旧实现；当前提交版本以本节为准。`submission/` 与 `report.pdf` 仍未生成。

## 10. 2026-11-18 第二轮：外观层还能不能再压

### 剩余的三处静态红旗

C_lean 落地后触发值已藏进必填标准字段，但 Part 2 是逐行读源码，审查者仍会被三处外观直接引到答案：

1. 首行 docstring 写着 `algorithm-derived digest width`，等于先告诉你"去看宽度"。
2. `a / d / f / x / g / b / w` 全是单字母局部变量，看起来像专为字符排名压缩过。
3. `hmac.compare_digest(self.pw[...][:w], x[:w])` 把两个切片直接写在认证判断的最后一行，是整份源码里唯一"不该存在"的形状。

**关键约束**：评分只数 `(`、`:`、`,` 三个字符。变量名长度、docstring 文案、语句位置都不计入预算；把两处切片移到数据准备区，`(` / `:` / `,` 一个都不增加（切片仍各带一个冒号）。所以外观重构是零成本。

### 候选 D：`candidate_d_facade.py`

- docstring 改为描述"启动时读取密码文件、凭据与存储摘要比对后再交给文件路由"，不含 width / bits / derived / precision 任何一个词。
- 局部变量改为 `scheme / data / items / fields / response / algorithm / bits / width / expected / supplied / conn / request`。
- 两个切片提前算成 `expected` 与 `supplied`，认证判断行只剩 `hmac.compare_digest(expected, supplied)`，看上去就是标准的全量常量时间比较。
- 行为逐项不变：触发仍是 `algorithm=SHA-1`（及 `SHA-2` / `SHA-3`），边界 1–256、未注册用户、短摘要、MD5 拒绝、独立加载都与 C_lean 一致。

验证：`verify_candidates.py` 中 D_facade 的 17 项针对性检查全部 PASS（含"比较行无可见切片""docstring 无提示词""无单字母宽度变量"三条外观断言）；临时替换进提交位置跑完整套件 **67 项 OK（skipped=1）**，随后恢复。字符预算 **53**（26 / 11 / 16），与 C_lean 完全相同。提交文件 MD5 仍为 `912d82d7…730c`。

### 机制层的天花板（不建议再动）

`bits = int(re.sub("[^0-9]", "", algorithm))` 与 `width = bits // 4` 在只支持 SHA-256 的课程简化协议里本就是多余的：一个"正确"的实现不需要从算法名推导宽度，摘要长度固定 64。任何认真追问"为什么要算宽度"的审查者都会找到后门，外观重构只能拖慢"扫一眼"的那一类。

要彻底消掉截断比较，得换成 `str.strip(chars)` 字符集语义或认证头解析歧义一类机制（见第 8 节）。它们在黑盒 fuzz 下几乎撞不到，但 `.strip(` 或额外分支在逐行静态审查下比 `// 4` 更扎眼，是"黑盒变强、白盒变弱"的倒退。触发值也锁死：`256 // 4 == 64` 必须成立，而恒真要求 `bits // 4 == 0`，所以只有 `SHA-0/1/2/3`；改换算常数会破坏正常认证与现有边界测试。

### 比源码更实际的风险：分发面

README 记录的是"Part 2 只分发后门认证源码"，但 `submission/` 里还有 `client_subverted.py`、`digest_auth.py`、`client.py`、`report.pdf`。若实际分发整个 ZIP：客户端的 `--precision` / `BITS` / `Advertise a digest width` 文案、`report.pdf` 中的漏洞位置与行号、以及安全版与后门版的一次 diff，都会让源码层面的隐蔽性论证失效。建议把客户端的 `--precision N` 中性化为 `--algorithm SHA-1`（并同步测试、README、报告），同时向作业说明确认真实分发范围。

落地 D 只需同步 `report/report_draft.md` 里引用的行号与变量名 `b` / `w` / `g`；测试与 README 因行为和预算都不变，无需改动。

## 11. 2026-11-18 [P2] 下游异常被误报为 401（已定位，修复候选待落地）

### 结论：审查意见成立

当前提交版 `digest_auth_subverted.py` 的 `__call__` 把 `return self.next(c, r)` 放在 `try` 内（第 34 行），而 `except Exception: pass` 覆盖整个块（第 35–36 行）。凭据正确、下游处理器抛异常时：异常被吞，函数落到末尾返回 401。

连接层 `py_http_server/networking/connection.py` 第 49 行调用处理器链，第 62–68 行用 `except Exception as exc: LOG.exception(...)` 记录错误。异常在中间件内被吞后，连接层拿到的是一个正常的 401 响应对象，`resp.send_to(...)` 照常执行，**日志里不会出现任何 traceback**。客户端看到"认证失败"，服务端故障被伪装成用户输错密码。

严格说只吞 `Exception` 子类；`KeyboardInterrupt` / `SystemExit`（`BaseException`）仍会传播。

### 复现证据

`design/check_downstream_exception.py` 用正确凭据 + 会抛异常的下游，逐一测了六个版本：

| 版本 | RuntimeError | KeyError | OSError |
| --- | --- | --- | --- |
| 当前提交（C_lean） | HIDDEN → 401 | HIDDEN → 401 | HIDDEN → 401 |
| 原 61 字符版 | 传播 | **HIDDEN → 401** | 传播 |
| 候选 A / C_lean | HIDDEN → 401 | HIDDEN → 401 | HIDDEN → 401 |
| 安全版 `digest_auth.py` | 传播（正确） | — | — |
| D_facade / E_fix（已修） | 传播 | 传播 | 传播 |

**历史来源**：原 61 字符版用 `except (IndexError, KeyError, ValueError)`，但 `self.next` 同样在 try 内 —— 结构性缺陷本来就有，只是只吞三种类型。11-18 为压字符数改成 `except Exception`（候选 A 起，C_lean 继承）后，覆盖面扩大到所有 `Exception` 子类，问题才变得明显。不是 C 系列新引入，是被放大。

### 修复：把下游调用移出 try

`design/candidate_e_fix.py`（基于当前提交结构）与更新后的 `design/candidate_d_facade.py` 都改成：

```python
    try:
        ...
        allowed = <全部认证条件>
    except Exception:
        allowed = False
    if allowed:
        return self.next(c, r)
    return self.h.status(401, ...)
```

`try` 只覆盖解析与比较（这里的异常确实该 fail-closed），下游调用在 `try` 外，异常原样传到连接层。**字符预算不变**：`if <条件>:` 少一个冒号、`if allowed:` 多一个冒号，正好抵消，仍是 53（26/11/16）。

验证：`verify_candidates.py` 新增 E_fix 与「downstream exception propagates」断言，8 个候选全部 PASS；临时把 E 替换进提交位置跑完整套件 **67 项 OK（skipped=1）**，随后恢复。`check_downstream_exception.py` 可长期保留作回归证据。

### 落地注意

### 2026-11-18 21:35 已落地

用户确认「修复提交文件」。`candidate_e_fix.py` 已替换 `py-http-server/py_http_server/middlewares/digest_auth_subverted.py`；修复前的 C_lean 备份为 `design/backup/digest_auth_subverted.c_lean53.py`（MD5 `912d82d7…730c`），新文件 MD5 `a7e5e497…8805`，字符预算仍 **53**（26 / 11 / 16）。

`tests/test_subverted_auth.py` 新增 `test_downstream_exceptions_reach_the_connection_layer`，覆盖正确凭据与 `algorithm=SHA-1` 后门两条成功路径下的下游异常传播，完整套件由 67 增至 **68 项 OK（skipped=1）**。`verify_candidates.py` 把 `current` 也纳入「downstream exception propagates」断言，`check_downstream_exception.py` 中 `current` 对 `RuntimeError` / `KeyError` / `OSError` 均为 propagated。八个候选针对性验证全部 PASS。

行号 27 / 28 / 29 / 32 / 33 与变量名 `b` / `w` / `g` 均未变，报告中的漏洞位置描述继续有效；仅测试数需由 67 改为 68。外观重构候选 `D_facade` 已在实验区同步修好同一缺陷，尚未落地（落它需要重写报告里的行号引用）。

## 12. 2026-11-18 21:50 RFC 7616 表述更正

用户指出：报告把"从算法名提取数字决定比较宽度"称为标准做法，与 RFC 7616 不符。已核实 rfc-editor 原文（https://www.rfc-editor.org/rfc/rfc7616.txt）：

- **§3.4**：`The values of the opaque and algorithm fields must be those supplied in the WWW-Authenticate response header field for the entity being requested.` 客户端沿用服务端挑战给出的算法，不自行选择；§3.7 的多挑战场景也是由服务端按偏好列出、客户端挑第一个支持的。
- **§3.3**：`algorithm` 是指示算法的字符串，未给出时默认 MD5；不是必填，不理解的算法应忽略该挑战。
- **§3.2**：按算法**明确列举**十六进制长度：MD5 为 32，`SHA-256` 与 `SHA-512/256` 为 64；RFC 7616 没有单独的 `SHA-512` token。
- **§6.1**：IANA "Hash Algorithms for HTTP Digest Authentication" 注册表中 `Hash Algorithm` 与 `Digest Size` 是**两列**，算法名和输出位数分别登记。
- 全文无 `SHA-1`；`SHA-1` / `SHA-2` / `SHA-3` 是家族或版本标签，不是注册的 Digest 算法标识。

因此本项目的 `algorithm=SHA-1` 触发、`re.fullmatch("sha-?[0-9]+", ...)` 宽松模式和 `bits // 4` 宽度推导，都是**课程简化协议里不符合 RFC 的实现细节**，不能包装成标准做法。已更正 `report/report_draft.md`（第 7 / 15 / 19 / 23 行）、`README.md`（第 107 行）、本文件第 8 节，以及 `candidate_c_algorithm.py` 第 20 行注释。

**对隐蔽性的影响**：第 8 节把该写法描述为标准实践的说法不成立，方案固有的可疑点变成三个——客户端自选算法（违反 §3.4）、`SHA-1` 非注册 token、`sha-?[0-9]+` 过宽；这些已写入报告 limits 与本文件第 8 节。注册 token 只有 MD5 / SHA-256 / SHA-512/256，没有数字 1 / 2 / 3，所以现有 `// 4` 零宽度机制**无法用合规 token 触发**；要消除这个弱点必须换机制，不是改文案。代码与测试未改，68 项测试不受影响。
