# gsb-0031 本地日志文件异常模式分析器

基于 Python CLI 的多格式日志异常模式分析工具。支持普通文本日志、JSON Lines、Nginx access/error 日志解析，
提供异常指纹归一化去重、分钟/小时/天三级趋势统计、关键字/级别阈值告警、以及控制台/JSON/CSV/Markdown 四种输出。

---

## 目录

- [安装环境](#安装环境)
- [快速开始](#快速开始)
- [命令参数](#命令参数)
- [支持的日志格式](#支持的日志格式)
  - [普通文本日志](#1-普通文本日志)
  - [JSON Lines 日志](#2-json-lines-日志)
  - [Nginx access 日志](#3-nginx-access-日志)
  - [Nginx error 日志](#4-nginx-error-日志)
- [字段映射配置](#字段映射配置)
- [关键字规则配置](#关键字规则配置)
- [告警规则配置](#告警规则配置)
- [异常指纹归一化](#异常指纹归一化)
- [报告导出示例](#报告导出示例)
  - [CSV 报告](#1-csv-报告)
  - [Markdown 报告](#2-markdown-报告)
  - [JSON 输出](#3-json-输出)
- [完整验证命令](#完整验证命令)
- [运行单元测试](#运行单元测试)

---

## 安装环境

- **Python 版本**: 3.8+（已在 3.11 / 3.13 验证）
- **依赖**: 仅使用 Python 标准库，无第三方依赖需要安装

```bash
# 克隆或进入项目目录即可使用
cd gsb-0031
python log_analyzer.py --help
```

---

## 快速开始

```bash
# 1. 基础分析：扫描目录，默认分析 ERROR/WARNING/CRITICAL 级别
python log_analyzer.py ./sample_logs

# 2. 带关键字规则
python log_analyzer.py ./sample_logs -r keywords_rules.json

# 3. 同时导出 CSV 和 Markdown 报告
python log_analyzer.py ./sample_logs -r keywords_rules.json \
    -o report.csv --markdown report.md

# 4. JSON 格式输出（便于脚本消费）
python log_analyzer.py ./sample_logs -r keywords_rules.json --json > result.json

# 5. 按时间范围筛选
python log_analyzer.py ./sample_logs \
    --start "2024-01-15 00:00:00" \
    --end "2024-01-16 23:59:59"

# 6. 指定 JSON Lines 格式 + 自定义字段映射
python log_analyzer.py app.jsonl --format json --mapping field_map.json

# 7. 分析 Nginx 访问日志
python log_analyzer.py access.log --format nginx-access

# 8. 启用告警规则
python log_analyzer.py ./sample_logs -r keywords_rules.json --alert-rules alert_rules.json
```

---

## 命令参数

| 参数 | 类型 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `path` | 位置参数 | 必填 | 日志文件或目录路径（支持递归扫描） |
| `-r, --rules` | str | None | 关键字规则 JSON 文件路径 |
| `--alert-rules` | str | None | 告警规则 JSON 文件路径 |
| `--start` | datetime | None | 起始时间过滤（格式 `YYYY-MM-DD HH:MM:SS` 或 `YYYY-MM-DD`） |
| `--end` | datetime | None | 结束时间过滤 |
| `--top` | int | 10 | Top N 异常模式/指纹显示数量 |
| `-o, --output` | str | None | CSV 报告导出路径 |
| `--markdown` | str | None | Markdown 报告导出路径 |
| `--levels` | str | `ERROR,FATAL,CRITICAL,WARNING,WARN` | 要分析的日志级别，逗号分隔 |
| `--json` | flag | False | 以 JSON 格式输出结果到 stdout |
| `--format` | enum | `auto` | 日志格式：`auto` / `text` / `json` / `nginx-access` / `nginx-error` |
| `--mapping` | str | None | 字段映射配置 JSON（用于自定义 JSON 字段名） |

---

## 支持的日志格式

### 1. 普通文本日志

支持两种常见模式：

```
# 模式 A：时间戳 + 级别 + [模块] + 消息
2024-01-15 08:30:01 ERROR [PaymentProcessor] Connection timeout

# 模式 B：[时间戳] + [级别] + [模块] + 消息
[2024-01-15T12:00:00.001] [ERROR] [ApiGateway] Upstream timed out
```

支持的日志级别：`DEBUG` / `INFO` / `WARNING` / `WARN` / `ERROR` / `FATAL` / `CRITICAL` / `TRACE`

### 2. JSON Lines 日志

每行一个 JSON 对象，自动识别以下常见字段名（也可通过 `--mapping` 自定义）：

- **时间戳**: `timestamp`, `time`, `ts`, `@timestamp`, `datetime`, `date`
- **级别**: `level`, `severity`, `log_level`, `loglevel`
- **模块**: `module`, `service`, `component`, `logger`, `app`
- **消息**: `message`, `msg`, `content`, `log`, `text`

示例：

```json
{"timestamp":"2024-01-15T09:00:00","level":"ERROR","module":"Payment","message":"Connection timeout order=123"}
{"time":"2024-01-15 09:05:00","severity":"WARN","service":"Auth","msg":"Failed login"}
```

### 3. Nginx access 日志

标准 combined 格式：

```
192.168.1.1 - - [15/Jan/2024:08:30:01 +0000] "POST /api/pay HTTP/1.1" 500 1024 "-" "curl/7.0"
```

HTTP 状态码到日志级别的映射：
- `5xx` → `ERROR`
- `4xx` → `WARNING`
- `2xx` / `3xx` → `INFO`（默认级别过滤不包含，需通过 `--levels INFO,...` 开启）

### 4. Nginx error 日志

```
2024/01/15 08:30:01 [error] 1234#5678: *9001 upstream timed out, client: 192.168.1.1, server: example.com, request: "POST /api HTTP/1.1", host: "example.com"
```

Nginx 级别到标准级别的映射：
- `alert` / `crit` → `CRITICAL`
- `error` → `ERROR`
- `warn` → `WARNING`
- `notice` / `info` → `INFO`
- `debug` → `DEBUG`

---

## 字段映射配置

当 JSON Lines 日志使用自定义字段名时，通过 `--mapping mapping.json` 指定字段映射：

```json
{
  "timestamp": "ts",
  "level": "log_level",
  "message": "content",
  "module": "app"
}
```

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| `timestamp` | 是 | 时间戳字段在原始 JSON 中的 key |
| `level` | 是 | 日志级别字段 key |
| `message` | 是 | 日志消息字段 key |
| `module` | 否 | 模块/服务字段 key（缺失则默认 `UNKNOWN`） |

**使用示例**：

```bash
# 输入 app.jsonl 内容：
# {"ts":"2024-01-15 09:00:00","log_level":"error","app":"PaySvc","content":"Timeout"}
python log_analyzer.py app.jsonl --format json --mapping mapping.json
```

---

## 关键字规则配置

JSON 数组格式，每条规则包含 `name`（展示名）和 `pattern`（正则表达式）：

```json
[
  {
    "name": "连接超时",
    "pattern": "timeout",
    "ignore_case": true
  },
  {
    "name": "数据库死锁",
    "pattern": "deadlock|exhausted",
    "ignore_case": true
  },
  {
    "name": "空指针异常",
    "pattern": "NullPointerException",
    "ignore_case": false
  }
]
```

| 字段 | 必填 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `name` | 是 | - | 规则展示名（用于统计和告警） |
| `pattern` | 是 | - | Python 正则表达式 |
| `ignore_case` | 否 | true | 是否忽略大小写匹配 |

项目已内置 [keywords_rules.json](keywords_rules.json) 包含 15 条常见规则，可直接使用。

---

## 告警规则配置

JSON 对象格式，`alerts` 字段为规则数组，支持两种告警类型：

```json
{
  "alerts": [
    {
      "type": "keyword",
      "keyword": "超时错误",
      "threshold": 5,
      "window_minutes": 10,
      "risk": "HIGH"
    },
    {
      "type": "level",
      "level": "ERROR",
      "threshold": 20,
      "window_minutes": 60,
      "risk": "HIGH"
    }
  ]
}
```

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| `type` | 是 | 告警类型：`keyword`（关键字维度）或 `level`（级别维度） |
| `threshold` | 是 | 触发阈值（窗口内出现次数 >= 阈值触发） |
| `window_minutes` | 是 | 滑动窗口大小（分钟） |
| `keyword` | keyword 类型必填 | 要监控的关键字规则名（与关键字规则的 `name` 对应） |
| `level` | level 类型必填 | 要监控的日志级别，如 `ERROR` |
| `risk` | 否 | 告警风险等级，默认 `HIGH` |

**示例语义**：
- 关键字「超时错误」在 10 分钟内出现 >= 5 次 → 触发 HIGH 告警
- 级别 `ERROR` 在 60 分钟内出现 >= 20 次 → 触发 HIGH 告警

风险等级评估综合考虑：日志级别（CRITICAL=3/ERROR=2/WARNING=1）+ 关键字命中数 + 告警命中数×2，
总分 >=5 → `HIGH`，>=3 → `MEDIUM`，>=1 → `LOW`，否则 `INFO`。

---

## 异常指纹归一化

为了对"同类异常"做聚合去重，分析器会对日志消息做归一化处理，将动态片段替换为占位符，
再结合 `级别 + 模块 + 归一化消息` 生成 16 位 MD5 指纹。

已内置的归一化规则：

| 占位符 | 匹配内容 | 示例 |
| --- | --- | --- |
| `{IP}` | IPv4 地址（含端口） | `192.168.1.100:8080` |
| `{UUID}` | UUID | `550e8400-e29b-41d4-a716-446655440000` |
| `{HEX}` | 16 进制串（>=6 位） | `0xffa1b2` / `DEADBEEF` |
| `{LONG_ID}` | 13-19 位长整数 | `123456789012345` |
| `{NUMBER}` | 4 位及以上整数 | `12345` |
| `{REF_ID}` | 带前缀的引用 ID | `order_123` / `req_abc-xyz` / `user_999` |
| `{DURATION}` | 耗时数字+单位 | `250ms` / `5s` / `30 minutes` |
| `{ADDR}` | 内存地址 | `0x7fff1234` |
| 上下文占位 | line/port/code/status + 数字 | `line {NUMBER}` / `port {NUMBER}` |

**示例**：

```
原始 1: User 12345 login failed from 192.168.1.1 order_abc-001 after 500ms
原始 2: User 99999 login failed from 10.0.0.5 order_xyz-999 after 1200ms
归一化: User {NUMBER} login failed from {IP} {REF_ID} after {DURATION}
→ 两条记录会被归为同一个异常指纹
```

每个异常指纹会记录：
- **首次出现时间 / 最后出现时间**
- **出现次数**
- **涉及模块列表**
- **涉及来源文件列表**
- **关键字命中集合**
- **示例消息**（第一条原始消息）
- **风险等级**

---

## 报告导出示例

### 1. CSV 报告

```bash
python log_analyzer.py ./sample_logs -r keywords_rules.json -o report.csv
```

包含扩展字段：`file` / `timestamp` / `level` / `module` / **`fingerprint`** / **`risk`** / `keywords` / `message`

```csv
file,timestamp,level,module,fingerprint,risk,keywords,message
E:/app.log,2024-01-15 09:00:00,ERROR,Payment,a1b2c3d4e5f67890,HIGH,"超时;支付相关",Connection timeout order_123
E:/app.log,2024-01-15 10:00:00,WARNING,Auth,f9e8d7c6b5a43210,LOW,"登录失败",Failed login attempt
```

### 2. Markdown 报告

```bash
python log_analyzer.py ./sample_logs -r keywords_rules.json --markdown report.md
```

报告包含以下章节（均为表格形式，可直接粘贴到知识库）：

1. **总体概览** — 扫描文件数、异常总数、指纹种类数、高风险告警数
2. **扫描文件列表** — 每个文件的异常记录数
3. **级别统计** — 各级别次数及占比
4. **模块统计 Top N** — 按模块聚合
5. **关键字命中 Top N** — 关键字规则命中情况
6. **异常指纹 Top N** — 指纹、次数、级别、风险、首次/最后出现时间、模块、示例消息
7. **时间趋势** — 按天 / 按小时 / 按分钟三张表
8. **高风险告警列表** — 触发告警的记录明细（时间、级别、模块、告警原因、消息、来源文件）

### 3. JSON 输出

```bash
python log_analyzer.py ./sample_logs -r keywords_rules.json --json
```

顶层字段：
```json
{
  "files": [],
  "file_counts": {},
  "total_records": 0,
  "by_level": {},
  "by_module": {},
  "by_keyword": {},
  "trends": { "by_minute": {}, "by_hour": {}, "by_day": {} },
  "top_patterns": [],
  "top_fingerprints": [],
  "high_risk_alerts": []
}
```

---

## 完整验证命令

以下命令可作为端到端验证流程（在项目根目录执行）：

```bash
# 0. 运行全部单元测试
python test_log_analyzer.py

# 1. 基础文本日志分析（控制台）
python log_analyzer.py ./sample_logs

# 2. 文本日志 + 关键字规则 + Top 20
python log_analyzer.py ./sample_logs -r keywords_rules.json --top 20

# 3. 时间范围过滤 + 仅分析 ERROR 和 CRITICAL
python log_analyzer.py ./sample_logs \
    --start "2024-01-15 00:00:00" \
    --end "2024-01-15 23:59:59" \
    --levels "ERROR,CRITICAL"

# 4. JSON 输出（管道到 jq 或文件）
python log_analyzer.py ./sample_logs -r keywords_rules.json --json

# 5. 生成 JSON Lines 测试文件并分析
python -c "
import json
lines = [
    {'timestamp':'2024-01-15T09:00:00','level':'ERROR','module':'Payment','message':'Timeout id=1'},
    {'timestamp':'2024-01-15T09:05:00','level':'ERROR','module':'Payment','message':'Timeout id=2'},
    {'timestamp':'2024-01-15T10:00:00','level':'WARNING','module':'Auth','message':'Failed login'},
]
with open('./sample_logs/app.jsonl','w',encoding='utf-8') as f:
    for l in lines:
        f.write(json.dumps(l,ensure_ascii=False)+'\n')
"
python log_analyzer.py ./sample_logs/app.jsonl --format json

# 6. 自定义字段映射
python -c "
import json
with open('./sample_logs/custom.jsonl','w',encoding='utf-8') as f:
    f.write(json.dumps({'ts':'2024-01-15 09:00:00','log_level':'error','app':'PaySvc','content':'DB timeout'})+'\n')
    f.write(json.dumps({'ts':'2024-01-15 10:00:00','log_level':'warn','app':'AuthSvc','content':'Login failed'})+'\n')
"
python -c "
import json
with open('field_map.json','w',encoding='utf-8') as f:
    json.dump({'timestamp':'ts','level':'log_level','message':'content','module':'app'},f)
"
python log_analyzer.py ./sample_logs/custom.jsonl --format json --mapping field_map.json

# 7. 生成 Nginx access 测试日志并分析
python -c "
lines = [
    '192.168.1.1 - - [15/Jan/2024:08:30:01 +0000] \"GET /ok HTTP/1.1\" 200 128 \"-\" \"UA\"',
    '10.0.0.1 - - [15/Jan/2024:09:00:00 +0000] \"POST /api/a HTTP/1.1\" 500 1024 \"-\" \"UA\"',
    '10.0.0.2 - - [15/Jan/2024:09:05:00 +0000] \"POST /api/b HTTP/1.1\" 502 512 \"-\" \"UA\"',
    '10.0.0.3 - - [15/Jan/2024:10:00:00 +0000] \"GET /missing HTTP/1.1\" 404 256 \"-\" \"UA\"',
]
with open('./sample_logs/access.log','w',encoding='utf-8') as f:
    f.write('\n'.join(lines)+'\n')
"
python log_analyzer.py ./sample_logs/access.log --format nginx-access

# 8. 生成 Nginx error 测试日志并分析
python -c "
lines = [
    '2024/01/15 09:00:00 [error] 1234#5678: *1 upstream timed out, client: 10.0.0.1',
    '2024/01/15 10:00:00 [warn] 1234#5678: *3 invalid header, client: 10.0.0.3',
    '2024/01/15 11:00:00 [crit] 1234#5678: *4 no live upstreams while connecting',
]
with open('./sample_logs/error_nginx.log','w',encoding='utf-8') as f:
    f.write('\n'.join(lines)+'\n')
"
python log_analyzer.py ./sample_logs/error_nginx.log --format nginx-error

# 9. 告警规则测试（构造高频异常 + 规则）
python -c "
import json
with open('alert_rules.json','w',encoding='utf-8') as f:
    json.dump({'alerts':[
        {'type':'keyword','keyword':'超时','threshold':2,'window_minutes':60,'risk':'HIGH'},
        {'type':'level','level':'ERROR','threshold':3,'window_minutes':60,'risk':'HIGH'},
    ]},f,ensure_ascii=False)
"
python log_analyzer.py ./sample_logs -r keywords_rules.json --alert-rules alert_rules.json

# 10. 综合导出：CSV + Markdown + JSON 三重输出
python log_analyzer.py ./sample_logs \
    -r keywords_rules.json \
    --alert-rules alert_rules.json \
    -o full_report.csv \
    --markdown full_report.md \
    --json > full_report.json
```

---

## 运行单元测试

```bash
# 运行全部测试（约 100+ 用例，覆盖所有功能点）
python test_log_analyzer.py

# 仅运行特定测试类
python -m unittest test_log_analyzer.TestAnalyzeLogsText -v

# 仅运行特定测试方法
python -m unittest test_log_analyzer.TestExportCSV.test_export_csv_extended_fields -v
```

测试覆盖矩阵：

| 测试类 | 覆盖场景 |
| --- | --- |
| `TestParseTimestamp` | 6 种时间格式 + 非法输入 |
| `TestParseTextLog` | 普通文本日志 8 种边界情况 |
| `TestParseJsonLines` | JSON Lines 标准/别名/自定义映射/损坏输入 |
| `TestParseNginxLogs` | Nginx access/error 状态码映射/级别转换 |
| `TestParseLogLineDispatch` | 格式自动探测 + 强制格式 + 空行 |
| `TestFieldMapping` | 字段映射配置加载/校验 |
| `TestFingerprintNormalization` | IP/UUID/数字/耗时等 9 种归一化 + 指纹碰撞验证 |
| `TestKeywordRules` | 关键字规则加载/正则匹配/大小写 |
| `TestAlertRules` | 告警规则加载/必填字段 |
| `TestRiskAssessment` | 风险等级评分矩阵 |
| `TestCollectLogFiles` | 多种扩展名（log/jsonl/json/txt）目录递归 |
| `TestAnalyzeLogsText` | 文本日志主流程 16 项指标验证 |
| `TestAnalyzeLogsJsonLines` | JSON Lines 自动探测 + 指纹聚合 |
| `TestAnalyzeLogsWithFieldMapping` | 自定义字段映射完整流程 |
| `TestAnalyzeLogsNginx` | Nginx access/error 格式分析 |
| `TestTrendsGranularity` | 分钟/小时/天三级趋势一致性校验 |
| `TestAlertThresholds` | 关键字告警 + 级别告警阈值触发 |
| `TestExportCSV` | CSV 扩展字段（fingerprint/risk/file） |
| `TestExportMarkdown` | Markdown 完整章节校验 |
| `TestAbnormalInputs` | 损坏行/空文件/非 UTF8/超长行/缺失时间戳 |
| `TestIntegrationCLI` | CLI 全部参数 E2E 验证（15 条子用例） |
