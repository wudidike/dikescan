
## 安装

```bash
pip install -r requirements.txt
```

## 使用方法

### 扫描模式

工具支持三种扫描模式（默认混合扫描）：

```bash
# 混合扫描（默认）- 先爬虫后字典，合并去重
python dikescan.py -u http://example.com

# 仅字典扫描
python dikescan.py -u http://example.com --mode wordlist

# 仅爬虫扫描（无需字典）
python dikescan.py -u http://example.com --mode crawl
```

### 基本扫描（默认1线程）

```bash
# 默认1线程，低速扫描
python dikescan.py -u http://example.com

# 关闭随机延时可提升速度
python dikescan.py -u http://example.com --no-random-delay
```

### 多线程扫描

```bash
# 10线程扫描（threads > 5时Linux/Mac自动启用异步模式）
python dikescan.py -u http://example.com -t 10

# 推荐配置：关闭随机延时 + 高并发
python dikescan.py -u http://example.com -t 10 --no-random-delay
```

### 异步模式（高性能）

当并发数较高时（threads > 5 或 crawl_threads > 5）：
- **Linux/Mac**：自动启用异步模式
- **Windows**：自动使用线程模式（避免兼容性问题）

```bash
# 强制启用异步模式（Linux/Mac推荐）
python dikescan.py -u http://example.com -t 10 --crawl-threads 5 --async

# 异步模式优势：更高并发、更低CPU占用
```

### 使用自定义字典

```bash
# 扫描字典文件夹中所有txt文件（默认）
python dikescan.py -u http://example.com -w dict

# 指定单个字典文件
python dikescan.py -u http://example.com -w dict/common.txt
```

### 爬虫深度控制

```bash
python dikescan.py -u http://example.com --crawl-depth 3
```

### 优先级扫描（敏感路径优先）

```bash
python dikescan.py -u http://example.com --priority-scan
```

### 定时扫描

```bash
# 指定时间启动
python dikescan.py -u http://example.com --schedule-time "2024-01-01 10:00:00"

# 间隔循环扫描（每24小时）
python dikescan.py -u http://example.com --schedule-interval 24
```

### 断点续扫

每轮迭代会自动落盘断点（`.scan_resume.json`），中断后加 `--resume` 继续，已完成任务会跳过。

```bash
python dikescan.py -u http://example.com --resume
```

### 回归测试（离线，不联网）

```bash
python test_dikescan.py                    # 46 项纯逻辑与判定层断言
python smoke_target.py                     # 另开一个终端，启动本地靶站 :8899
python dikescan.py -u http://127.0.0.1:8899/ --mode crawl -t 3 --no-random-delay
```

### 自定义请求头和代理

```bash
python dikescan.py -u http://example.com --headers "Cookie:xxx;Referer:xxx" --proxy "http://127.0.0.1:8080"
```

### HTTP 方法与表单探测

默认全部用 GET。工具会自动解析页面里的 `<form>`，提取 `method` 与 `<input name>`，
生成对应的 POST / GET 参数化探测任务。

```bash
# 全队列改用 POST 发送（注意：会对字典和爬虫产出的每个路径都发 POST）
python dikescan.py -u http://example.com -m POST --data "id=1&action=view"

# 指定 JSON 请求体
python dikescan.py -u http://example.com -m POST --data '{"id":1}' --content-type application/json

# 只探测 HEAD（省流量，先判存在性）
python dikescan.py -u http://example.com -m HEAD

# 关闭表单探测
python dikescan.py -u http://example.com --no-scan-forms
```

支持方法：GET / HEAD / POST / PUT / DELETE / OPTIONS / PATCH

### 响应体敏感信息匹配

200 响应（非二进制）会自动匹配以下类型，命中后终端标红、写入 CSV 的 `secrets` 列：

| 类型 | 说明 |
|---|---|
| PRC_ID / SG_NRIC / MY_NRIC / HKID | 身份证、NRIC、香港身份证 |
| CN_MOBILE / EMAIL | 手机号、邮箱 |
| CREDIT_CARD | Visa / MasterCard / Amex / Discover |
| PRIVATE_KEY / JWT | 私钥头、JWT |
| AWS_AKIA / GITHUB_TOKEN / GOOGLE_API / SLACK_TOKEN | 云与平台凭据 |
| JDBC_URL / CREDENTIAL | 数据库连接串、password/token/secret 赋值 |
| PRIVATE_IP | 内网地址 |

### 证据落盘

默认把每个有效结果的 HTTP 原始请求与响应写入 `evidence/`，可直接粘进工单或导入 Burp 复现。

```bash
python dikescan.py -u http://example.com --evidence-dir my_evidence
python dikescan.py -u http://example.com --no-evidence     # 关闭
```

### 去重模式

```bash
# redirect（默认）：只按最终落地地址去重，N 个路径都跳同一登录页时只留一条
python dikescan.py -u http://example.com --dedup-mode redirect

# content：按响应内容指纹去重（SPA 站点会被大量合并）
python dikescan.py -u http://example.com --dedup-mode content

# off：不去重
python dikescan.py -u http://example.com --dedup-mode off
```

### 目录尾斜杠变体

```bash
# 为目录型字典条目额外生成 /xxx/ 形态（扫描量约翻倍）
python dikescan.py -u http://example.com --dir-slash
```

### 拼接数量上限

路径片段笛卡尔拼接默认最多生成 20000 条，防止把扫描拖死。

```bash
python dikescan.py -u http://example.com --max-combine 5000
```

### 自定义状态码筛选

```bash
# 只保留200和403状态码
python dikescan.py -u http://example.com --include-status "200,403"

# 排除404状态码
python dikescan.py -u http://example.com --exclude-status "404"
```

## 功能特性

- **三种扫描模式**: 仅字典、仅爬虫、混合扫描（默认）
- **多请求方法**: GET/HEAD/POST/PUT/DELETE/OPTIONS/PATCH，自动从表单生成参数化探测
- **字典自动加载**: 默认扫描dict文件夹下所有txt文件
- **爬虫增强**: 自动爬取站点路径、支持深度控制、路径提取、表单与参数提取
- **统一请求层**: 线程引擎与异步引擎共用同一份判定逻辑，参数语义一致
- **软404基线**: 多维度采样（status/title/body-hash/相对大小），不再靠字节差误杀
- **敏感信息匹配**: PII 与凭据正则，命中即标红并计入报告
- **证据落盘**: HTTP 原始请求与响应，可直接粘工单或导入 Burp
- **智能处理**: 敏感路径标记、优先级扫描
- **异步模式**: 高并发自动启用，协程驱动，更高性能更低CPU
- **交互控制**: 优雅暂停/退出、断点续扫、实时进度
- **定时扫描**: 定时启动、间隔循环
- **结果处理**: 高亮展示、CSV导出、兜底保存
- **容错兼容**: UA池切换、代理支持、编码处理

## 项目结构

```
web-path-scanner/
├── dikescan.py          # 主程序
├── dikescan.py.bak      # 改造前的原始版本备份
├── test_dikescan.py     # 离线回归测试（46 项断言）
├── smoke_target.py      # 本地靶站，用于端到端冒烟（:8899）
├── requirements.txt   # 依赖
├── README.md          # 使用文档
└── dict/              # 字典文件夹（默认）
    └── common.txt     # 示例字典
```
