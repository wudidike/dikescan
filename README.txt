
## 安装

```bash
pip install -r requirements.txt
```

## 使用方法

### 扫描模式

工具支持三种扫描模式（默认混合扫描）：

```bash
# 混合扫描（默认）- 先爬虫后字典，合并去重
python scanner.py -u http://example.com

# 仅字典扫描
python scanner.py -u http://example.com --mode wordlist

# 仅爬虫扫描（无需字典）
python scanner.py -u http://example.com --mode crawl
```

### 基本扫描（默认1线程）

```bash
# 默认1线程，低速扫描
python scanner.py -u http://example.com

# 关闭随机延时可提升速度
python scanner.py -u http://example.com --no-random-delay
```

### 多线程扫描

```bash
# 10线程扫描（threads > 5时Linux/Mac自动启用异步模式）
python scanner.py -u http://example.com -t 10

# 推荐配置：关闭随机延时 + 高并发
python scanner.py -u http://example.com -t 10 --no-random-delay
```

### 异步模式（高性能）

当并发数较高时（threads > 5 或 crawl_threads > 5）：
- **Linux/Mac**：自动启用异步模式
- **Windows**：自动使用线程模式（避免兼容性问题）

```bash
# 强制启用异步模式（Linux/Mac推荐）
python scanner.py -u http://example.com -t 10 --crawl-threads 5 --async

# 异步模式优势：更高并发、更低CPU占用
```

### 使用自定义字典

```bash
# 扫描字典文件夹中所有txt文件（默认）
python scanner.py -u http://example.com -w dict

# 指定单个字典文件
python scanner.py -u http://example.com -w dict/common.txt
```

### 爬虫深度控制

```bash
python scanner.py -u http://example.com --crawl-depth 3
```

### 优先级扫描（敏感路径优先）

```bash
python scanner.py -u http://example.com --priority-scan
```

### 定时扫描

```bash
# 指定时间启动
python scanner.py -u http://example.com --schedule-time "2024-01-01 10:00:00"

# 间隔循环扫描（每24小时）
python scanner.py -u http://example.com --schedule-interval 24
```

### 断点续扫

```bash
python scanner.py -u http://example.com --resume
```

### 自定义请求头和代理

```bash
python scanner.py -u http://example.com --headers "Cookie:xxx;Referer:xxx" --proxy "http://127.0.0.1:8080"
```

### 自定义状态码筛选

```bash
# 只保留200和403状态码
python scanner.py -u http://example.com --include-status "200,403"

# 排除404状态码
python scanner.py -u http://example.com --exclude-status "404"
```

## 功能特性

- **三种扫描模式**: 仅字典、仅爬虫、混合扫描（默认）
- **字典自动加载**: 默认扫描dict文件夹下所有txt文件
- **爬虫增强**: 自动爬取站点路径、支持深度控制、路径提取
- **智能处理**: 敏感路径标记、优先级扫描
- **异步模式**: 高并发自动启用，协程驱动，更高性能更低CPU
- **交互控制**: 优雅暂停/退出、断点续扫、实时进度
- **定时扫描**: 定时启动、间隔循环
- **结果处理**: 高亮展示、CSV导出、兜底保存
- **容错兼容**: UA池切换、代理支持、编码处理

## 项目结构

```
web-path-scanner/
├── scanner.py          # 主程序
├── requirements.txt   # 依赖
├── README.md          # 使用文档
└── dict/              # 字典文件夹（默认）
    └── common.txt     # 示例字典
```
