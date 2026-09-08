#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Web Path Scanner - 目录路径扫描工具
支持字典扫描、爬虫增强、智能路径处理、定时扫描等功能
"""

from __future__ import annotations

import argparse
import asyncio
import aiohttp
import csv
import os
import sys
import time
import signal
import json
import re
import urllib.parse
import random
import threading
import warnings
import hashlib
import uuid
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import Set, List, Dict, Optional, Tuple
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from html.parser import HTMLParser
import html as _html_lib

warnings.filterwarnings("ignore")

import requests
import requests.packages.urllib3.exceptions as _urllib3_exc
requests.packages.urllib3.disable_warnings(_urllib3_exc.InsecureRequestWarning)

VERSION = "1.0.0"
PROGRAM_NAME = "Web Path Scanner"

DEFAULT_SENSITIVE_WORDS = [
    "admin", "backup", "config", "api", "user", "log", "secret",
    "test", "dev", "manage", "org-chart", "intranet", "console",
    "login", "register", "setup", "install", "wp-admin", "administrator",
    "phpmyadmin", "mysql", "postgres", "mongodb", "redis", "elasticsearch",
    "swagger", "docs", "documentation", "debug", "trace", "monitor",
    "status", "health", "metrics", "actuator", "env", "configuration"
]

DEFAULT_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
]

STATUS_CODE_COLORS = {
    200: "\033[92m",
    301: "\033[93m",
    302: "\033[93m",
    403: "\033[91m",
}
COLOR_RESET = "\033[0m"

# ---------------------------------------------------------------------------
# 统一请求层
# 线程引擎与异步引擎消费同一种 Task，产出同一种 RespInfo，
# 再由 Scanner.evaluate() 做唯一一份判定，避免两套逻辑功能漂移。
# ---------------------------------------------------------------------------

SUPPORTED_METHODS = ("GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH")


@dataclass
class Task:
    """一次探测请求的完整描述。"""
    url: str
    method: str = "GET"
    data: Optional[str] = None
    content_type: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    source: str = "wordlist"

    def key(self) -> str:
        """去重键：同 method + 同 url + 同 body 视为同一任务。"""
        return f"{self.method.upper()}|{self.url}|{self.data or ''}"


@dataclass
class RespInfo:
    """标准化的响应信息，与具体 HTTP 客户端无关。"""
    status: int
    url: str
    headers: Dict[str, str]
    content: bytes
    history: List[str]
    elapsed: float
    method: str = "GET"
    request_headers: Dict[str, str] = field(default_factory=dict)
    request_body: str = ""

    @property
    def text(self) -> str:
        return self.content.decode("utf-8", errors="ignore")


# 响应体敏感信息匹配：PII 与凭据。只在前 SCAN_SECRET_MAX_BYTES 字节内匹配。
SCAN_SECRET_MAX_BYTES = 512 * 1024
EVIDENCE_BODY_LIMIT = 32 * 1024

RESULT_FIELDS = [
    "url", "method", "status_code", "status_desc", "scan_time", "title",
    "is_sensitive", "is_sensitive_duplicate", "content_size",
    "redirect_chain", "content_type", "secrets", "evidence_file",
    "dup_count", "note", "cluster",
]

SECRET_PATTERNS: List[Tuple[str, str]] = [
    ("PRC_ID",       r'(?<!\d)[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx](?!\d)'),
    ("SG_NRIC",      r'(?<![A-Za-z0-9])[STFGstfg]\d{7}[A-Za-z](?![A-Za-z0-9])'),
    ("MY_NRIC",      r'(?<!\d)\d{6}-\d{2}-\d{4}(?!\d)'),
    ("HKID",         r'(?<![A-Za-z0-9])[A-Z]{1,2}\d{6}\(\d\)(?![A-Za-z0-9])'),
    ("CN_MOBILE",    r'(?<!\d)1[3-9]\d{9}(?!\d)'),
    ("EMAIL",        r'[\w.+-]+@[\w-]+\.[\w.-]{2,}'),
    ("CREDIT_CARD",  r'(?<!\d)(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[ -]?\d{4}[ -]?\d{4}[ -]?\d{2,4}(?!\d)'),
    ("PRIVATE_KEY",  r'-----BEGIN [A-Z ]*PRIVATE KEY-----'),
    ("JWT",          r'\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}'),
    ("AWS_AKIA",     r'\bAKIA[0-9A-Z]{16}\b'),
    ("GITHUB_TOKEN", r'\bgh[pousr]_[0-9A-Za-z]{20,}'),
    ("GOOGLE_API",   r'\bAIza[0-9A-Za-z_\-]{35}\b'),
    ("SLACK_TOKEN",  r'\bxox[baprs]-[0-9A-Za-z-]{10,}'),
    ("JDBC_URL",     r'\bjdbc:[a-z0-9]+://[^\s"\'<>]+'),
    ("CREDENTIAL",   r'(?i)\b(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key)\s*[=:]\s*["\']?[^\s&"\'<>]{4,}'),
    ("PRIVATE_IP",   r'(?<!\d)(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})(?!\d)'),
]

_COMPILED_SECRET_PATTERNS = [(name, re.compile(p)) for name, p in SECRET_PATTERNS]


def match_secrets(content: bytes) -> List[str]:
    """在响应体前 SCAN_SECRET_MAX_BYTES 字节内匹配敏感信息，返回类型名列表。"""
    if not content:
        return []
    sample = content[:SCAN_SECRET_MAX_BYTES]
    text = sample.decode("utf-8", errors="ignore")
    found = []
    for name, pattern in _COMPILED_SECRET_PATTERNS:
        if pattern.search(text):
            found.append(name)
    return found


class GlobalState:
    def __init__(self):
        self.paused = False
        self.should_exit = False
        self.interrupted = False
        self.lock = threading.Lock()
        self.current_input_mode = threading.Event()
        self.scanning_thread = None


GLOBAL_STATE = GlobalState()


class LinkExtractor(HTMLParser):
    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.base_domain = urllib.parse.urlparse(base_url).netloc
        self.links: Set[str] = set()
        self.tag_stack: List[str] = []
        self.forms: List[Dict] = []
        self._current_form: Optional[Dict] = None

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]):
        self.tag_stack.append(tag)
        attrs_dict = dict(attrs)

        if tag == "form":
            self._current_form = {
                "action": attrs_dict.get("action") or "",
                "method": (attrs_dict.get("method") or "GET").upper(),
                "enctype": attrs_dict.get("enctype") or "application/x-www-form-urlencoded",
                "inputs": [],
            }
            action = self._current_form["action"]
            if action:
                self._process_link(action)
            return

        if self._current_form is not None and tag in ("input", "textarea", "select"):
            name = attrs_dict.get("name")
            if name:
                self._current_form["inputs"].append({
                    "name": name,
                    "type": (attrs_dict.get("type") or "text").lower(),
                    "value": attrs_dict.get("value") or "",
                })
            return

        if tag in ("a", "link", "area"):
            href = attrs_dict.get("href")
            if href:
                self._process_link(href)
        elif tag in ("img", "script", "iframe", "source", "video", "audio", "embed"):
            src = attrs_dict.get("src")
            if src:
                self._process_link(src)
            if tag == "img":
                srcset = attrs_dict.get("srcset")
                if srcset:
                    for candidate in srcset.split(","):
                        candidate = candidate.strip()
                        if candidate:
                            self._process_link(candidate.split()[0])
        elif tag == "object":
            data = attrs_dict.get("data")
            if data:
                self._process_link(data)
        elif tag == "form":
            action = attrs_dict.get("action")
            if action:
                self._process_link(action)
        elif tag == "meta":
            http_equiv = attrs_dict.get("http-equiv", "").lower()
            content = attrs_dict.get("content", "")
            if http_equiv == "refresh" and content:
                match = re.search(r'url=["\']?([^"\';\s]+)', content, re.IGNORECASE)
                if match:
                    self._process_link(match.group(1))

    def handle_endtag(self, tag: str):
        if tag == "form" and self._current_form is not None:
            if self._current_form["inputs"] or self._current_form["method"] == "POST":
                self.forms.append(self._current_form)
            self._current_form = None
        if self.tag_stack and self.tag_stack[-1] == tag:
            self.tag_stack.pop()

    def _process_link(self, link: str):
        if not link or link.startswith(("#", "mailto:", "javascript:", "tel:", "ftp:")):
            return

        if "#" in link:
            link = link.split("#")[0]

        parsed = urllib.parse.urlparse(link)
        query = parsed.query
        path = parsed.path

        if parsed.scheme and parsed.scheme not in ("http", "https"):
            return

        if parsed.netloc and parsed.netloc != self.base_domain:
            return

        if parsed.netloc:
            # 始终用 scheme+netloc+path 重建，不直接用原始 link，
            # 否则后面再拼一次 query 会得到 ?a=1?a=1
            full_url = f"{parsed.scheme or urllib.parse.urlparse(self.base_url).scheme}://{parsed.netloc}{path}"
        else:
            if path.startswith("/"):
                base_parts = urllib.parse.urlparse(self.base_url)
                full_url = f"{base_parts.scheme}://{base_parts.netloc}{path}"
            else:
                base_parts = urllib.parse.urlparse(self.base_url)
                base_path = base_parts.path.rsplit("/", 1)[0] if base_parts.path else ""
                full_url = f"{base_parts.scheme}://{base_parts.netloc}{base_path}/{path}"

        if query:
            full_url = f"{full_url}?{query}"

        self.links.add(full_url)

    def extract_parent_paths(self, paths: Set[str]) -> Set[str]:
        result = set()
        for path in paths:
            parsed = urllib.parse.urlparse(path)
            path_parts = parsed.path.strip("/").split("/")
            for i in range(1, len(path_parts)):
                parent = "/".join(path_parts[:i])
                result.add(f"{parsed.scheme}://{parsed.netloc}/{parent}")
        return result


class CSSParser:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.paths: Set[str] = set()

    def parse(self, css_content: str) -> Set[str]:
        url_pattern = re.compile(r'url\(\s*["\']?([^"\')\s]+)["\']?\s*\)', re.IGNORECASE)
        for match in url_pattern.finditer(css_content):
            url = match.group(1).strip()
            if self._is_valid_web_path(url):
                full_url = self._make_full_url(url)
                if full_url:
                    self.paths.add(full_url)
        return self.paths

    def _is_valid_web_path(self, url: str) -> bool:
        if not url:
            return False
        url_lower = url.lower()
        if any(url_lower.startswith(prefix) for prefix in ['data:', 'javascript:', 'ftp:', 'mailto:', 'tel:', 'css:', 'ios-']):
            return False
        if url.startswith('//'):
            return True
        if url.startswith('/'):
            return True
        if url.startswith('http://') or url.startswith('https://'):
            return True
        return bool(re.match(r'^[a-zA-Z0-9_/.-]+$', url))

    def _make_full_url(self, url: str) -> Optional[str]:
        base_parsed = urllib.parse.urlparse(self.base_url)
        if url.startswith('//'):
            return f"{base_parsed.scheme}:{url}"
        if url.startswith('http://') or url.startswith('https://'):
            return url
        if url.startswith('/'):
            return f"{base_parsed.scheme}://{base_parsed.netloc}{url}"
        base_path = base_parsed.path.rsplit('/', 1)[0] if base_parsed.path else ""
        return f"{base_parsed.scheme}://{base_parsed.netloc}{base_path}/{url}"


class JSParser:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.paths: Set[str] = set()

    def parse(self, js_content: str) -> Set[str]:
        js_content = re.sub(r'//.*?$', '', js_content, flags=re.MULTILINE)
        js_content = re.sub(r'/\*.*?\*/', '', js_content, flags=re.DOTALL)
        path_patterns = [
            r'["\']/(?:[a-zA-Z0-9_-]*/?)+(?:/[a-zA-Z0-9_.-]+)+/?["\']',
            r'["\']\.(?:/[a-zA-Z0-9_-]+)+["\']',
            r'["\']{1,2}/(?:[a-zA-Z0-9_-]+/)*[a-zA-Z0-9_.-]+/?["\']{1,2}',
            r'["\']api["\']?\s*:\s*["\']([^"\']+)["\']',
            r'["\']/api[^"\']*["\']',
            r'fetch\s*\(\s*["\']([^"\']+)["\']',
            r'axios\.(?:get|post|put|delete)\s*\(\s*["\']([^"\']+)["\']',
            r'\.(?:get|post|put|delete)\s*\(\s*["\']([^"\']+)["\']',
            r'router(?:\.push|\.replace|\.go)?\s*\(\s*["\']([^"\']+)["\']',
            r'navigateTo\s*\(\s*["\']([^"\']+)["\']',
            r'window\.location\s*=\s*["\']([^"\']+)["\']',
            r'location\.href\s*=\s*["\']([^"\']+)["\']',
            r'document\.location\s*=\s*["\']([^"\']+)["\']',
            r'import\s*\(\s*["\']([^"\']+)["\']',
            r'require\s*\(\s*["\']([^"\']+)["\']',
            r'loadScript\s*\(\s*["\']([^"\']+)["\']',
            r'resourceUrl\s*:\s*["\']([^"\']+)["\']',
            r'path\s*:\s*["\']([^"\']+)["\']',
            r'url\s*:\s*["\']([^"\']+)["\']',
            r'route\s*:\s*["\']([^"\']+)["\']',
            r'routes\s*:\s*\[[\s\S]*?path\s*:\s*["\']([^"\']+)["\']',
            r'createRoute\s*\(\s*["\']([^"\']+)["\']',
            r'pathToRegexp\s*\(\s*["\']([^"\']+)["\']',
        ]
        for pattern in path_patterns:
            for match in re.finditer(pattern, js_content, re.IGNORECASE):
                path = match.group(0).strip('"\'')
                if self._is_valid_path(path):
                    full_url = self._make_full_url(path)
                    if full_url:
                        self.paths.add(full_url)
        path_var_pattern = r'(?:window|location|document)[\w.]*(?:\+|=)\s*["\']([^"\']+)["\']'
        for match in re.finditer(path_var_pattern, js_content):
            path = match.group(1)
            if self._is_valid_path(path):
                full_url = self._make_full_url(path)
                if full_url:
                    self.paths.add(full_url)
        api_endpoints = self._extract_api_endpoints(js_content)
        for endpoint in api_endpoints:
            if self._is_valid_path(endpoint):
                full_url = self._make_full_url(endpoint)
                if full_url:
                    self.paths.add(full_url)
        return self.paths

    def _extract_api_endpoints(self, js_content: str) -> Set[str]:
        endpoints = set()
        api_patterns = [
            r'(?:api|rest|graphql|v1|v2|v3)[-/][a-zA-Z0-9_/.-]+',
            r'/users?/[/a-z0-9_-]+',
            r'/admin[s]?/[/a-z0-9_-]+',
            r'/auth[/a-z0-9_-]*',
            r'/dashboard[/a-z0-9_-]*',
            r'/settings?[/a-z0-9_-]*',
            r'/profile[s]?[/a-z0-9_-]*',
            r'/product[s]?/[/a-z0-9_-]+',
            r'/order[s]?/[/a-z0-9_-]+',
            r'/payment[s]?[/a-z0-9_-]*',
            r'/upload[/a-z0-9_-]*',
            r'/download[/a-z0-9_-]*',
            r'/config[/a-z0-9_-]*',
            r'/api[/a-z0-9_/-]+',
        ]
        for pattern in api_patterns:
            for match in re.finditer(pattern, js_content, re.IGNORECASE):
                path = match.group(0)
                if path.startswith('/'):
                    endpoints.add(path)
                else:
                    endpoints.add('/' + path)
        return endpoints

    def _is_valid_path(self, path: str) -> bool:
        if not path or not path.startswith('/'):
            return False
        if re.search(r'[\s"\'<>\[\]{}|\\^`]', path):
            return False
        if len(path) < 2:
            return False
        keywords = {'var', 'let', 'const', 'function', 'return', 'if', 'else', 'for', 'while', 'switch', 'case', 'break', 'continue', 'try', 'catch', 'throw', 'new', 'this', 'self', 'undefined', 'null', 'true', 'false'}
        path_clean = path.strip('/').lower()
        if path_clean in keywords:
            return False
        if re.match(r'^[\d.]+$', path_clean):
            return False
        return True

    def _make_full_url(self, path: str) -> Optional[str]:
        base_parsed = urllib.parse.urlparse(self.base_url)
        path = path.strip()
        if path.startswith('//'):
            return f"{base_parsed.scheme}:{path}"
        if path.startswith('http://') or path.startswith('https://'):
            return path
        if not path.startswith('/'):
            path = '/' + path
        return f"{base_parsed.scheme}://{base_parsed.netloc}{path}"


class PathCombiner:
    # scheme://netloc 前缀与后面的 path 分离处理，避免把协议头的 // 当成重复斜杠
    _SCHEME_RE = re.compile(r'^([a-zA-Z][a-zA-Z0-9+.\-]*://[^/]*)(.*)$', re.DOTALL)

    @staticmethod
    def normalize_path(path: str) -> str:
        """
        规范化路径。修复要点：
        1. 不再对整串做 replace('//','/')，否则 http://host 会被改成 http:/host；
        2. 不再砍掉 ?query，字典里的参数化 payload 必须保留；
        3. 不再强制追加尾斜杠，避免字典条目被改写成另一种形态；
        4. 仍然去掉 #fragment，仍然折叠 path 内部多余的斜杠。
        """
        if not path:
            return ""

        m = PathCombiner._SCHEME_RE.match(path)
        if m:
            prefix, rest = m.group(1), m.group(2)
        else:
            prefix, rest = "", path

        rest = rest.split("#")[0]
        while "//" in rest:
            rest = rest.replace("//", "/")
        rest = rest.strip()

        if rest == "":
            rest = "/" if prefix else ""

        return prefix + rest

    @staticmethod
    def combine_paths(base_url: str, fragments: List[str], max_up_levels: int = 3) -> Set[str]:
        result = set()
        base_parsed = urllib.parse.urlparse(base_url)
        base_path = base_parsed.path.strip('/')
        path_parts = base_path.split('/') if base_path else []
        for fragment in fragments:
            fragment = fragment.strip('/')
            if not fragment:
                continue
            for up_level in range(min(max_up_levels, len(path_parts)) + 1):
                if up_level == 0:
                    new_path = f"{'/'.join(path_parts)}/{fragment}" if path_parts else fragment
                else:
                    new_path = f"{'/'.join(path_parts[:-up_level])}/{fragment}" if path_parts[:-up_level] else fragment
                new_path = new_path.strip('/')
                full_url = f"{base_parsed.scheme}://{base_parsed.netloc}/{new_path}/"
                result.add(PathCombiner.normalize_path(full_url))
        return result

    @staticmethod
    def deduplicate_paths(paths: Set[str]) -> Set[str]:
        """
        只做规范化 + 集合去重。
        修复要点：原实现用 `len(parts) != len(set(parts))` 丢弃"含重复片段"的路径，
        把 /admin/eWebEditor/eWebEditor/db/web.zip、/api/v2/test/api-docs 这类
        完全合法的路径当成重复项静默丢掉了。
        """
        normalized = set()
        for path in paths:
            norm = PathCombiner.normalize_path(path)
            if norm:
                normalized.add(norm)
        return normalized

    @staticmethod
    def apply_dir_slash(paths: Set[str]) -> Set[str]:
        """为目录型路径（末尾无扩展名、无斜杠）额外生成一份带尾斜杠的变体。"""
        result = set()
        for path in paths:
            result.add(path)
            if path.endswith("/"):
                continue
            last = path.split("?")[0].rstrip("/").rsplit("/", 1)[-1]
            if last and "." not in last:
                result.add(path + "/")
        return result


class FingerprintCache:
    """
    结果去重缓存。三种模式：
      off      - 不去重
      content  - 按 (status, 长度, body hash) 去重（原行为；SPA 站点会被丢光）
      redirect - 只按重定向目标去重（默认，安全）：N 个路径都 302 到同一个
                 登录页时只保留一条，其余场景全部保留
    """

    def __init__(self, mode: str = "redirect"):
        self.mode = mode if mode in ("off", "content", "redirect") else "redirect"
        self.cache: Dict[str, List[str]] = {}
        self.duplicate_count = 0
        self.sensitive_duplicate_count = 0

    def _compute_hash(self, content: bytes) -> str:
        if len(content) > 1024 * 1024:
            data = content[:1024] + content[-1024:]
        else:
            data = content
        return hashlib.md5(data).hexdigest()

    def _make_key(self, status: int, content: bytes) -> str:
        if status != 200:
            return f"{status}_none_none"
        content_hash = self._compute_hash(content)
        content_len = len(content)
        return f"{status}_{content_len}_{content_hash}"

    def check_and_add(self, status: int, content: bytes, url: str, is_sensitive: bool = False,
                      redirect_target: str = "") -> Tuple[bool, bool]:
        if self.mode == "off":
            return True, False

        if self.mode == "content":
            if status != 200:
                return True, False
            key = self._make_key(status, content)
        else:
            # 去重维度是"最终落地 URL"：
            # 跟随重定向后，history[-1] 是请求 URL（各不相同），真正相同的是 resp.url。
            if not redirect_target:
                return True, False
            key = f"redirect::{redirect_target}"

        if key in self.cache:
            if is_sensitive:
                self.sensitive_duplicate_count += 1
                return False, True
            self.duplicate_count += 1
            return False, False
        self.cache[key] = [url]
        return True, False

    def get_duplicate_count(self) -> int:
        return self.duplicate_count

    def get_sensitive_duplicate_count(self) -> int:
        return self.sensitive_duplicate_count


# ===========================================================================
# 响应模板归一化 + 聚类去重
# ===========================================================================
# 起因（fsm.global 实测）：Akamai 的 403 拒绝页把请求路径和一个随机 Reference
# 号回显进 body，导致每条 403 的长度和 md5 都不一样：
#     /system-config/.env  403 390B  Reference #18.e20c0317.1788856190.3ee90e67
#     /sitemaps/.env       403 381B  Reference #18.e20c0317.1788856191.3ee911f9
# 任何"body hash 完全一致才算重复"的去重都会把同一个页面报成 N 条结果。
# 办法：先把响应里的变量部分（URL / 长 hex / 时间戳 / 数字 / 路径）抹掉，
# 只留下页面骨架，再算指纹 —— 这类 WAF 页会被折叠成 1 条。
# ===========================================================================

_TEMPLATE_TEXT_TYPES = (
    "text/", "application/json", "application/xml",
    "application/javascript", "application/x-javascript",
    "application/xhtml", "+json", "+xml",
)

# 命中这些 title 且同模板出现多次的 200，基本是维护页/出错页/占位页
GENERIC_TITLE_PATTERNS = (
    "system upgrade", "under maintenance", "maintenance", "under construction",
    "coming soon", "site is down", "temporarily unavailable", "service unavailable",
    "access denied", "forbidden", "not found", "404", "error", "be right back",
)


def normalize_template(text: str, aggressive: bool = False, max_len: int = 32768) -> str:
    """
    把响应文本归一化成"页面骨架"。

    aggressive=True 时会额外把 /xxx 形式的路径 token 抹掉，
    用于错误页（403/401/400/5xx）—— 这类页面往往把请求路径直接写进正文，
    而路径不同不代表页面不同。200 响应默认不这么做，避免过度合并真实内容。
    """
    s = _html_lib.unescape(text[:max_len])
    s = re.sub(r"https?://[^\s\"'<>)\]]+", " <URL> ", s)
    s = re.sub(r"\b[0-9a-fA-F]{8,}\b", " <HEX> ", s)
    s = re.sub(r"\b\d{9,}\b", " <TS> ", s)
    s = re.sub(r"\b\d+\b", " <N> ", s)
    if aggressive:
        s = re.sub(r"/[^\s\"'<>),;]*", " <PATH> ", s)
    s = re.sub(r"\s+", " ", s)
    return s.strip().lower()


CLUSTER_URL_CAP = 3000          # 每个簇最多记录的 URL 数（防止内存爆掉）
CLUSTER_HARD_CAP = 20000        # 单个簇累计到这个量级后不再生成结果


class ResponseCluster:
    """按"页面骨架"聚类响应。同一簇只保留 1 条结果，其余记进 sidecar 文件。"""

    def __init__(self):
        self.clusters: Dict[str, Dict] = {}
        self._lock = threading.Lock()
        self.total_collapsed = 0

    def fingerprint(self, status: int, content: bytes, headers: Optional[Dict] = None) -> str:
        ct = ((headers or {}).get("content-type") or "").lower()
        if ct and not any(t in ct for t in _TEMPLATE_TEXT_TYPES):
            # 二进制：按状态码 + 大小档位分簇，避免大文件进正则
            return f"bin::{status}::{len(content) // 512}"
        try:
            text = content[:65536].decode("utf-8", "ignore")
        except Exception:
            text = ""
        if not text.strip():
            return f"empty::{status}::{len(content) // 512}"
        tpl = normalize_template(text, aggressive=(status != 200))
        if not tpl:
            return f"empty::{status}::{len(content) // 512}"
        return f"{status}::{hashlib.md5(tpl.encode('utf-8', 'ignore')).hexdigest()[:16]}"

    def put(self, fp: str, url: str) -> int:
        """登记一次响应，返回该簇截至目前的累计条数。"""
        with self._lock:
            c = self.clusters.get(fp)
            if c is None:
                c = {"count": 0, "urls": [], "first": url, "status": int(fp.split("::")[0]) if fp.split("::")[0].isdigit() else 0}
                self.clusters[fp] = c
            c["count"] += 1
            if len(c["urls"]) < CLUSTER_URL_CAP:
                c["urls"].append(url)
            if c["count"] > 1:
                self.total_collapsed += 1
            return c["count"]

    def url_list(self, fp: str) -> List[str]:
        c = self.clusters.get(fp)
        return list(c["urls"]) if c else []


# ===========================================================================
# Phase 2：探测能力扩展
# ===========================================================================

# --- 403 / 401 绕过 ---
BYPASS_HEADER_NAMES = (
    "X-Original-URL", "X-Rewrite-URL", "X-Custom-IP-Authorization",
    "X-Forwarded-For", "X-Real-IP", "X-Client-IP", "X-Originating-IP",
    "X-Host", "X-Forwarded-Host", "Referer", "X-Forwarded-Server",
)
_BYPASS_FIXED_VALUES = {
    "X-Forwarded-For": "127.0.0.1",
    "X-Real-IP": "127.0.0.1",
    "X-Client-IP": "127.0.0.1",
    "X-Originating-IP": "127.0.0.1",
    "X-Custom-IP-Authorization": "127.0.0.1",
    "X-Host": "localhost",
    "X-Forwarded-Host": "localhost",
    "X-Forwarded-Server": "localhost",
}


def bypass_header_values(name: str, path: str, base_url: str) -> List[str]:
    if name in ("X-Original-URL", "X-Rewrite-URL"):
        return [path]
    if name == "Referer":
        return [base_url]
    v = _BYPASS_FIXED_VALUES.get(name, "127.0.0.1")
    return [v]


def bypass_path_variants(url: str, limit: int = 14) -> List[str]:
    """生成 403 绕过的路径变异。全部保持同 host、只改 path。"""
    p = urllib.parse.urlsplit(url)
    path = p.path or "/"
    tail = path.lstrip("/")
    cands = [
        path,
        "/" + tail,
        "/;" + tail,
        "//" + tail,
        "/./" + tail,
        path + "/",
        path + "/.",
        path + ";",
        path + "%09",
        path + "..;/",
        path + ";%09",
        path + "%20",
        "/..%2f" + tail,
        "/%2e%2e/" + tail,
        path.replace("/", "/;/", 1) if "/" in path else path,
    ]
    if tail:
        # 大小写变异：整段大写 + 首字母大写
        cands.append("/" + tail.upper())
        cands.append("/" + tail[0].upper() + tail[1:])
    out, seen = [], set()
    for c in cands:
        if not c or c in seen:
            continue
        seen.add(c)
        out.append(urllib.parse.urlunsplit((p.scheme, p.netloc, c, p.query, "")))
        if len(out) >= limit:
            break
    return out


# --- 备份 / 源码泄漏后缀 ---
BACKUP_SUFFIXES = (
    ".bak", ".old", ".orig", ".save", ".swp", ".swo", ".~", ".1", ".2",
    ".zip", ".tar.gz", ".tgz", ".rar", ".7z", ".sql", ".txt", ".log",
    ".copy", ".backup", "_bak", "_old", ".2024", ".inc", ".dist",
)


def backup_variants(url: str) -> List[str]:
    p = urllib.parse.urlsplit(url)
    path = p.path or "/"
    out, seen = [], set()

    def add(newpath):
        if not newpath or newpath in seen:
            return
        seen.add(newpath)
        out.append(urllib.parse.urlunsplit((p.scheme, p.netloc, newpath, "", "")))

    for suf in BACKUP_SUFFIXES:
        add(path + suf)
        add(path.rstrip("/") + suf)
    # 去扩展名再加后缀： /a/b.php -> /a/b.zip
    if "." in path.rsplit("/", 1)[-1]:
        stem = path.rsplit(".", 1)[0]
        for suf in (".zip", ".bak", ".old", ".sql", ".tar.gz", ".swp"):
            add(stem + suf)
        add(stem + "/")
    return out


# --- 敏感文件专项清单（字典里不一定有，或位置不一定在根） ---
SENSITIVE_FILES = (
    ".git/HEAD", ".git/config", ".git/index", ".svn/entries", ".svn/wc.db",
    ".env", ".env.local", ".env.production", ".env.backup", ".DS_Store",
    ".idea/workspace.xml", ".vscode/sftp.json", ".npmrc", ".htpasswd",
    ".htaccess", ".aws/credentials", ".docker/config.json",
    "WEB-INF/web.xml", "WEB-INF/classes/", "META-INF/MANIFEST.MF",
    "actuator", "actuator/env", "actuator/heapdump", "actuator/beans",
    "actuator/gateway/routes", "actuator/metrics",
    "swagger-ui.html", "swagger/index.html", "api-docs", "v2/api-docs",
    "v3/api-docs", "graphql", "graphiql", "altair",
    "phpinfo.php", "info.php", "test.php", "server-status", "server-info",
    "console", "debug/default/view", "_profiler/phpinfo",
    "elmah.axd", "trace.axd", "web.config", "config.php", "configuration.php",
    "backup.sql", "dump.sql", "db.sql", "database.sql", "data.sql",
    "phpMyAdmin/", "adminer.php", "solr/", "jenkins/", "manager/html",
    "crossdomain.xml", "clientaccesspolicy.xml", "robots.txt",
    "sitemap.xml", "sitemap_index.xml", ".well-known/security.txt",
)

# --- 递归枚举用的高价值小字典（不加载 14 万条大字典，避免扫描量爆炸） ---
RECURSIVE_WORDS = (
    "admin", "api", "apis", "app", "apps", "auth", "backup", "backups",
    "bin", "cache", "cgi-bin", "conf", "config", "console", "css", "dashboard",
    "data", "db", "debug", "dev", "doc", "docs", "download", "downloads",
    "editor", "export", "files", "file", "forum", "ftp", "git", "home",
    "images", "img", "import", "inc", "include", "index", "internal", "js",
    "json", "lib", "log", "logs", "login", "mail", "manage", "manager",
    "media", "member", "members", "misc", "mobile", "module", "modules",
    "new", "news", "old", "order", "orders", "panel", "private", "public",
    "report", "reports", "resource", "resources", "root", "script", "scripts",
    "search", "secret", "server", "service", "setting", "settings", "setup",
    "share", "shell", "sql", "src", "ssl", "static", "statistics", "status",
    "store", "svc", "sys", "system", "temp", "template", "templates", "test",
    "tests", "tmp", "tools", "upload", "uploads", "user", "users", "util",
    "utils", "v1", "v2", "v3", "vendor", "web", "webadmin", "wp-admin",
    "wp-content", "www", "xml", "zip",
)


class RateLimiter:
    """令牌桶限速。--max-rate 之前只是个定义了但没人用的死参数。"""

    def __init__(self, rate: int):
        self.rate = max(0, int(rate or 0))
        self.tokens = float(self.rate)
        self.last = time.time()
        self._lock = threading.Lock()

    def acquire(self):
        if self.rate <= 0:
            return
        while True:
            with self._lock:
                now = time.time()
                self.tokens = min(float(self.rate), self.tokens + (now - self.last) * self.rate)
                self.last = now
                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    return
                wait = (1.0 - self.tokens) / float(self.rate)
            time.sleep(min(wait, 1.0))


class Soft404Detector:
    """
    软 404 检测。

    重写原因：原实现用 `abs(sample_size - size) <= 50B` 判定无效页，
    样本小于 1KB 时还放宽到 100B，导致静态资源、短 JSON、跳转页被成片误杀。

    新策略（多维度基线）：
      1. 采样多个形态不同的随机路径（目录 / 文件 / 深层），记录
         status / 最终 URL / title / body-hash / size；
      2. 目标响应 body-hash 命中样本 hash      -> 判无效；
      3. title 完全一致且相对大小差 <= 10%     -> 判无效；
      4. 其余一律判有效，宁可多报也不误杀。
    """

    def __init__(self, scanner: 'Scanner', size_threshold: int = 3):
        self.scanner = scanner
        self.invalid_features: List[Dict] = []
        self.fake_404_pattern: Optional[str] = None
        self.min_sample_count = 5
        self.is_soft_404_site = False
        self.size_count: Dict[int, int] = defaultdict(int)
        self.size_threshold = size_threshold
        self.title_size_tolerance = 0.10
        self.homepage_hash = ""
        self.homepage_size = 0
        self._homepage_title = ""
        self.sampled_paths: List[str] = []

    def _compute_hash(self, content: bytes) -> str:
        if len(content) > 1024 * 1024:
            data = content[:1024] + content[-1024:]
        else:
            data = content
        return hashlib.md5(data).hexdigest()

    def detect(self) -> bool:
        """采样多种形态的随机路径，建立软 404 基线特征。"""
        print("\n[*] 正在检测软404（多维度基线采样）...")

        token = uuid.uuid4().hex[:8]
        test_paths = [
            f"/notexist-{token}/",
            f"/notexist-{token}",
            f"/notexist-{token}.php",
            f"/notexist-{token}.html",
            f"/a/b/notexist-{token}",
            f"/null-{uuid.uuid4().hex[:8]}/",
            f"/undefined-{uuid.uuid4().hex[:8]}/",
        ]
        for i in range(self.min_sample_count):
            test_paths.append(f"/notexist-{uuid.uuid4().hex[:8]}-{i}/")

        try:
            resp = self.scanner.session.get(
                urllib.parse.urljoin(self.scanner.args.url, "/"),
                timeout=self.scanner.args.timeout,
                verify=False,
                allow_redirects=True,
            )
            if resp.status_code == 200:
                self.homepage_size = len(resp.content)
                self.homepage_hash = self._compute_hash(resp.content)
                self._homepage_title = self._extract_title(resp.text)
            print(f"[*] 主页响应: {resp.status_code}, 大小: {self.homepage_size}B")
        except Exception:
            self.homepage_size = 0
            self.homepage_hash = ""

        for test_path in test_paths:
            try:
                resp = self.scanner.session.get(
                    urllib.parse.urljoin(self.scanner.args.url, test_path),
                    timeout=self.scanner.args.timeout,
                    verify=False,
                    allow_redirects=True,
                )
                if resp.status_code != 200:
                    continue
                content = resp.content
                content_hash = self._compute_hash(content)
                if content_hash == self.homepage_hash:
                    continue
                self.invalid_features.append({
                    "size": len(content),
                    "hash": content_hash,
                    "title": self._extract_title(resp.text),
                    "pattern": test_path,
                    "final_url": resp.url,
                })
                self.sampled_paths.append(test_path)
            except Exception:
                pass

        if self.invalid_features:
            self.fake_404_pattern = self.invalid_features[0]["pattern"]
            self.is_soft_404_site = True
            sizes = sorted({f["size"] for f in self.invalid_features})
            titles = sorted({f["title"] for f in self.invalid_features if f["title"]})
            print(f"[*] 软404检测完成，采集到 {len(self.invalid_features)} 个无效页面特征")
            print(f"[*] 无效页面大小集合: {sizes}")
            if titles:
                print(f"[*] 无效页面 title: {titles[:3]}")
            return True

        # fsm.global 这类站点：不存在的路径返回 404，但 body 就是首页内容。
        # 上面的采样循环遇到 status != 200 就 continue，这类特征一条都采不到，
        # 结果"请求 /admin 却拿回首页正文"的软 404 完全识别不出来。
        # 所以无论采样结果如何，都把首页正文登记为一个无效基线：
        # 200 响应 body == 首页 body，就等于你拿到的是兜底页。
        if self.homepage_hash:
            self.invalid_features.append({
                "size": self.homepage_size,
                "hash": self.homepage_hash,
                "title": self._homepage_title or "",
                "pattern": "<homepage>",
                "final_url": getattr(self.scanner.args, "url", ""),
            })
            self.is_soft_404_site = True
            self.fake_404_pattern = "<homepage>"
            print(f"[*] 已将首页正文登记为无效基线 ({self.homepage_size}B) "
                  f"—— 200 但 body 与首页一致的路径会被判为软404")
            return True

        print("[!] 未采集到软404特征（目标对不存在路径返回非200），跳过软404过滤")
        self.is_soft_404_site = False
        return False

    def record_size(self, content_size: int):
        """仅用于统计展示。原实现的 suspicious_sizes 会把等长的不同页面误判为重复，已废弃。"""
        self.size_count[content_size] += 1

    def _extract_title(self, html: str) -> str:
        try:
            match = re.search(r"<title[^>]*>([^<]+)</title>", html, re.IGNORECASE)
            if match:
                return match.group(1).strip().lower()
        except Exception:
            pass
        return ""

    def is_invalid_content(self, resp: RespInfo, title: str = "") -> Tuple[bool, str]:
        """
        判定响应是否为软 404。

        只认两种硬证据：
          1. body hash 与样本完全一致；
          2. title 完全一致且相对大小差 <= 10%。
        其余一律判有效 —— 宁可多报，不误杀。
        """
        if not self.invalid_features:
            return False, ""

        content = resp.content
        content_hash = self._compute_hash(content)
        content_size = len(content)

        if not title:
            title = self._extract_title(resp.text)
        title_norm = (title or "").strip().lower()

        for feature in self.invalid_features:
            if feature["hash"] == content_hash:
                return True, f"hash_match({content_size}B)"

        if title_norm:
            for feature in self.invalid_features:
                if not feature["title"]:
                    continue
                if feature["title"].strip().lower() != title_norm:
                    continue
                max_size = max(feature["size"], content_size) or 1
                if abs(feature["size"] - content_size) / max_size <= self.title_size_tolerance:
                    return True, f"title_match({title_norm[:24]})"

        return False, ""



class AsyncCrawler:
    def __init__(self, args: argparse.Namespace, scanner: 'Scanner'):
        self.args = args
        self.scanner = scanner
        self.base_url = args.url
        self.max_depth = getattr(args, 'crawl_depth', 5)
        self.max_concurrency = getattr(args, 'crawl_threads', 5) * 4
        self.timeout = getattr(args, 'timeout', 10)
        self.debug = getattr(args, 'debug', False)

        self.crawled: Set[str] = set()
        self.css_js_paths: Set[str] = set()
        self.forms: List[Dict] = []
        self.visited: Set[str] = set()
        self.to_crawl: asyncio.Queue = asyncio.Queue()
        self.results: List[Tuple[Set[str], Set[str], List[Tuple[str, int]]]] = []
        self.is_spa_detected = False
        self.base_domain = urllib.parse.urlparse(self.base_url).netloc
        self.base_scheme_netloc = f"{urllib.parse.urlparse(self.base_url).scheme}://{urllib.parse.urlparse(self.base_url).netloc}"

        self.common_spa_routes = [
            "/", "/home", "/index", "/login", "/register", "/signup", "/signin",
            "/logout", "/dashboard", "/admin", "/administrator", "/manage", "/management",
            "/settings", "/profile", "/user", "/users", "/account", "/accounts",
            "/api", "/api/v1", "/api/v2", "/rest", "/graphql",
            "/auth", "/oauth", "/sso", "/cas", "/ldap",
        ]

        self.session: Optional[aiohttp.ClientSession] = None
        self._lock = asyncio.Lock()

    async def init_session(self):
        connector = aiohttp.TCPConnector(
            limit=self.max_concurrency,
            limit_per_host=self.max_concurrency,
            ssl=False
        )
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={"User-Agent": random.choice(DEFAULT_USER_AGENTS)}
        )

    async def close_session(self):
        if self.session:
            await self.session.close()

    async def crawl_single_url(self, current_url: str, depth: int) -> Tuple[Set[str], Set[str], List[Tuple[str, int]], List[Dict]]:
        local_crawled: Set[str] = set()
        local_css_js_paths: Set[str] = set()
        local_new_links: List[Tuple[str, int]] = []
        local_forms: List[Dict] = []

        if not self.session:
            return local_crawled, local_css_js_paths, local_new_links, local_forms

        try:
            if self.debug:
                print(f"[D] 爬取: {current_url} (深度: {depth})")

            async with self.session.get(current_url, allow_redirects=True) as resp:
                final_url = str(resp.url)
                local_crawled.add(final_url)

                if self.debug:
                    print(f"[D] 响应: {final_url} - 状态:{resp.status} 大小:{resp.content_length or 0}B")

                if resp.status == 200:
                    content = await resp.read()
                    final_url_parsed = urllib.parse.urlparse(final_url)
                    base_path_prefix = final_url_parsed.path.rsplit("/", 1)[0] if final_url_parsed.path else ""
                    is_root_path = final_url_parsed.path == "/" or final_url_parsed.path == ""

                    if depth == 0 and len(content) < 500:
                        if not self.is_spa_detected:
                            self.is_spa_detected = True
                            print(f"\033[94m[*] 检测到可能是 SPA 站点 (主页响应 {len(content)}B，最终路径: {final_url_parsed.path})\033[0m")
                            for route in self.common_spa_routes:
                                if is_root_path:
                                    full_route_url = self.base_scheme_netloc + route
                                else:
                                    full_route_url = self.base_scheme_netloc + base_path_prefix + route
                                local_new_links.append((full_route_url, 1))

                    if depth < self.max_depth:
                        text = content.decode('utf-8', errors='ignore')

                        parser = LinkExtractor(final_url)
                        parser.feed(text)
                        local_forms = list(parser.forms)

                        css_links = self.scanner._extract_css_links(text, final_url)
                        js_links = self.scanner._extract_js_links(text, final_url)

                        for css_url in css_links:
                            css_paths = await self._fetch_and_parse_css_async(css_url)
                            local_css_js_paths.update(css_paths)

                        for js_url in js_links:
                            js_paths = await self._fetch_and_parse_js_async(js_url)
                            local_css_js_paths.update(js_paths)

                        for link in parser.links:
                            local_new_links.append((link, depth + 1))

                        parent_paths = parser.extract_parent_paths(parser.links)
                        for parent in parent_paths:
                            local_new_links.append((parent, depth + 1))

        except asyncio.CancelledError:
            raise
        except Exception as e:
            if self.debug:
                print(f"[D] 爬取失败: {current_url} - 错误: {e}")

        return local_crawled, local_css_js_paths, local_new_links, local_forms

    async def _fetch_and_parse_css_async(self, css_url: str) -> Set[str]:
        paths = set()
        if not self.session:
            return paths

        try:
            async with self.session.get(css_url) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    parser = CSSParser(css_url)
                    paths = parser.parse(text)
        except Exception:
            pass
        return paths

    async def _fetch_and_parse_js_async(self, js_url: str) -> Set[str]:
        paths = set()
        if not self.session:
            return paths

        try:
            async with self.session.get(js_url) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    parser = JSParser(js_url)
                    paths = parser.parse(text)
        except Exception:
            pass
        return paths

    async def worker(self, worker_id: int):
        while not GLOBAL_STATE.should_exit:
            try:
                current_url, depth = await asyncio.wait_for(self.to_crawl.get(), timeout=0.5)
            except asyncio.TimeoutError:
                continue

            async with self._lock:
                if current_url in self.visited or depth > self.max_depth:
                    self.to_crawl.task_done()
                    continue
                self.visited.add(current_url)

            local_crawled, local_css_js_paths, local_new_links, local_forms = await self.crawl_single_url(current_url, depth)

            async with self._lock:
                self.crawled.update(local_crawled)
                self.css_js_paths.update(local_css_js_paths)
                self.forms.extend(local_forms)

                for new_url, new_depth in local_new_links:
                    if new_url not in self.visited and new_depth <= self.max_depth:
                        await self.to_crawl.put((new_url, new_depth))

            self.to_crawl.task_done()

    async def run_async(self):
        await self.init_session()
        print(f"\n\033[94m[*] 启动异步爬虫模式，深度: {self.max_depth}，并发: {self.max_concurrency}\033[0m")

        await self.to_crawl.put((self.base_url, 0))

        workers = [asyncio.create_task(self.worker(i)) for i in range(self.max_concurrency)]

        async def monitor_progress():
            last_count = 0
            while not GLOBAL_STATE.should_exit:
                await asyncio.sleep(1)
                current_size = self.to_crawl.qsize()
                if current_size != last_count:
                    print(f"\r[*] 爬虫进度: 已爬取 {len(self.crawled)} 个页面, 待爬取 {current_size}", end="", flush=True)
                    last_count = current_size

        monitor_task = asyncio.create_task(monitor_progress())

        await self.to_crawl.join()

        for w in workers:
            w.cancel()

        await asyncio.gather(*workers, return_exceptions=True)
        monitor_task.cancel()
        await asyncio.gather(monitor_task, return_exceptions=True)

        await self.close_session()

        combined_paths = self.crawled | self.css_js_paths
        print(f"\n\033[94m[*] 异步爬虫完成，共提取 {len(combined_paths)} 条路径 (爬取 {len(self.crawled)} 个页面)\033[0m")
        return combined_paths


class AsyncScanner:
    def __init__(self, args: argparse.Namespace, scanner: 'Scanner'):
        self.args = args
        self.scanner = scanner
        self.max_concurrency = max(1, getattr(args, 'threads', 1) * 10)
        self.timeout = getattr(args, 'timeout', 10)
        self.delay = getattr(args, 'delay', 0.1)
        self.debug = getattr(args, 'debug', False)
        self.proxy = getattr(args, 'proxy', None)
        self.base_headers = self._build_headers()

        self.session: Optional[aiohttp.ClientSession] = None
        self.semaphore: Optional[asyncio.Semaphore] = None
        self._async_lock = asyncio.Lock()

    def _build_headers(self) -> Dict[str, str]:
        """异步引擎此前只设 UA，自定义 header 全丢。这里与线程引擎对齐。"""
        headers = {"User-Agent": random.choice(DEFAULT_USER_AGENTS)}
        raw = getattr(self.args, "headers", None)
        if raw:
            for header in raw.split(";"):
                if ":" in header:
                    k, v = header.split(":", 1)
                    headers[k.strip()] = v.strip()
        return headers

    async def init_session(self):
        connector = aiohttp.TCPConnector(
            limit=self.max_concurrency,
            limit_per_host=self.max_concurrency,
            ssl=False
        )
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers=self.base_headers
        )
        self.semaphore = asyncio.Semaphore(self.max_concurrency)

    async def close_session(self):
        if self.session:
            await self.session.close()

    async def _request(self, task: Task) -> Optional[RespInfo]:
        headers = dict(self.base_headers)
        headers.update(task.headers)
        if task.content_type and task.data is not None:
            headers["Content-Type"] = task.content_type

        body = None
        if task.data is not None:
            body = task.data.encode("utf-8") if isinstance(task.data, str) else task.data

        try:
            start = time.time()
            async with self.session.request(
                task.method,
                task.url,
                data=body,
                headers=headers,
                allow_redirects=True,
                proxy=self.proxy,
            ) as r:
                content = await r.read()
                return RespInfo(
                    status=r.status,
                    url=str(r.url),
                    headers={k.lower(): v for k, v in r.headers.items()},
                    content=content,
                    history=[str(h.url) for h in r.history],
                    elapsed=time.time() - start,
                    method=task.method,
                    request_headers=headers,
                    request_body=task.data or "",
                )
        except asyncio.CancelledError:
            raise
        except Exception:
            if self.debug:
                print(f"[D] 异步请求失败: {task.method} {task.url}")
            return None

    async def scan_single_task(self, task: Task) -> Optional[Dict]:
        if self.rate_limiter:
            self.rate_limiter.acquire()
        async with self.semaphore:
            if GLOBAL_STATE.should_exit:
                return None

            while GLOBAL_STATE.paused:
                await asyncio.sleep(0.1)

            if self.delay > 0:
                await asyncio.sleep(random.uniform(self.delay * 0.5, self.delay * 1.5))

            resp = await self._request(task)
            if resp is None:
                return None
            return self.scanner.evaluate(task, resp)

    async def worker(self, tasks: List[Task], progress_callback=None):
        for task in tasks:
            if GLOBAL_STATE.should_exit:
                break

            async with self._async_lock:
                self.scanner.scanned_count += 1
                self.scanner.scanned_urls.add(task.url)
                self.scanner.scanned_keys.add(task.key())
                count = self.scanner.scanned_count

            result = await self.scan_single_task(task)

            if result:
                async with self._async_lock:
                    self.scanner.results.append(result)
                    self.scanner.found_count += 1
                    if result["is_sensitive"] == 1:
                        self.scanner.sensitive_count += 1

                self.scanner._print_result(result)

            if progress_callback:
                progress_callback(count)

            await asyncio.sleep(0)

    async def run_async(self, tasks: List[Task]):
        await self.init_session()
        print(f"\n\033[94m[*] 启动异步扫描模式，并发: {self.max_concurrency}\033[0m")

        self.scanner.start_time = time.time()
        self.scanner.args.total_paths = len(tasks)

        total = len(tasks)
        start_time = time.time()
        last_update = [start_time]
        update_interval = 0.5

        def progress_callback(count):
            now = time.time()
            if now - last_update[0] >= update_interval:
                last_update[0] = now
                percent = (count / total * 100) if total > 0 else 0
                speed = count / (now - start_time) if start_time else 0
                remaining = (total - count) / speed if speed > 0 else 0

                bar_length = 30
                filled = int(bar_length * count / total) if total > 0 else 0
                bar = "=" * filled + "-" * (bar_length - filled)

                sys.stdout.write(f"\r[{bar}] {percent:.1f}% {count}/{total} 速度:{speed:.1f}/s 剩余:{remaining:.0f}s 敏感:{self.scanner.sensitive_count} 异步")
                sys.stdout.flush()

        batch_size = self.max_concurrency * 2
        for i in range(0, len(tasks), batch_size):
            if GLOBAL_STATE.should_exit:
                break

            batch = tasks[i:i + batch_size]
            n = max(1, min(self.max_concurrency, len(batch)))
            # 关键修复：切片分派。原实现把同一个 batch 交给 n 个 worker，
            # 每个 worker 都从头部遍历整个 batch，导致每条路径被请求 n 次。
            workers = [
                asyncio.create_task(self.worker(batch[j::n], progress_callback))
                for j in range(n)
            ]
            await asyncio.gather(*workers, return_exceptions=True)

        await self.close_session()
        print()


class AdaptiveThreadController:
    def __init__(self, initial_threads: int, max_threads: int):
        self.current_threads = initial_threads
        self.max_threads = max_threads
        self.success_count = 0
        self.timeout_count = 0
        self.success_threshold = 10
        self.timeout_threshold = 3

    def record_success(self):
        self.success_count += 1
        self.timeout_count = 0
        if self.success_count >= self.success_threshold and self.current_threads < self.max_threads:
            self.current_threads += 1
            self.success_count = 0

    def record_timeout(self):
        self.timeout_count += 1
        self.success_count = 0
        if self.timeout_count >= self.timeout_threshold and self.current_threads > 1:
            self.current_threads -= 1
            self.timeout_count = 0

    def get_threads(self) -> int:
        return self.current_threads


class ProxyPool:
    def __init__(self, proxy_list: List[str]):
        self.proxies = proxy_list
        self.current_index = 0
        self.failed_proxies: Set[str] = set()
        self.available_proxies: List[str] = []

    def validate_and_init(self, test_url: str, timeout: int = 5) -> bool:
        self.available_proxies = []
        for proxy in self.proxies:
            if proxy in self.failed_proxies:
                continue
            try:
                test_proxy = {
                    "http": proxy if proxy.startswith('socks5://') else proxy,
                    "https": proxy if proxy.startswith('socks5://') else proxy,
                }
                resp = requests.get(test_url, proxies=test_proxy, timeout=timeout, verify=False)
                if resp.status_code < 500:
                    self.available_proxies.append(proxy)
            except Exception:
                self.failed_proxies.add(proxy)
        return len(self.available_proxies) > 0

    def get_next_proxy(self) -> Optional[Dict[str, str]]:
        if not self.available_proxies:
            return None
        proxy = self.available_proxies[self.current_index % len(self.available_proxies)]
        self.current_index += 1
        return {
            "http": proxy,
            "https": proxy,
        }

    def mark_failed(self, proxy: str):
        if proxy in self.available_proxies:
            self.available_proxies.remove(proxy)
        self.failed_proxies.add(proxy)


class BanRecoveryManager:
    def __init__(self):
        self.consecutive_ban_count = 0
        self.ban_threshold = 5
        self.current_delay = 1.0
        self.max_delay = 60.0
        self.is_banned = False
        self.retry_after: Optional[int] = None

    def record_response(self, status_code: int, retry_after: Optional[str] = None):
        if status_code in (429, 503):
            self.consecutive_ban_count += 1
            if self.consecutive_ban_count >= self.ban_threshold:
                self.is_banned = True
                if retry_after and retry_after.isdigit():
                    self.retry_after = int(retry_after)
                    self.current_delay = float(self.retry_after)
                else:
                    self.current_delay = min(self.current_delay * 2, self.max_delay)
        else:
            self.consecutive_ban_count = 0
            self.is_banned = False
            self.current_delay = 1.0

    def should_wait(self) -> bool:
        return self.is_banned

    def get_wait_time(self) -> float:
        return self.current_delay

    def reset(self):
        self.consecutive_ban_count = 0
        self.is_banned = False
        self.current_delay = 1.0
        self.retry_after = None


class Scanner:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.results: List[Dict] = []
        self.results_lock = threading.Lock()
        self.scanned_count = 0
        self.scanned_lock = threading.Lock()
        self.found_count = 0
        self.found_lock = threading.Lock()
        self.sensitive_count = 0
        self.sensitive_lock = threading.Lock()
        self.start_time: Optional[float] = None

        print("\033[91m[!] 本工具仅用于公司授权的安全渗透测试，禁止非法使用，使用前需获得目标授权\033[0m\n")

        self.session = requests.Session()
        self.session.headers.update({"User-Agent": random.choice(DEFAULT_USER_AGENTS)})

        if args.headers:
            for header in args.headers.split(";"):
                if ":" in header:
                    key, value = header.split(":", 1)
                    self.session.headers[key.strip()] = value.strip()

        if args.proxy:
            self.session.proxies = {
                "http": args.proxy,
                "https": args.proxy,
            }

        self.fingerprint_cache = FingerprintCache(getattr(args, 'dedup_mode', 'redirect'))
        self.response_cluster = ResponseCluster()
        self.status_urls: Dict[int, List[str]] = {}
        self.rate_limiter = RateLimiter(getattr(args, 'max_rate', 20))
        dup_threshold = getattr(args, 'dup_size_threshold', 3)
        self.soft_404_detector = Soft404Detector(self, dup_threshold)
        self.adaptive_thread_controller = AdaptiveThreadController(
            args.threads, args.threads
        )
        self.ban_recovery_manager = BanRecoveryManager()
        self.proxy_pool: Optional[ProxyPool] = None
        self.failed_tasks: List[Task] = []
        self.failed_lock = threading.Lock()

        self.all_discovered_paths: Set[str] = set()
        self.all_discovered_tasks: Dict[str, Task] = {}
        self.scanned_urls: Set[str] = set()
        self.scanned_keys: Set[str] = set()
        self._processed_200: Set[str] = set()
        self.discovered_lock = threading.Lock()

        self._setup_signal_handlers()
        self._init_proxy_pool()
        self._init_cookie_pool()
        self._init_audit_log()

    def _init_proxy_pool(self):
        if hasattr(self.args, 'proxy_pool') and self.args.proxy_pool:
            try:
                with open(self.args.proxy_pool, 'r') as f:
                    proxies = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                if proxies:
                    self.proxy_pool = ProxyPool(proxies)
                    if self.proxy_pool.validate_and_init(self.args.url, self.args.timeout):
                        print(f"\033[94m[*] 代理池初始化成功，有效代理: {len(self.proxy_pool.available_proxies)}\033[0m")
                    else:
                        print(f"\033[93m[!] 代理池验证失败，将使用直连\033[0m")
                        self.proxy_pool = None
            except Exception as e:
                if self.args.debug:
                    print(f"代理池加载失败: {e}")

    def _init_cookie_pool(self):
        if hasattr(self.args, 'cookie_pool') and self.args.cookie_pool:
            try:
                with open(self.args.cookie_pool, 'r') as f:
                    cookies = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                if cookies:
                    cookie_str = '; '.join(cookies)
                    self.session.headers['Cookie'] = cookie_str
                    print(f"\033[94m[*] Cookie池已加载\033[0m")
            except Exception as e:
                if self.args.debug:
                    print(f"Cookie池加载失败: {e}")

    def _init_audit_log(self):
        self.audit_log: List[Dict] = []
        self.audit_lock = threading.Lock()

    def _log_audit(self, action: str, details: Dict):
        with self.audit_lock:
            self.audit_log.append({
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "action": action,
                "target": self.args.url,
                "details": details
            })

    def _setup_signal_handlers(self):
        if sys.platform != "win32":
            signal.signal(signal.SIGINT, self._signal_handler)
        else:
            signal.signal(signal.SIGINT, self._signal_handler_windows)

    def _signal_handler(self, signum, frame):
        with GLOBAL_STATE.lock:
            if GLOBAL_STATE.interrupted:
                return
            GLOBAL_STATE.interrupted = True

        if GLOBAL_STATE.current_input_mode.is_set():
            GLOBAL_STATE.should_exit = True
            return

        self._pause_and_show_menu()

    def _signal_handler_windows(self, signum, frame):
        self._pause_and_show_menu()

    def _pause_and_show_menu(self):
        GLOBAL_STATE.paused = True
        sys.stdout.flush()
        self._print_stats()

        first_prompt = True
        while True:
            try:
                print("\n\033[94m[扫描已暂停]\033[0m")
                print("1 - 继续扫描")
                print("2 - 保存结果并退出")
                if first_prompt and GLOBAL_STATE.interrupted:
                    print("(Ctrl+C 再次按下默认选择保存结果并退出)")
                print()
                sys.stdout.flush()
                first_prompt = False

                if sys.platform == "win32":
                    import msvcrt
                    print("请输入选项 (1-2): ", end="", flush=True)
                    start = time.time()
                    choice = ""
                    while time.time() - start < 10:
                        if msvcrt.kbhit():
                            ch = msvcrt.getch()
                            if ch in (b'1', b'2', b'\r', b'\n'):
                                choice = ch.decode('utf-8', errors='ignore')
                                print(choice)
                                break
                            elif ch == b'\x03':
                                raise KeyboardInterrupt()
                        time.sleep(0.05)
                else:
                    import termios
                    import tty
                    import select as sel
                    print("请输入选项 (1-2): ", end="", flush=True)
                    sys.stdout.flush()
                    
                    try:
                        fd = sys.stdin.fileno()
                        old_settings = termios.tcgetattr(fd)
                        tty.setcbreak(fd)
                        try:
                            if sel.select([sys.stdin], [], [], 10)[0]:
                                choice = sys.stdin.read(1).strip()
                            else:
                                choice = ""
                        finally:
                            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
                    except Exception:
                        choice = input("").strip() if hasattr(sys.stdin, 'read') else ""

                if not choice:
                    if GLOBAL_STATE.interrupted:
                        GLOBAL_STATE.should_exit = True
                        self._save_results()
                        self._save_resume_point()
                        print("\033[92m已保存结果并退出\033[0m")
                        sys.exit(0)
                    print("\033[93m等待超时，继续等待输入...\033[0m")
                    continue

                if choice == "1":
                    GLOBAL_STATE.paused = False
                    GLOBAL_STATE.interrupted = False
                    print("\033[92m继续扫描...\033[0m\n")
                    return
                elif choice == "2":
                    GLOBAL_STATE.should_exit = True
                    self._save_results()
                    self._save_resume_point()
                    print("\033[92m已保存结果并退出\033[0m")
                    sys.exit(0)

            except KeyboardInterrupt:
                GLOBAL_STATE.should_exit = True
                self._save_results()
                self._save_resume_point()
                print("\033[92m已保存结果并退出\033[0m")
                sys.exit(0)
            except Exception:
                if GLOBAL_STATE.interrupted:
                    GLOBAL_STATE.should_exit = True
                    self._save_results()
                    self._save_resume_point()
                    print("\033[92m已保存结果并退出\033[0m")
                    sys.exit(0)
                break

    def _print_stats(self):
        elapsed = time.time() - self.start_time if self.start_time else 0
        total = self._get_total_paths()

        print("\n" + "=" * 60)
        print(f"当前扫描统计:")
        print(f"  已扫描路径数: {self.scanned_count}/{total}")
        print(f"  有效结果数: {self.found_count}")
        print(f"  已发现敏感路径数: {self.sensitive_count}")
        print(f"  总耗时: {elapsed:.1f}秒")
        print(f"  平均速度: {self.scanned_count/elapsed:.1f} 条/秒" if elapsed > 0 else "  平均速度: 计算中...")
        print("=" * 60)

    def _get_total_paths(self) -> int:
        return getattr(self.args, 'total_paths', self.scanned_count)

    def normalize_url(self, url: str) -> str:
        parsed = urllib.parse.urlparse(url)
        if not parsed.scheme:
            url = f"http://{url}"
            parsed = urllib.parse.urlparse(url)

        path = parsed.path if parsed.path else "/"
        if not path.endswith("/"):
            path += "/"

        return f"{parsed.scheme}://{parsed.netloc}{path}"

    def load_wordlist(self) -> Set[str]:
        paths: Set[str] = set()

        if os.path.isfile(self.args.wordlist):
            self._load_file(self.args.wordlist, paths)
        elif os.path.isdir(self.args.wordlist):
            for filename in os.listdir(self.args.wordlist):
                if filename.endswith(".txt"):
                    self._load_file(os.path.join(self.args.wordlist, filename), paths)
        else:
            print(f"\033[91m错误: 字典路径不存在: {self.args.wordlist}\033[0m")
            sys.exit(1)

        return paths

    def _load_file(self, filepath: str, paths: Set[str]):
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    paths.add(line)
        except Exception as e:
            if self.args.debug:
                print(f"读取文件失败 {filepath}: {e}")

    def crawl(self, url: str, max_depth: int = 2) -> Set[str]:
        from collections import deque
        from concurrent.futures import ThreadPoolExecutor, as_completed

        crawl_threads = getattr(self.args, 'crawl_threads', 5)
        print(f"\n\033[94m[*] 启动爬虫模式，深度: {max_depth}，并发: {crawl_threads}\033[0m")

        crawled: Set[str] = set()
        css_js_paths: Set[str] = set()
        visited: Set[str] = set()
        visited_lock = threading.Lock()
        to_crawl = deque([(url, 0)])
        to_crawl_lock = threading.Lock()
        base_domain = urllib.parse.urlparse(url).netloc
        base_scheme_netloc = f"{urllib.parse.urlparse(url).scheme}://{urllib.parse.urlparse(url).netloc}"
        is_spa_detected = False
        spa_detected_lock = threading.Lock()
        results_lock = threading.Lock()
        crawled_count = [0]
        forms: List[Dict] = []

        common_spa_routes = [
            "/", "/home", "/index", "/login", "/register", "/signup", "/signin",
            "/logout", "/dashboard", "/admin", "/administrator", "/manage", "/management",
            "/settings", "/profile", "/user", "/users", "/account", "/accounts",
            "/api", "/api/v1", "/api/v2", "/rest", "/graphql",
            "/auth", "/oauth", "/sso", "/cas", "/ldap",
            "/backup", "/backups", "/config", "/configuration", "/settings",
            "/upload", "/uploads", "/download", "/downloads", "/file", "/files",
            "/docs", "/documentation", "/swagger", "/api-docs", "/openapi",
            "/console", "/terminal", "/shell", "/bash", "/ssh",
            "/test", "/tests", "/testing", "/debug", "/trace", "/monitor",
            "/status", "/health", "/healthz", "/actuator", "/metrics",
            "/product", "/products", "/order", "/orders", "/cart", "/checkout", "/payment", "/payments",
            "/news", "/article", "/articles", "/post", "/posts", "/blog",
            "/search", "/query", "/find", "/filter",
            "/help", "/faq", "/support", "/contact",
            "/about", "/company", "/careers", "/jobs", "/team",
            "/pricing", "/plans", "/subscription", "/billing",
            "/invoice", "/invoices", "/receipt", "/receipts",
            "/reports", "/analytics", "/statistics", "/stats", "/data",
            "/export", "/import", "/migrate", "/migration",
            "/database", "/db", "/sql", "/mysql", "/postgres", "/mongodb", "/redis", "/elasticsearch",
            "/phpmyadmin", "/adminer", "/pgadmin", "/rocketchat", "/jira", "/confluence",
            "/git", "/svn", "/jenkins", "/ci", "/cd", "/pipeline",
            "/webhook", "/callback", "/notify", "/notification", "/notifications",
            "/message", "/messages", "/chat", "/inbox", "/sent", "/draft", "/drafts",
            "/calendar", "/event", "/events", "/schedule", "/scheduler",
            "/task", "/tasks", "/todo", "/todos", "/project", "/projects", "/workspace",
            "/member", "/members", "/group", "/groups", "/team", "/teams", "/organization", "/org",
            "/permission", "/permissions", "/role", "/roles", "/access", "/authorize",
            "/log", "/logs", "/logging", "/logger", "/audit", "/auditlog",
            "/security", "/vulnerability", "/scan", "/scanner",
            "/asset", "/assets", "/image", "/images", "/photo", "/photos", "/video", "/videos", "/media",
            "/template", "/templates", "/theme", "/themes", "/css", "/styles", "/style",
            "/script", "/scripts", "/js", "/javascript", "/font", "/fonts", "/icon", "/icons",
            "/v1", "/v2", "/v3", "/v4", "/v5", "/latest", "/current", "/stable",
            "/beta", "/alpha", "/test", "/testing", "/demo", "/staging", "/stage", "/dev", "/development", "/prod", "/production",
            "/app", "/application", "/portal", "/sso", "/idp", "/sp",
            "/verify", "/confirm", "/activate", "/activation", "/reset", "/forgot", "/recover",
            "/en", "/zh", "/cn", "/ja", "/ko", "/es", "/fr", "/de", "/ru", "/ar", "/i18n", "/lang", "/language",
        ]

        def crawl_single_url(current_url: str, depth: int) -> Tuple[Set[str], Set[str], List[Tuple[str, int]], List[Dict]]:
            nonlocal is_spa_detected
            local_crawled: Set[str] = set()
            local_css_js_paths: Set[str] = set()
            local_new_links: List[Tuple[str, int]] = []
            local_forms: List[Dict] = []

            try:
                if self.args.debug:
                    print(f"[D] 爬取: {current_url} (深度: {depth})")

                resp = self.session.get(current_url, timeout=self.args.timeout, verify=False)
                final_url = resp.url

                if self.args.debug and final_url != current_url:
                    print(f"[D] 重定向: {current_url} -> {final_url}")

                local_crawled.add(final_url)

                if self.args.debug:
                    print(f"[D] 响应: {final_url} - 状态:{resp.status_code} 大小:{len(resp.content)}B")

                final_url_parsed = urllib.parse.urlparse(final_url)
                base_path_prefix = final_url_parsed.path.rsplit("/", 1)[0] if final_url_parsed.path else ""
                is_root_path = final_url_parsed.path == "/" or final_url_parsed.path == ""

                if depth == 0 and len(resp.content) < 500:
                    with spa_detected_lock:
                        if not is_spa_detected:
                            is_spa_detected = True
                            print(f"\033[94m[*] 检测到可能是 SPA 站点或存在重定向 (主页响应 {len(resp.content)}B，最终路径: {final_url_parsed.path})\033[0m")
                            if self.args.debug:
                                print(f"[D] 即将添加 {len(common_spa_routes)} 个常见路由")
                            for route in common_spa_routes:
                                if is_root_path:
                                    full_route_url = base_scheme_netloc + route
                                else:
                                    full_route_url = base_scheme_netloc + base_path_prefix + route
                                local_new_links.append((full_route_url, 1))
                                if self.args.debug:
                                    print(f"[D] 添加SPA路由: {full_route_url}")

                if depth < max_depth:
                    parser = LinkExtractor(final_url)
                    parser.feed(resp.text)
                    local_forms = list(parser.forms)

                    css_links = self._extract_css_links(resp.text, final_url)
                    js_links = self._extract_js_links(resp.text, final_url)

                    if self.args.debug:
                        print(f"[D] 发现 {len(css_links)} 个CSS链接, {len(js_links)} 个JS链接")

                    for css_url in css_links:
                        css_paths = self._fetch_and_parse_css(css_url)
                        local_css_js_paths.update(css_paths)

                    for js_url in js_links:
                        js_paths = self._fetch_and_parse_js(js_url)
                        local_css_js_paths.update(js_paths)

                    for link in parser.links:
                        if self.args.debug:
                            print(f"[D] 发现链接: {link}")
                        local_new_links.append((link, depth + 1))

                    parent_paths = parser.extract_parent_paths(parser.links)
                    for parent in parent_paths:
                        local_new_links.append((parent, depth + 1))

            except Exception as e:
                if self.args.debug:
                    print(f"[D] 爬取失败: {current_url} - 错误: {e}")

            return local_crawled, local_css_js_paths, local_new_links, local_forms

        while True:
            if GLOBAL_STATE.should_exit:
                break

            while GLOBAL_STATE.paused:
                time.sleep(0.1)

            with to_crawl_lock:
                if not to_crawl:
                    break
                batch = []
                batch_size = min(crawl_threads * 2, len(to_crawl))
                for _ in range(batch_size):
                    if to_crawl:
                        batch.append(to_crawl.popleft())

            if not batch:
                break

            with ThreadPoolExecutor(max_workers=crawl_threads) as executor:
                futures = {executor.submit(crawl_single_url, url, depth): (url, depth) for url, depth in batch}

                for future in as_completed(futures):
                    if GLOBAL_STATE.should_exit:
                        break

                    local_crawled, local_css_js_paths, local_new_links, local_forms = future.result()
                    forms.extend(local_forms)

                    with results_lock:
                        for crawled_url in local_crawled:
                            if crawled_url not in visited:
                                visited.add(crawled_url)
                                crawled.add(crawled_url)
                                crawled_count[0] += 1
                        css_js_paths.update(local_css_js_paths)

                    with to_crawl_lock:
                        for new_url, new_depth in local_new_links:
                            if new_url not in visited and new_depth <= max_depth:
                                to_crawl.append((new_url, new_depth))

        if css_js_paths:
            print(f"\033[94m[*] CSS/JS提取路径: {len(css_js_paths)}\033[0m")

        combined_paths = crawled | css_js_paths
        self._last_crawl_forms = forms
        if forms:
            print(f"\033[94m[*] 从页面中提取到 {len(forms)} 个表单\033[0m")
        print(f"\033[94m[*] 爬虫完成，共提取 {len(combined_paths)} 条路径 (爬取 {len(crawled)} 个页面)\033[0m")
        return combined_paths

    def _extract_css_links(self, html: str, base_url: str) -> Set[str]:
        css_links = set()
        css_pattern = re.compile(r'<link[^>]+href=["\']([^"\']+\.css[^"\']*)["\']', re.IGNORECASE)
        for match in css_pattern.finditer(html):
            href = match.group(1)
            full_url = urllib.parse.urljoin(base_url, href)
            css_links.add(full_url)
        return css_links

    def _extract_js_links(self, html: str, base_url: str) -> Set[str]:
        js_links = set()
        js_pattern = re.compile(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', re.IGNORECASE)
        for match in js_pattern.finditer(html):
            src = match.group(1)
            full_url = urllib.parse.urljoin(base_url, src)
            js_links.add(full_url)
        return js_links

    def _fetch_and_parse_css(self, css_url: str) -> Set[str]:
        paths = set()
        try:
            if self.args.debug:
                print(f"[D] 解析CSS: {css_url}")
            resp = self.session.get(css_url, timeout=self.args.timeout, verify=False)
            if resp.status_code == 200:
                parser = CSSParser(css_url)
                paths = parser.parse(resp.text)
                if self.args.debug and paths:
                    print(f"[D] CSS提取路径: {len(paths)} 个")
        except Exception as e:
            if self.args.debug:
                print(f"[D] CSS解析失败: {css_url} - 错误: {e}")
        return paths

    def _fetch_and_parse_js(self, js_url: str) -> Set[str]:
        paths = set()
        try:
            if self.args.debug:
                print(f"[D] 解析JS: {js_url}")
            resp = self.session.get(js_url, timeout=self.args.timeout, verify=False)
            if resp.status_code == 200:
                parser = JSParser(js_url)
                paths = parser.parse(resp.text)
                if self.args.debug and paths:
                    print(f"[D] JS提取路径: {len(paths)} 个")
                    for p in list(paths)[:5]:
                        print(f"[D]   - {p}")
                    if len(paths) > 5:
                        print(f"[D]   ... 还有 {len(paths) - 5} 个")
        except Exception as e:
            if self.args.debug:
                print(f"[D] JS解析失败: {js_url} - 错误: {e}")
        return paths

    def _combine_extracted_paths(self, base_url: str, extracted_paths: Set[str]) -> Set[str]:
        fragments = []
        for path in extracted_paths:
            parsed = urllib.parse.urlparse(path)
            path_parts = parsed.path.strip('/').split('/')
            for part in path_parts:
                if part and '.' not in part and len(part) > 2:
                    fragments.append(part)

        combined = PathCombiner.combine_paths(base_url, fragments, max_up_levels=3)
        combined = PathCombiner.deduplicate_paths(combined)
        return combined

    def extract_parent_paths(self, paths: Set[str]) -> Set[str]:
        result = set()
        for path in paths:
            parsed = urllib.parse.urlparse(path)
            path_parts = parsed.path.strip("/").split("/")
            for i in range(1, len(path_parts)):
                parent = "/".join(path_parts[:i])
                result.add(f"{parsed.scheme}://{parsed.netloc}/{parent}")
        return result

    def is_sensitive_path(self, path: str) -> bool:
        path_lower = path.lower()
        sensitive_words = self.args.sensitive_words.split(",") if hasattr(self.args, "sensitive_words") and self.args.sensitive_words else DEFAULT_SENSITIVE_WORDS

        for word in sensitive_words:
            word = word.strip()
            if word and word.lower() in path_lower:
                return True
        return False

    def classify_paths(self, paths: Set[str]) -> Tuple[Set[str], Set[str], Set[str]]:
        sensitive = set()
        crawler = set()
        normal = set()

        for path in paths:
            if self.is_sensitive_path(path):
                sensitive.add(path)
            elif path.startswith(self.args.url):
                crawler.add(path)
            else:
                normal.add(path)

        return sensitive, crawler, normal

    def build_scan_queue(self, wordlist_paths: Set[str], crawler_paths: Optional[Set[str]] = None) -> List[str]:
        all_paths: Set[str] = set()

        if self.args.mode in ("wordlist", "mixed"):
            all_paths.update(wordlist_paths)

        if self.args.mode in ("crawl", "mixed"):
            if crawler_paths:
                all_paths.update(crawler_paths)

        if not all_paths:
            print("\033[91m[!] 没有可扫描的路径，请检查字典路径或启用爬虫模式\033[0m")
            return []

        sensitive, crawler, normal = self.classify_paths(all_paths)

        if self.args.priority_scan:
            return list(sensitive) + list(crawler) + list(normal)
        else:
            return list(all_paths)

    # ------------------------------------------------------------------
    # 统一请求层：两个引擎都走这里，判定逻辑只有一份
    # ------------------------------------------------------------------

    def _is_textual(self, resp: RespInfo) -> bool:
        ct = (resp.headers.get("content-type") or "").lower()
        if not ct:
            return True
        binary_prefixes = (
            "image/", "audio/", "video/", "font/",
            "application/octet-stream", "application/zip",
            "application/pdf", "application/x-gzip", "application/x-zip-compressed",
        )
        return not ct.startswith(binary_prefixes)

    def _fmt_size(self, size: int) -> str:
        if size < 1024:
            return f"{size}B"
        if size < 1024 * 1024:
            return f"{size/1024:.1f}KB"
        return f"{size/1024/1024:.1f}MB"

    def _request_sync(self, task: Task) -> Optional[RespInfo]:
        """线程引擎的请求实现。"""
        self._enhance_request_headers()
        headers = dict(self.session.headers)
        headers.update(task.headers)
        if task.content_type and task.data is not None:
            headers["Content-Type"] = task.content_type

        body = None
        if task.data is not None:
            body = task.data.encode("utf-8") if isinstance(task.data, str) else task.data

        start = time.time()
        resp = self.session.request(
            method=task.method,
            url=task.url,
            data=body,
            headers=headers,
            timeout=self.args.timeout,
            allow_redirects=True,
            verify=False,
        )
        return RespInfo(
            status=resp.status_code,
            url=resp.url,
            headers={k.lower(): v for k, v in resp.headers.items()},
            content=resp.content,
            history=[r.url for r in resp.history],
            elapsed=time.time() - start,
            method=task.method,
            request_headers=headers,
            request_body=task.data or "",
        )

    def evaluate(self, task: Task, resp: RespInfo) -> Optional[Dict]:
        """
        唯一的判定入口。状态码过滤 -> 软404 -> 关键词 -> 去重 -> 敏感标记
        -> 敏感信息匹配 -> 证据落盘。
        """
        status = resp.status
        final_url = resp.url

        include_status = getattr(self.args, "include_status", None)
        exclude_status = getattr(self.args, "exclude_status", None)
        default_exclude = {404, 500, 502, 503, 504}

        if exclude_status:
            exclude_codes = set(int(x.strip()) for x in exclude_status.split(",") if x.strip().isdigit())
        else:
            exclude_codes = default_exclude

        if include_status:
            include_codes = set(int(x.strip()) for x in include_status.split(",") if x.strip().isdigit())
            if status not in include_codes:
                return None
        elif status in exclude_codes:
            return None

        is_sensitive = self.is_sensitive_path(final_url)

        # 重定向去重只看"最终落地地址"：
        # - 跟随重定向后拿到 200 的，落地地址就是 resp.url；
        # - 未跟随（3xx）的，用 Location 头。
        # 注意不能用 history[-1]，那是请求 URL，每个任务都不同，起不到去重作用。
        if resp.history:
            redirect_target = final_url
        elif 300 <= status < 400:
            redirect_target = resp.headers.get("location") or final_url
        else:
            redirect_target = ""

        is_sensitive_duplicate = False
        title = ""
        size_str = self._fmt_size(len(resp.content))
        secrets: List[str] = []

        if status == 200:
            self.soft_404_detector.record_size(len(resp.content))
            title = self._extract_title(resp.text)

            is_invalid, reason = self.soft_404_detector.is_invalid_content(resp, title)
            if is_invalid:
                if self.args.debug:
                    print(f"[D] 过滤无效页面: {final_url} ({reason})")
                return None

            valid_keywords = getattr(self.args, "valid_keywords", None)
            if valid_keywords:
                kws = [k.strip().lower() for k in valid_keywords.split(",") if k.strip()]
                if kws:
                    body_lower = resp.text.lower()
                    if not any(k in body_lower for k in kws):
                        return None

            invalid_keywords = getattr(self.args, "invalid_keywords", None)
            if invalid_keywords:
                kws = [k.strip().lower() for k in invalid_keywords.split(",") if k.strip()]
                if kws:
                    body_lower = resp.text.lower()
                    if any(k in body_lower for k in kws):
                        return None

            if self._is_textual(resp):
                secrets = match_secrets(resp.content)
        else:
            if status not in (204, 304):
                title = self._extract_title(resp.text)

        # --- 去重：模板聚类（两个引擎共用；旧的两处 check_and_add 已合并到这里）---
        keep, note, is_sensitive_duplicate, cluster_id = self._apply_dedup(
            status, resp, final_url, is_sensitive, redirect_target)
        if not keep:
            return None

        # 记录状态码维度的 URL 清单，供 Phase 2（403 绕过 / 备份 fuzz）使用。
        # 折叠掉的结果不会进 self.results，但绕过探测需要真实路径，所以单独存一份。
        self._record_status_url(status, final_url)

        if getattr(self.args, "sourcemap", False):
            self._maybe_extract_sourcemap(status, resp, final_url)

        evidence_file = ""
        if getattr(self.args, "save_evidence", True) and (status == 200 or is_sensitive or secrets):
            evidence_file = self._save_evidence(task, resp)

        return {
            "url": final_url,
            "method": task.method,
            "status_code": status,
            "status_desc": self._get_status_desc(status),
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "title": title,
            "is_sensitive": 1 if is_sensitive else 0,
            "is_sensitive_duplicate": 1 if is_sensitive_duplicate else 0,
            "content_size": size_str,
            "redirect_chain": " -> ".join(resp.history + [final_url]) if resp.history else "",
            "content_type": (resp.headers.get("content-type") or "")[:60],
            "secrets": ",".join(secrets),
            "evidence_file": evidence_file,
            "cluster": cluster_id,
            "dup_count": 0,
            "note": note,
        }

    # ------------------------------------------------------------------
    # 去重：模板聚类
    # ------------------------------------------------------------------

    def _apply_dedup(self, status: int, resp: 'RespInfo', url: str,
                     is_sensitive: bool, redirect_target: str) -> Tuple[bool, str, bool, str]:
        """
        返回 (是否保留, 备注, 是否敏感重复项)。

        off      - 完全不去重
        redirect - 旧行为，只按最终落地 URL 去重
        template - 默认。按"页面骨架"聚类，同簇只留 1 条，其余进 sidecar
        strict   - 同 template，但敏感路径不参与折叠（每条都单独出结果）
        """
        mode = getattr(self.args, "dedup_mode", "template")
        if mode == "off":
            return True, "", False, ""

        if mode == "redirect":
            is_new, is_sensitive_duplicate = self.fingerprint_cache.check_and_add(
                status, resp.content, url, is_sensitive, redirect_target)
            return (is_new, "", bool(is_sensitive_duplicate), "")

        fp = self.response_cluster.fingerprint(status, resp.content, resp.headers)
        count = self.response_cluster.put(fp, url)

        if count > CLUSTER_HARD_CAP:
            return False, "", False, fp

        keep_per = max(1, int(getattr(self.args, "dedup_keep", 1) or 1))
        if mode == "strict" and is_sensitive:
            return True, "", False, fp
        if count > keep_per:
            # 第一次达到"通用页"量级时提示一次，避免用户以为结果丢了
            threshold = max(2, int(getattr(self.args, "dedup_generic", 5) or 5))
            if count == threshold + 1:
                print(f"\n\033[93m[i] 检测到通用响应模板（{status}，已出现 {count} 次）："
                      f"{url[:70]}\033[0m")
                print(f"\033[93m    后续同模板响应将折叠计数，完整 URL 清单见 clusters/ 目录\033[0m\n")
            return False, "", False, fp

        return True, "", False, fp

    def _record_status_url(self, status: int, url: str):
        """按状态码留存 URL，供 Phase 2 使用。上限内才记，防止内存膨胀。"""
        cap = int(getattr(self.args, "status_url_cap", 4000) or 4000)
        try:
            with self.results_lock:
                lst = self.status_urls.setdefault(status, [])
                if len(lst) < cap:
                    lst.append(url)
        except Exception:
            pass

    def _annotate_clusters(self):
        """扫描结束后回填折叠数量与备注，并把每个簇的完整 URL 写进 sidecar。"""
        if getattr(self.args, "dedup_mode", "template") not in ("template", "strict"):
            return
        threshold = max(2, int(getattr(self.args, "dedup_generic", 5) or 5))
        sidecar_dir = getattr(self.args, "cluster_dir", "clusters")

        big = []
        for r in self.results:
            fp = r.get("cluster") or ""
            c = self.response_cluster.clusters.get(fp)
            if not c:
                continue
            n = c["count"] - 1
            r["dup_count"] = n
            status = r.get("status_code", 0)
            title = (r.get("title") or "").lower()
            if n >= threshold:
                if status in (401, 403):
                    r["note"] = f"WAF/中间件默认拒绝页（折叠 {n} 条）"
                elif any(p in title for p in GENERIC_TITLE_PATTERNS):
                    r["note"] = f"疑似通用兜底/维护页（折叠 {n} 条）"
                else:
                    r["note"] = f"同模板响应（折叠 {n} 条）"
            elif n > 0:
                r["note"] = f"同模板响应（折叠 {n} 条）"
            if n > 0:
                big.append((n, status, r.get("url", ""), r.get("title", "")))

        if not big:
            return

        try:
            os.makedirs(sidecar_dir, exist_ok=True)
        except Exception:
            sidecar_dir = ""

        written = 0
        for fp, c in self.response_cluster.clusters.items():
            if c["count"] < 2 or not sidecar_dir:
                continue
            safe = re.sub(r"[^0-9A-Za-z]+", "_", fp)[:60]
            try:
                with open(os.path.join(sidecar_dir, f"{safe}.txt"), "w", encoding="utf-8") as f:
                    f.write(f"# 簇 {fp}  共 {c['count']} 条\n")
                    for u in c["urls"]:
                        f.write(u + "\n")
                written += 1
            except Exception:
                pass

        big.sort(reverse=True)
        print(f"\n\033[96m[*] 响应聚类：{len(self.response_cluster.clusters)} 个模板，"
              f"折叠掉 {self.response_cluster.total_collapsed} 条重复响应\033[0m")
        print(f"\033[96m    完整 URL 清单已写入 {sidecar_dir or '(未写)'} ({written} 个簇)\033[0m")
        print("\033[96m    折叠最多的模板 Top5:\033[0m")
        for n, status, url, title in big[:5]:
            print(f"\033[96m      x{n + 1:<5} [{status}] {url[:58]}"
                  f"{('  ' + title[:26]) if title else ''}\033[0m")

    # ------------------------------------------------------------------
    # Phase 2：探测能力扩展（03 绕过 / 递归 / 备份 / 敏感文件）
    # ------------------------------------------------------------------

    def _run_phase2(self):
        if GLOBAL_STATE.should_exit:
            return
        args = self.args
        enabled = any([
            getattr(args, 'phase2', False) or getattr(args, 'bypass_403', False)
            or getattr(args, 'recursive', False) or getattr(args, 'backup_fuzz', False)
            or getattr(args, 'sensitive_files', False) or getattr(args, 'sourcemap', False),
        ])
        if not enabled:
            return

        method = getattr(args, 'method', 'GET')
        rounds = max(1, int(getattr(args, 'phase2_rounds', 1) or 1))
        for r in range(rounds):
            new_tasks = []
            # --phase2 是总开关：单独传 --phase2 时全部探测生效
            all_on = getattr(args, 'phase2', False)
            if all_on or getattr(args, 'bypass_403', False):
                new_tasks += self._gen_bypass_tasks(method)
            if all_on or getattr(args, 'recursive', False):
                new_tasks += self._gen_recursive_tasks(method)
            if all_on or getattr(args, 'backup_fuzz', False):
                new_tasks += self._gen_backup_tasks(method)
            if all_on or getattr(args, 'sensitive_files', False):
                new_tasks += self._gen_sensitive_file_tasks(method)

            added = 0
            for t in new_tasks:
                k = t.key()
                with self.discovered_lock:
                    if k in self.scanned_keys or k in self.all_discovered_tasks:
                        continue
                    self.all_discovered_tasks[k] = t
                    added += 1
            if added == 0:
                print('\n\033[94m[*] Phase 2 没有新增任务，结束\033[0m')
                break
            print(f'\n\033[94m[*] Phase 2 round {r+1}: +{added} tasks\033[0m')

            pending = [t for k, t in self.all_discovered_tasks.items() if k not in self.scanned_keys]
            self.args.total_paths = len(pending)
            self._scan_tasks(pending)
            if GLOBAL_STATE.should_exit:
                break

    def _gen_bypass_tasks(self, method):
        urls = list(self.status_urls.get(403, [])) + list(self.status_urls.get(401, []))
        if not urls:
            return []
        max_n = max(1, int(getattr(self.args, 'bypass_max', 60)))
        urls = urls[:max_n]
        out = []
        for url in urls:
            parsed = urllib.parse.urlsplit(url)
            path = parsed.path or '/'
            for h in BYPASS_HEADER_NAMES:
                for v in bypass_header_values(h, path, self.args.url):
                    out.append(Task(url=url, method=method, source='bypass', headers={h: v}))
            for mut in bypass_path_variants(url):
                out.append(Task(url=mut, method=method, source='bypass'))
        return out

    def _gen_recursive_tasks(self, method):
        candidates = set()
        for r in self.results:
            if r.get('status_code') not in (200, 301, 302):
                continue
            p = urllib.parse.urlparse(r.get('url', '')).path
            if not p:
                continue
            parent = p.rsplit('/', 1)[0]
            if not parent:
                continue
            base = urllib.parse.urlsplit(r['url'])
            base_url = urllib.parse.urlunsplit((base.scheme, base.netloc, parent, '', ''))
            candidates.add(base_url)
        max_dirs = max(1, int(getattr(self.args, 'recursive_max_dirs', 20)))
        out = []
        for base_url in list(candidates)[:max_dirs]:
            for w in RECURSIVE_WORDS:
                out.append(Task(url=base_url + '/' + w, method=method, source='recursive'))
        return out

    def _gen_backup_tasks(self, method):
        urls = []
        for r in self.results:
            if r.get('status_code') == 200:
                urls.append(r.get('url'))
            if len(urls) >= int(getattr(self.args, 'backup_max', 200)):
                break
        out = []
        for u in urls:
            for v in backup_variants(u):
                out.append(Task(url=v, method=method, source='backup'))
        return out

    def _gen_sensitive_file_tasks(self, method):
        out = []
        for f in SENSITIVE_FILES:
            out.append(Task(url=self.args.url.rstrip('/') + '/' + f, method=method, source='sensitive'))
        seen = set()
        for r in self.results:
            if r.get('status_code') != 200:
                continue
            p = urllib.parse.urlparse(r.get('url', '')).path
            if not p:
                continue
            parent = p.rsplit('/', 1)[0]
            if not parent or parent in seen:
                continue
            seen.add(parent)
            base = urllib.parse.urlsplit(r['url'])
            base_url = urllib.parse.urlunsplit((base.scheme, base.netloc, parent, '', ''))
            for f in SENSITIVE_FILES:
                out.append(Task(url=base_url + '/' + f, method=method, source='sensitive'))
        return out

    # ------------------------------------------------------------------
    # Phase 2：sourcemap 提取（拿到 JS 响应时顺手做，代价极低）
    # ------------------------------------------------------------------
    # ------------------------------------------------------------------
    # Phase 2：sourcemap 提取（拿到 JS 响应时顺手做，代价极低）
    # ------------------------------------------------------------------

    def _maybe_extract_sourcemap(self, status: int, resp: 'RespInfo', url: str):
        try:
            if status != 200 or not resp.content:
                return
            method = getattr(self.args, "method", "GET")
            path = urllib.parse.urlparse(url).path

            if path.endswith(".map"):
                import json as _json
                data = _json.loads(resp.content[:4 * 1024 * 1024].decode("utf-8", "ignore"))
                for s in (data.get("sources") or [])[:500]:
                    s = (s or "").strip()
                    if not s or s.startswith("webpack://") and "/" not in s:
                        continue
                    s = re.sub(r"^webpack:///", "", s)
                    s = re.sub(r"^webpack://", "", s)
                    if not s.startswith("/"):
                        s = "/" + s.lstrip("./")
                    if s.startswith("/"):
                        self.add_task(Task(url=urllib.parse.urljoin(self.args.url, s),
                                           method=method, source="sourcemap"))
                return

            if path.endswith(".js"):
                tail = resp.content[-512:].decode("utf-8", "ignore")
                m = re.search(r"sourceMappingURL=([^\s*]+)", tail)
                if not m:
                    head = resp.content[:4096].decode("utf-8", "ignore")
                    m = re.search(r"sourceMappingURL=([^\s*]+)", head)
                if m:
                    sm = urllib.parse.urljoin(url, m.group(1).strip())
                    self.add_task(Task(url=sm, method=method, source="sourcemap"))
        except Exception:
            pass

    def _save_evidence(self, task: Task, resp: RespInfo) -> str:
        """把请求与响应原文落盘，便于直接粘进工单或导入 Burp 复现。"""
        try:
            evidence_dir = getattr(self.args, "evidence_dir", "evidence") or "evidence"
            os.makedirs(evidence_dir, exist_ok=True)

            digest = hashlib.md5(task.key().encode("utf-8", errors="ignore")).hexdigest()[:12]
            safe_status = resp.status if isinstance(resp.status, int) else 0
            path = os.path.join(evidence_dir, f"{safe_status}_{digest}.txt")

            parsed = urllib.parse.urlparse(task.url)
            target = parsed.path or "/"
            if parsed.query:
                target += "?" + parsed.query

            lines = [f"{task.method} {target} HTTP/1.1", f"Host: {parsed.netloc}"]
            for k, v in (resp.request_headers or {}).items():
                if k.lower() == "host":
                    continue
                lines.append(f"{k}: {v}")
            lines.append("")
            if task.data:
                lines.append(task.data)
                lines.append("")

            lines.append("-" * 60)
            lines.append(f"HTTP/1.1 {resp.status} {self._get_status_desc(resp.status)}")
            for k, v in resp.headers.items():
                lines.append(f"{k}: {v}")
            lines.append("")
            if self._is_textual(resp):
                lines.append(resp.content[:EVIDENCE_BODY_LIMIT].decode("utf-8", errors="ignore"))
            else:
                lines.append(f"<binary content {len(resp.content)} bytes, omitted>")

            with open(path, "w", encoding="utf-8", errors="ignore") as f:
                f.write("\n".join(lines))
            return path
        except Exception:
            return ""

    def scan_task(self, task: Task) -> Optional[Dict]:
        """线程引擎的单任务入口。"""
        if self.rate_limiter:
            self.rate_limiter.acquire()
        if self.ban_recovery_manager.should_wait():
            time.sleep(self.ban_recovery_manager.get_wait_time())
            self.session.headers.update({"User-Agent": random.choice(DEFAULT_USER_AGENTS)})

        if self.proxy_pool:
            proxy = self.proxy_pool.get_next_proxy()
            if proxy:
                self.session.proxies = proxy

        for attempt in range(self.args.retry + 1):
            try:
                resp = self._request_sync(task)
                if resp is None:
                    raise RuntimeError("request returned nothing")

                self.ban_recovery_manager.record_response(resp.status, resp.headers.get("retry-after"))
                if "set-cookie" in resp.headers:
                    self._update_cookies(resp.headers.get("set-cookie", ""))

                return self.evaluate(task, resp)

            except requests.exceptions.Timeout:
                self.adaptive_thread_controller.record_timeout()
                if attempt < self.args.retry:
                    self.session.headers.update({"User-Agent": random.choice(DEFAULT_USER_AGENTS)})
                    time.sleep(0.5)
                    continue
                with self.failed_lock:
                    self.failed_tasks.append(task)
                return None
            except Exception as e:
                if attempt < self.args.retry:
                    self.session.headers.update({"User-Agent": random.choice(DEFAULT_USER_AGENTS)})
                    time.sleep(0.5)
                    continue
                if self.args.debug:
                    print(f"请求错误 {task.url}: {e}")
                with self.failed_lock:
                    self.failed_tasks.append(task)
                return None

        return None

    def _form_to_task(self, form: Dict, base_url: str) -> Optional[Task]:
        """把 HTML 表单转成可探测的 Task。"""
        action = form.get("action") or base_url
        url = urllib.parse.urljoin(base_url, action)
        method = (form.get("method") or "GET").upper()
        if method not in SUPPORTED_METHODS:
            method = "POST"
        inputs = form.get("inputs") or []
        if not inputs:
            return None

        pairs = [(i["name"], i.get("value") or "") for i in inputs]
        if method == "GET":
            qs = urllib.parse.urlencode(pairs)
            url = f"{url}{'&' if '?' in url else '?'}{qs}"
            return Task(url=url, method="GET", source="form")
        return Task(
            url=url,
            method=method,
            data=urllib.parse.urlencode(pairs),
            content_type=form.get("enctype") or "application/x-www-form-urlencoded",
            source="form",
        )

    def add_task(self, task: Task) -> bool:
        """登记任务，返回是否为新增。"""
        key = task.key()
        with self.discovered_lock:
            if key in self.all_discovered_tasks:
                return False
            self.all_discovered_tasks[key] = task
            self.all_discovered_paths.add(task.url)
            return True

    def _enhance_request_headers(self):
        referer = getattr(self.args, 'url', '')
        if referer:
            parsed = urllib.parse.urlparse(referer)
            self.session.headers['Referer'] = f"{parsed.scheme}://{parsed.netloc}/"
        accept_encoding = random.choice([
            'gzip, deflate, br',
            'gzip, deflate',
            'deflate, gzip',
            'br, gzip, deflate'
        ])
        self.session.headers['Accept-Encoding'] = accept_encoding
        accept_language = random.choice([
            'zh-CN,zh;q=0.9,en;q=0.8',
            'en-US,en;q=0.9,zh-CN;q=0.8',
            'zh-CN,zh;q=0.9',
            'en;q=0.9',
        ])
        self.session.headers['Accept-Language'] = accept_language
        self.session.headers['Accept'] = random.choice([
            'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            '*/*',
        ])

    def _update_cookies(self, set_cookie_header: str):
        try:
            cookie_parts = set_cookie_header.split(';')
            if cookie_parts:
                cookie_name_value = cookie_parts[0].strip()
                if '=' in cookie_name_value:
                    name, value = cookie_name_value.split('=', 1)
                    name = name.strip()
                    existing = self.session.headers.get('Cookie', '')
                    cookie_dict = {}
                    if existing:
                        for cookie in existing.split(';'):
                            if '=' in cookie:
                                k, v = cookie.split('=', 1)
                                cookie_dict[k.strip()] = v.strip()
                    cookie_dict[name] = value.strip()
                    new_cookies = '; '.join(f"{k}={v}" for k, v in cookie_dict.items())
                    self.session.headers['Cookie'] = new_cookies
        except Exception:
            pass

    def _extract_title(self, html: str) -> str:
        try:
            match = re.search(r"<title[^>]*>([^<]+)</title>", html, re.IGNORECASE)
            if match:
                title = match.group(1).strip()
                title = re.sub(r"\s+", " ", title)
                return title[:200]
        except Exception:
            pass
        return ""

    def _get_status_desc(self, status: int) -> str:
        descriptions = {
            200: "OK",
            301: "Moved Permanently",
            302: "Found",
            403: "Forbidden",
            404: "Not Found",
            500: "Internal Server Error",
            502: "Bad Gateway",
            503: "Service Unavailable",
            504: "Gateway Timeout",
        }
        return descriptions.get(status, "Unknown")

    def worker(self, task: Task, progress_callback=None):
        if GLOBAL_STATE.should_exit:
            return

        while GLOBAL_STATE.paused:
            time.sleep(0.1)
            if GLOBAL_STATE.should_exit:
                return

        random_delay = getattr(self.args, 'random_delay', True)
        with self.scanned_lock:
            is_first = self.scanned_count == 0
        if not is_first:
            delay = random.uniform(0.1, 0.5) if random_delay else self.args.delay
            time.sleep(delay)

        result = self.scan_task(task)

        with self.scanned_lock:
            self.scanned_count += 1

        with self.discovered_lock:
            self.scanned_keys.add(task.key())
            self.scanned_urls.add(task.url)

        if result:
            with self.results_lock:
                self.results.append(result)

            with self.found_lock:
                self.found_count += 1

            if result["is_sensitive"] == 1:
                with self.sensitive_lock:
                    self.sensitive_count += 1

            self._print_result(result)

        if progress_callback:
            progress_callback(self.scanned_count)

    def _print_result(self, result: Dict):
        status = result["status_code"]
        color = STATUS_CODE_COLORS.get(status, "")

        parts = []
        if result["is_sensitive"] == 1:
            parts.append("\033[91m[敏感]\033[0m ")
        method = result.get("method", "GET")
        if method and method != "GET":
            parts.append(f"\033[96m[{method}]\033[0m ")
        parts.append(color)
        parts.append(f"{result['url']} [{status}] {result['status_desc']} {result.get('content_size', '')}")
        if result.get("secrets"):
            parts.append(f" \033[95m[泄露:{result['secrets']}]\033[0m")
        parts.append(COLOR_RESET)
        print("".join(parts))

    def run(self):
        self.start_time = time.time()

        normalized_url = self.normalize_url(self.args.url)
        self.args.url = normalized_url
        print(f"\n目标 URL: {normalized_url}")
        print(f"扫描模式: {self.args.mode}")

        print(f"\n[*] 测试目标站点连接...")
        try:
            test_resp = self.session.get(normalized_url, timeout=5, verify=False)
            print(f"[*] 目标站点响应状态: {test_resp.status_code}")
        except Exception as e:
            print(f"\033[91m[!] 警告: 无法连接到目标站点: {e}\033[0m")
            print(f"[*] 将继续尝试扫描...\n")

        self._log_audit("start", {
            "url": normalized_url,
            "mode": self.args.mode,
            "method": getattr(self.args, 'method', 'GET'),
            "threads": self.args.threads,
            "wordlist": self.args.wordlist
        })

        # 断点续扫：只恢复状态，不再直接 return（原实现加载完就退出，一次请求都不发）
        if self.args.resume:
            self._load_resume_point()

        if getattr(self.args, 'soft_404_detect', True):
            print(f"\n[*] 正在检测软404...")
            try:
                if self.soft_404_detector.detect():
                    print(f"[*] 软404检测完成")
                else:
                    print(f"[!] 未检测到软404特征，跳过软404过滤")
            except Exception as e:
                print(f"[!] 软404检测异常，将跳过: {e}")

        method = (getattr(self.args, 'method', 'GET') or 'GET').upper()
        if method not in SUPPORTED_METHODS:
            print(f"\033[91m[!] 不支持的请求方法 {method}，回退 GET\033[0m")
            method = "GET"
        self.args.method = method

        data = getattr(self.args, 'data', None)
        content_type = getattr(self.args, 'content_type', None)

        wordlist_paths: Set[str] = set()
        crawler_paths: Optional[Set[str]] = None
        crawler_forms: List[Dict] = []

        use_async = getattr(self.args, 'async_mode', False)
        auto_async_threshold = 5
        if not use_async:
            if self.args.threads > auto_async_threshold or getattr(self.args, 'crawl_threads', 5) > auto_async_threshold:
                if sys.platform == "win32":
                    use_async = False
                    print(f"\n\033[93m[*] Windows环境，自动使用线程模式\033[0m")
                else:
                    use_async = True
                    print(f"\n\033[94m[*] 检测到高并发设置，自动启用异步模式\033[0m")

        if use_async:
            print(f"\n\033[94m[*] 异步模式: 启用\033[0m")

        if self.args.mode in ("wordlist", "mixed"):
            if os.path.exists(self.args.wordlist):
                print(f"加载字典: {self.args.wordlist}")
                wordlist_paths = self.load_wordlist()
                wordlist_paths = PathCombiner.deduplicate_paths(wordlist_paths)
                if getattr(self.args, 'dir_slash', False):
                    wordlist_paths = PathCombiner.apply_dir_slash(wordlist_paths)
                print(f"字典路径数: {len(wordlist_paths)}")
            else:
                print(f"\033[93m[!] 字典路径不存在: {self.args.wordlist}\033[0m")

        if self.args.mode in ("crawl", "mixed"):
            if use_async:
                async_crawler = AsyncCrawler(self.args, self)
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    crawler_paths = loop.run_until_complete(async_crawler.run_async())
                    crawler_forms = list(async_crawler.forms)
                finally:
                    loop.close()
                crawler_paths = PathCombiner.deduplicate_paths(crawler_paths)
                print(f"爬虫路径数: {len(crawler_paths)}")
            else:
                crawler_paths = self.crawl(normalized_url, self.args.crawl_depth)
                crawler_paths = PathCombiner.deduplicate_paths(crawler_paths)
                crawler_forms = list(getattr(self, '_last_crawl_forms', []))
                print(f"爬虫路径数: {len(crawler_paths)}")

        all_paths = self.build_scan_queue(wordlist_paths, crawler_paths)

        normalized_all_paths = []
        seen = set()
        for path in all_paths:
            norm = PathCombiner.normalize_path(path)
            if norm and norm not in seen:
                seen.add(norm)
                normalized_all_paths.append(path)
        all_paths = normalized_all_paths

        tasks: List[Task] = []
        for p in all_paths:
            url = p if p.startswith(("http://", "https://")) else urllib.parse.urljoin(normalized_url, p)
            tasks.append(Task(url=url, method=method, data=data, content_type=content_type, source="wordlist"))

        if getattr(self.args, 'scan_forms', True) and crawler_forms:
            form_tasks: List[Task] = []
            for form in crawler_forms:
                t = self._form_to_task(form, normalized_url)
                if t:
                    form_tasks.append(t)
            if form_tasks:
                print(f"[*] 从 HTML 表单生成 {len(form_tasks)} 个探测任务")
                tasks.extend(form_tasks)

        if self.args.resume and self.scanned_keys:
            before = len(tasks)
            tasks = [t for t in tasks if t.key() not in self.scanned_keys]
            print(f"\033[93m[*] 断点续扫：跳过已完成 {before - len(tasks)} 条，剩余 {len(tasks)} 条\033[0m")

        self.args.total_paths = len(tasks)
        print(f"总扫描任务数: {len(tasks)} (请求方法: {method})")

        if not tasks:
            print("\033[93m[!] 没有可扫描的任务，退出\033[0m")
            self._finish_scan()
            return

        if self.args.schedule_time or self.args.schedule_interval:
            self._schedule_scan(tasks)
            return

        print(f"去重模式: {getattr(self.args, 'dedup_mode', 'template')} (FingerprintCache: {self.fingerprint_cache.mode})")
        if getattr(self.args, 'save_evidence', True):
            print(f"证据落盘: 开启 -> {getattr(self.args, 'evidence_dir', 'evidence')}/")
        else:
            print(f"证据落盘: 关闭")

        if use_async:
            print(f"请求延时: {self.args.delay}秒\n")
            async_scanner = AsyncScanner(self.args, self)
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                loop.run_until_complete(async_scanner.run_async(tasks))
            finally:
                loop.close()
            self._finish_scan()
        else:
            print(f"线程数: {self.args.threads}")
            print(f"请求延时: {self.args.delay}秒")
            print(f"重试次数: {self.args.retry}")
            random_delay = getattr(self.args, 'random_delay', True)
            print(f"随机延时: {'开启' if random_delay else '关闭'}\n")
            self._run_iterative_scan(tasks)

    def _run_iterative_scan(self, initial_tasks: List[Task]):
        iteration = 0
        max_iterations = getattr(self.args, 'max_iterations', 10)
        method = getattr(self.args, 'method', 'GET')

        for t in initial_tasks:
            self.add_task(t)

        print(f"\n\033[94m[*] 启动迭代扫描模式，最大迭代次数: {max_iterations}\033[0m\n")

        while iteration < max_iterations:
            iteration += 1
            print(f"\033[94m[*] ========== 迭代 {iteration} ==========\033[0m")

            with self.discovered_lock:
                pending = [t for k, t in self.all_discovered_tasks.items() if k not in self.scanned_keys]

            if not pending:
                print(f"\033[94m[*] 没有新任务可扫描，停止迭代\033[0m")
                break

            self.args.total_paths = len(pending)
            print(f"待扫描任务数: {len(pending)}")

            self._scan_tasks(pending)

            if GLOBAL_STATE.should_exit:
                break

            # 正确的新增判定：记录本轮扫描前的任务总数，之后再比增量
            before = len(self.all_discovered_tasks)

            new_200 = self._get_unprocessed_200_urls()
            if not new_200:
                print(f"\n\033[94m[*] 未发现新的200路径，停止迭代\033[0m")
                break

            print(f"\n\033[94m[*] 发现 {len(new_200)} 个新增200路径，开始二次爬虫...\033[0m")
            for url in new_200:
                self._crawl_single_url(url)

            combined = self._get_combined_paths_from_discovered()
            if combined:
                print(f"\033[94m[*] 拼接路径发现 {len(combined)} 个新路径\033[0m")
                for u in combined:
                    self.add_task(Task(url=u, method=method, source="combined"))

            gained = len(self.all_discovered_tasks) - before
            print(f"\033[94m[*] 本轮迭代: 累计扫描 {self.scanned_count} 条，新增 {gained} 个任务\033[0m")

            # 每轮落盘一次断点。原实现只在 Ctrl+C 时保存，进程被 kill 就全丢
            self._save_resume_point()

            if gained == 0:
                print(f"\033[94m[*] 无新任务产生，停止迭代\033[0m")
                break

        else:
            print(f"\033[93m[!] 达到最大迭代次数 {max_iterations}，停止扫描\033[0m")

        self._finish_scan()

    def _crawl_single_url(self, url: str):
        if GLOBAL_STATE.should_exit:
            return
        method = getattr(self.args, 'method', 'GET')
        try:
            resp = self.session.get(url, timeout=self.args.timeout, verify=False)
            final_url = resp.url
            if self.args.debug and final_url != url:
                print(f"[D] 重定向: {url} -> {final_url}")
            if resp.status_code == 200:
                parser = LinkExtractor(final_url)
                parser.feed(resp.text)

                for css_url in self._extract_css_links(resp.text, final_url):
                    for p in self._fetch_and_parse_css(css_url):
                        self.add_task(Task(url=p, method=method, source="css"))

                for js_url in self._extract_js_links(resp.text, final_url):
                    for p in self._fetch_and_parse_js(js_url):
                        self.add_task(Task(url=p, method=method, source="js"))

                for link in parser.links:
                    if link.startswith(self.args.url):
                        self.add_task(Task(url=link, method=method, source="crawl"))

                for parent in parser.extract_parent_paths(parser.links):
                    self.add_task(Task(url=parent, method=method, source="crawl"))

                for form in parser.forms:
                    t = self._form_to_task(form, final_url)
                    if t:
                        self.add_task(t)

        except Exception:
            pass

    def _get_unprocessed_200_urls(self) -> Set[str]:
        """返回自上次调用以来新增的 200 URL，避免每轮重复处理全部历史结果。"""
        with self.results_lock:
            urls = {r["url"] for r in self.results if r["status_code"] == 200}
        new_urls = urls - self._processed_200
        self._processed_200 |= urls
        return new_urls

    def _get_combined_paths_from_discovered(self) -> Set[str]:
        combined: Set[str] = set()
        discovered_200 = self._processed_200
        max_combine = getattr(self.args, 'max_combine', 20000)

        if not discovered_200:
            return combined

        fragments: Set[str] = set()
        for url in discovered_200:
            parsed = urllib.parse.urlparse(url)
            for part in parsed.path.strip('/').split('/'):
                if part and '.' not in part and len(part) > 2:
                    fragments.add(part)

        if not fragments:
            return combined

        # 组合量是 O(200路径数 x 片段数 x 4)，必须设上限，否则会把扫描拖死
        fragment_list = list(fragments)
        for base_url in list(discovered_200)[:200]:
            combined.update(PathCombiner.combine_paths(base_url, fragment_list, max_up_levels=3))
            if len(combined) >= max_combine:
                break

        combined = PathCombiner.deduplicate_paths(combined)
        with self.discovered_lock:
            combined -= self.all_discovered_paths

        return combined

    def _scan_tasks(self, tasks: List[Task]):
        progress_lock = threading.Lock()
        last_update = [time.time()]
        update_interval = 0.5
        current_threads = self.args.threads

        # 进度按本轮计数，不能用全局累计 scanned_count，
        # 否则第二轮迭代会出现 800% 这种溢出
        local_count = [0]
        count_lock = threading.Lock()

        def progress_callback(_ignored=None):
            with count_lock:
                local_count[0] += 1
                count = local_count[0]

            with progress_lock:
                now = time.time()
                if now - last_update[0] >= update_interval:
                    last_update[0] = now
                    total = self.args.total_paths
                    percent = (count / total * 100) if total > 0 else 0
                    speed = count / (now - self.start_time) if self.start_time else 0
                    remaining = (total - count) / speed if speed > 0 else 0

                    bar_length = 30
                    filled = min(bar_length, int(bar_length * count / total)) if total > 0 else 0
                    bar = "=" * filled + "-" * (bar_length - filled)

                    sys.stdout.write(f"\r[{bar}] {percent:.1f}% {count}/{total} 速度:{speed:.1f}/s 剩余:{max(0, remaining):.0f}s 敏感:{self.sensitive_count} 线程:{current_threads} ")
                    sys.stdout.flush()

        pending = list(tasks)
        while True:
            current_threads = self.adaptive_thread_controller.get_threads()

            with self.discovered_lock:
                pending = [t for t in pending if t.key() not in self.scanned_keys]

            if not pending:
                break

            with ThreadPoolExecutor(max_workers=current_threads) as executor:
                futures = {executor.submit(self.worker, task, progress_callback): task for task in pending}

                for future in as_completed(futures):
                    if GLOBAL_STATE.should_exit:
                        for f in futures:
                            f.cancel()
                        break
                    try:
                        # 原实现从未调用 result()，worker 里的异常被静默吞掉
                        future.result()
                    except Exception as e:
                        if self.args.debug:
                            print(f"[D] worker 异常: {e}")

            if not self.failed_tasks:
                break

            print(f"\n\033[94m[*] 重试失败任务: {len(self.failed_tasks)}\033[0m")
            retry = self.failed_tasks[:]
            self.failed_tasks = []
            with self.discovered_lock:
                # 失败任务必须摘掉"已扫"标记，否则重试列表会被再次过滤成空
                for t in retry:
                    self.scanned_keys.discard(t.key())
            pending = retry

    def _finish_scan(self):
        print("\n")
        self._annotate_clusters()
        self._run_phase2()
        self._save_results()
        self._print_summary()

    def _print_summary(self):
        elapsed = time.time() - (self.start_time or time.time())
        status_counts = defaultdict(int)

        for result in self.results:
            status_counts[result["status_code"]] += 1

        print("=" * 60)
        print("扫描完成!")
        print(f"  总耗时: {elapsed:.1f}秒")
        print(f"  总扫描路径数: {self.scanned_count}")
        print(f"  有效结果数: {len(self.results)}")
        print(f"  已发现敏感路径数: {self.sensitive_count}")

        deduplicate = getattr(self.args, 'deduplicate', True)
        if deduplicate:
            dup_count = self.fingerprint_cache.get_duplicate_count()
            sens_dup_count = self.fingerprint_cache.get_sensitive_duplicate_count()
            print(f"  已过滤重复200状态项: {dup_count}条")
            print(f"  已过滤敏感路径重复项: {sens_dup_count}条")

        print(f"  状态码分布:")
        for status, count in sorted(status_counts.items()):
            print(f"    {status}: {count}")
        print("=" * 60)

        self._log_audit("complete", {
            "elapsed": elapsed,
            "scanned": self.scanned_count,
            "results": len(self.results),
            "sensitive": self.sensitive_count,
            "duplicates_filtered": self.fingerprint_cache.get_duplicate_count() if deduplicate else 0,
            "status_counts": dict(status_counts)
        })
        self._save_audit_log()

    def _save_audit_log(self):
        audit_file = getattr(self.args, 'audit_log', 'scan_audit.log')
        try:
            with open(audit_file, "a", encoding="utf-8") as f:
                for entry in self.audit_log:
                    f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except Exception:
            pass

    def _save_results(self):
        output_file = self.args.output
        if output_file == "scan_result.csv":
            parsed = urllib.parse.urlparse(self.args.url)
            host = parsed.netloc.replace(":", "_")
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"scan_{host}_{timestamp}.csv"
        output_format = getattr(self.args, 'format', 'csv').lower()

        try:
            if output_format == 'json':
                with open(output_file, "w", encoding="utf-8") as f:
                    with self.results_lock:
                        json.dump(self.results, f, ensure_ascii=False, indent=2)
            elif output_format == 'html':
                self._save_html_report(output_file)
            else:
                with open(output_file, "w", newline="", encoding="utf-8") as f:
                    writer = csv.DictWriter(f, fieldnames=RESULT_FIELDS)
                    writer.writeheader()
                    with self.results_lock:
                        for result in self.results:
                            writer.writerow(result)

            print(f"\n\033[92m[+] 结果已保存到: {output_file}\033[0m")

        except Exception as e:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_file = f"temp_scan_{timestamp}.csv"

            try:
                with open(backup_file, "w", newline="", encoding="utf-8") as f:
                    writer = csv.DictWriter(f, fieldnames=RESULT_FIELDS)
                    writer.writeheader()
                    with self.results_lock:
                        for result in self.results:
                            writer.writerow(result)

                print(f"\n\033[93m[!] 主文件保存失败，已备份到: {backup_file}\033[0m")
            except Exception:
                print(f"\n\033[91m[!] 结果保存失败: {e}\033[0m")

    def _save_html_report(self, output_file: str):
        status_counts = defaultdict(int)
        sensitive_high = []
        sensitive_mid = []
        sensitive_low = []
        high_risk_words = ['admin', 'sql', 'phpmyadmin', 'mysql', 'postgres', 'mongodb', 'redis', 'elasticsearch']
        mid_risk_words = ['api', 'docs', 'swagger', 'documentation']
        low_risk_words = ['test', 'dev', 'debug', 'trace']

        with self.results_lock:
            for result in self.results:
                status_counts[result["status_code"]] += 1
                if result["is_sensitive"] == 1:
                    url_lower = result["url"].lower()
                    if any(word in url_lower for word in high_risk_words):
                        sensitive_high.append(result)
                    elif any(word in url_lower for word in mid_risk_words):
                        sensitive_mid.append(result)
                    elif any(word in url_lower for word in low_risk_words):
                        sensitive_low.append(result)
                    else:
                        sensitive_mid.append(result)

        html_content = self._generate_html_content(status_counts, sensitive_high, sensitive_mid, sensitive_low)

        with open(output_file, "w", encoding="utf-8") as f:
            f.write(html_content)

    def _generate_html_content(self, status_counts: Dict, sensitive_high: List, sensitive_mid: List, sensitive_low: List) -> str:
        status_pie_data = ", ".join([f"'{k}', {v}" for k, v in sorted(status_counts.items())])
        status_labels = ", ".join([f"'{k}'" for k, v in sorted(status_counts.items())])
        status_values = ", ".join([str(v) for k, v in sorted(status_counts.items())])

        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>扫描报告</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 2px solid #4CAF50; padding-bottom: 10px; }}
        h2 {{ color: #666; margin-top: 30px; }}
        .risk-high {{ color: #d32f2f; font-weight: bold; }}
        .risk-mid {{ color: #f57c00; font-weight: bold; }}
        .risk-low {{ color: #fbc02d; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #4CAF50; color: white; }}
        tr:hover {{ background-color: #f5f5f5; }}
        .chart-container {{ width: 400px; margin: 20px auto; }}
        .summary {{ background: #e8f5e9; padding: 15px; border-radius: 5px; margin: 20px 0; }}
        .badge {{ display: inline-block; padding: 3px 8px; border-radius: 3px; font-size: 12px; }}
        .badge-200 {{ background: #4CAF50; color: white; }}
        .badge-301 {{ background: #FF9800; color: white; }}
        .badge-302 {{ background: #FF9800; color: white; }}
        .badge-403 {{ background: #d32f2f; color: white; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Web路径扫描报告</h1>
        <div class="summary">
            <p><strong>扫描时间:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
            <p><strong>总结果数:</strong> {sum(status_counts.values())}</p>
            <p><strong>高风险路径:</strong> {len(sensitive_high)}</p>
            <p><strong>中风险路径:</strong> {len(sensitive_mid)}</p>
            <p><strong>低风险路径:</strong> {len(sensitive_low)}</p>
        </div>

        <h2>状态码分布</h2>
        <div class="chart-container">
            <canvas id="statusChart"></canvas>
        </div>

        <h2>高风险路径 (admin/sql/phpmyadmin)</h2>
        {self._generate_results_table(sensitive_high, 'risk-high')}

        <h2>中风险路径 (api/docs)</h2>
        {self._generate_results_table(sensitive_mid, 'risk-mid')}

        <h2>低风险路径 (test/dev)</h2>
        {self._generate_results_table(sensitive_low, 'risk-low')}
    </div>
    <script>
        new Chart(document.getElementById('statusChart'), {{
            type: 'pie',
            data: {{
                labels: [{status_labels}],
                datasets: [{{
                    data: [{status_values}],
                    backgroundColor: ['#4CAF50', '#FF9800', '#FFC107', '#d32f2f', '#9C27B0', '#2196F3']
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{
                    legend: {{ position: 'bottom' }}
                }}
            }}
        }});
    </script>
</body>
</html>"""
        return html

    @staticmethod
    def _html_escape(value) -> str:
        """报告里的 URL 与 title 来自目标站点，必须转义，否则会往报告里注入 HTML。"""
        return (str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace('"', "&quot;").replace("'", "&#39;"))

    def _generate_results_table(self, results: List, risk_class: str) -> str:
        if not results:
            return "<p>无</p>"
        rows = ""
        for r in results[:50]:
            badge_class = f"badge-{r['status_code']}"
            url = self._html_escape(r["url"])
            rows += f"""<tr>
                <td><span class="badge {badge_class}">{r['status_code']}</span></td>
                <td>{self._html_escape(r.get('method', 'GET'))}</td>
                <td><a href="{url}">{url}</a></td>
                <td>{self._html_escape(r.get('title', ''))}</td>
                <td>{self._html_escape(r.get('content_size', ''))}</td>
                <td>{self._html_escape(r.get('secrets', ''))}</td>
            </tr>"""
        return f"""<table>
            <thead>
                <tr>
                    <th>状态码</th>
                    <th>方法</th>
                    <th>URL</th>
                    <th>标题</th>
                    <th>大小</th>
                    <th>敏感信息</th>
                </tr>
            </thead>
            <tbody>{rows}</tbody>
        </table>"""

    def _save_resume_point(self):
        resume_data = {
            "url": self.args.url,
            "wordlist": self.args.wordlist,
            "scanned_count": self.scanned_count,
            "total_paths": self.args.total_paths,
            "threads": self.args.threads,
            "delay": self.args.delay,
            "retry": self.args.retry,
            "mode": self.args.mode,
            "method": getattr(self.args, 'method', 'GET'),
            "crawl_depth": self.args.crawl_depth,
            "scanned_keys": sorted(self.scanned_keys),
            "results": self.results,
            "timestamp": datetime.now().isoformat()
        }

        try:
            with open(".scan_resume.json", "w", encoding="utf-8") as f:
                json.dump(resume_data, f, indent=2)
        except Exception:
            pass

    def _load_resume_point(self):
        try:
            with open(".scan_resume.json", "r", encoding="utf-8") as f:
                data = json.load(f)

            print(f"\n\033[93m[*] 加载断点续扫: {data['timestamp']}\033[0m")
            print(f"[*] 已扫描: {data['scanned_count']}/{data['total_paths']}\n")

            self.scanned_count = data.get("scanned_count", 0)
            self.scanned_keys = set(data.get("scanned_keys", []))
            self.results = data.get("results", [])

            self.scanned_urls = set()
            for key in self.scanned_keys:
                parts = key.split("|")
                if len(parts) >= 2:
                    self.scanned_urls.add(parts[1])

            self._processed_200 = {
                r.get("url") for r in self.results
                if r.get("status_code") == 200 and r.get("url")
            }
            self.found_count = len(self.results)
            self.sensitive_count = sum(1 for r in self.results if r.get("is_sensitive") == 1)

            print(f"[*] 恢复已完成任务 {len(self.scanned_keys)} 条，已有结果 {len(self.results)} 条\n")

        except Exception as e:
            print(f"\033[91m[!] 加载断点失败: {e}\033[0m\n")

    def _schedule_scan(self, paths: List[str]):
        if self.args.schedule_time:
            target_time = datetime.strptime(self.args.schedule_time, "%Y-%m-%d %H:%M:%S")
            now = datetime.now()

            if target_time > now:
                delta = (target_time - now).total_seconds()
                print(f"\n\033[94m[*] 定时扫描将在 {target_time} 开始\033[0m")
                print(f"[*] 距离开始还有 {delta:.0f} 秒")

                while delta > 0:
                    if GLOBAL_STATE.should_exit:
                        return
                    hours = int(delta) // 3600
                    minutes = (int(delta) % 3600) // 60
                    seconds = int(delta) % 60
                    print(f"\r[*] 倒计时: {hours:02d}:{minutes:02d}:{seconds:02d} ", end="", flush=True)
                    time.sleep(1)
                    delta -= 1

                print("\n\033[92m[*] 开始扫描...\033[0m\n")
                self._run_iterative_scan(paths)
            else:
                print("\033[93m[!] 指定时间已过，立即开始扫描\033[0m\n")
                self._run_iterative_scan(paths)

        elif self.args.schedule_interval:
            interval_hours = float(self.args.schedule_interval)
            interval_seconds = interval_hours * 3600

            print(f"\n\033[94m[*] 间隔扫描模式，每 {interval_hours} 小时执行一次\033[0m")

            run_count = 0
            while not GLOBAL_STATE.should_exit:
                run_count += 1
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                self.args.output = f"scan_result_{timestamp}.csv"

                print(f"\n\033[92m[*] 第 {run_count} 次扫描开始: {datetime.now()}\033[0m")
                self.start_time = time.time()
                # t=1 时打一条时间估算，避免用户 144k 任务跑 33 小时才发现
                try:
                    rate = max(1, int(getattr(self.args, "max_rate", 20) or 20))
                    eta = (len(paths) if isinstance(paths, list) else 0) // max(1, int(getattr(self.args, "threads", 1) or 1)) / max(1.0, float(rate))
                    if int(getattr(self.args, "threads", 1) or 1) <= 1 and eta > 1800:
                        print(f"\033[93m[!] 检测到 -t 1 + 任务量 {len(paths)} 条，按 max-rate={rate}/s 估算约 {eta/3600:.1f} 小时\n    建议: -t 20 或 --max-rate 50\033[0m\n")
                except Exception:
                    pass
                self._run_iterative_scan(paths)

                if not GLOBAL_STATE.should_exit:
                    print(f"\n\033[94m[*] 等待 {interval_hours} 小时后继续...\033[0m")
                    for i in range(int(interval_seconds)):
                        if GLOBAL_STATE.should_exit:
                            break
                        remaining = int(interval_seconds) - i
                        hours = remaining // 3600
                        minutes = (remaining % 3600) // 60
                        seconds = remaining % 60
                        print(f"\r[*] 下次扫描倒计时: {hours:02d}:{minutes:02d}:{seconds:02d} ", end="", flush=True)
                        time.sleep(1)

            self._save_results()


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=f"{PROGRAM_NAME} v{VERSION} - Web路径扫描工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  %(prog)s -u http://example.com                        # 混合扫描(默认)
  %(prog)s -u http://example.com --mode wordlist        # 仅字典扫描
  %(prog)s -u http://example.com --mode crawl            # 仅爬虫扫描
  %(prog)s -u http://example.com -t 10                   # 多线程扫描
  %(prog)s -u http://example.com -w dict                # 指定字典文件夹
  %(prog)s -u http://example.com --schedule-time "2024-01-01 10:00:00"
  %(prog)s -u http://example.com --resume
        """
    )

    parser.add_argument("-u", "--url", required=True, help="目标站点URL")
    parser.add_argument("-w", "--wordlist", default="dict", help="字典文件路径或文件夹路径 (默认: dict)")
    parser.add_argument("-t", "--threads", type=int, default=1, help="扫描线程数 (默认: 1)")
    parser.add_argument("-o", "--output", default="scan_result.csv", help="结果输出文件路径 (默认: scan_result.csv)")

    parser.add_argument("--delay", type=float, default=0.1, help="请求间隔延时，单位秒 (默认: 0.1)")
    parser.add_argument("--retry", type=int, default=2, help="请求失败重试次数 (默认: 2)")
    parser.add_argument("--timeout", type=int, default=10, help="请求超时时间，单位秒 (默认: 10)")

    parser.add_argument("-m", "--method", default="GET",
                        help=f"HTTP 请求方法 (默认: GET)，支持 {','.join(SUPPORTED_METHODS)}")
    parser.add_argument("--data", help="请求体，配合 POST/PUT 使用，如 'a=1&b=2' 或 JSON 字符串")
    parser.add_argument("--content-type", dest="content_type",
                        help="请求体 Content-Type，如 application/json")
    parser.add_argument("--headers", help="自定义请求头，格式: Cookie:xxx;Referer:xxx")
    parser.add_argument("--proxy", help="HTTP/HTTPS代理")

    parser.add_argument("--include-status", help="保留的状态码，逗号分隔，如: 200,302,403")
    parser.add_argument("--exclude-status", help="排除的状态码，逗号分隔，如: 404,500,502")

    parser.add_argument("--mode", choices=["wordlist", "crawl", "mixed"], default="mixed", 
                        help="扫描模式: wordlist仅字典, crawl仅爬虫, mixed混合扫描(默认)")
    parser.add_argument("--crawl-depth", type=int, default=5, help="爬虫最大深度 (默认: 5)")
    parser.add_argument("--crawl-threads", type=int, default=5, help="爬虫并发线程数 (默认: 5)")

    parser.add_argument("--sensitive-words", help=f"敏感关键词，逗号分隔 (内置: {','.join(DEFAULT_SENSITIVE_WORDS[:5])}...)")
    parser.add_argument("--priority-scan", action="store_true", help="启用优先级扫描")

    parser.add_argument("--schedule-time", help="定时扫描启动时间，格式: YYYY-MM-DD HH:MM:SS")
    parser.add_argument("--schedule-interval", help="间隔扫描间隔时间，单位小时")
    parser.add_argument("--resume", action="store_true", help="从断点继续扫描")

    parser.add_argument("--dedup-mode", choices=["off", "content", "redirect", "template", "strict"], default="template",
                        help="去重模式: template 按页面骨架(默认) / strict 敏感项不折叠 / redirect 旧行为 / off 不去重")
    parser.add_argument("--dir-slash", action="store_true",
                        help="为目录型字典条目额外生成带尾斜杠的变体（会增大扫描量）")
    parser.add_argument("--save-evidence", dest="save_evidence", action="store_true", default=True,
                        help="保存 HTTP 原始请求与响应证据 (默认: 开启)")
    parser.add_argument("--no-evidence", dest="save_evidence", action="store_false",
                        help="关闭证据落盘")
    parser.add_argument("--evidence-dir", default="evidence", help="证据输出目录 (默认: evidence)")
    parser.add_argument("--no-scan-forms", dest="scan_forms", action="store_true",
                        help="不从 HTML 表单生成探测任务")
    parser.add_argument("--max-combine", type=int, default=20000,
                        help="路径片段拼接生成数量的上限 (默认: 20000)")
    parser.add_argument("--deduplicate", "-d", action="store_true", default=True, help="启用去重功能 (默认: 开启)")
    parser.add_argument("--no-deduplicate", action="store_false", dest="deduplicate", help="关闭去重功能")
    parser.add_argument("--valid-keywords", help="200响应需包含的关键词，逗号分隔")
    parser.add_argument("--invalid-keywords", help="200响应包含则过滤的关键词，逗号分隔")
    parser.add_argument("--random-delay", action="store_true", default=True, help="启用随机延时 (默认: 开启)")
    parser.add_argument("--no-random-delay", action="store_false", dest="random_delay", help="关闭随机延时")
    parser.add_argument("--soft-404-detect", action="store_true", default=True, help="启用软404检测 (默认: 开启)")
    parser.add_argument("--max-rate", type=int, default=0, help="最大请求速率限制 (每秒请求数，0表示不限制)")
    parser.add_argument("--max-iterations", type=int, default=10, help="最大迭代扫描次数 (默认: 10)")
    parser.add_argument("--dup-size-threshold", type=int, default=3, help="同一大小页面出现多少次判定为重复 (默认: 3)")
    parser.add_argument("--dedup-keep", type=int, default=1, help="每个聚类保留的代表条数 (默认: 1)")
    parser.add_argument("--dedup-generic", type=int, default=5, help="同模板出现多少次起标通用页提示 (默认: 5)")
    parser.add_argument("--cluster-dir", default="clusters", help="聚类折叠后的完整 URL 清单输出目录 (默认: clusters)")
    parser.add_argument("--status-url-cap", type=int, default=4000, help="每个状态码保留的 URL 上限 (默认: 4000)")
    parser.add_argument("--phase2", action="store_true", help="启用所有 Phase 2 探测")
    parser.add_argument("--bypass-403", action="store_true", help="403 绕过探测")
    parser.add_argument("--recursive", action="store_true", help="对已发现目录做递归枚举")
    parser.add_argument("--backup-fuzz", action="store_true", help="对 200 路径追加备份/源码后缀")
    parser.add_argument("--sensitive-files", action="store_true", help="在根 + 已发现目录下探测内置敏感文件清单")
    parser.add_argument("--sourcemap", action="store_true", help="从 JS 提取 sourceMappingURL 并尝试还原源码路径")
    parser.add_argument("--phase2-rounds", type=int, default=1, help="Phase 2 轮数 (默认: 1)")
    parser.add_argument("--bypass-max", type=int, default=60, help="403 绕过探测的最大源 URL 数 (默认: 60)")
    parser.add_argument("--recursive-max-dirs", type=int, default=20, help="递归枚举的最大目录数 (默认: 20)")
    parser.add_argument("--backup-max", type=int, default=200, help="备份 fuzz 的最大源 URL 数 (默认: 200)")


    parser.add_argument("--format", "-f", choices=["csv", "json", "html"], default="csv", help="输出格式 (默认: csv)")
    parser.add_argument("--cookie-pool", help="Cookie池文件路径")
    parser.add_argument("--proxy-pool", help="代理池文件路径")
    parser.add_argument("--audit-log", default="scan_audit.log", help="审计日志文件路径 (默认: scan_audit.log)")

    parser.add_argument("--debug", action="store_true", help="启用调试模式")
    parser.add_argument("--async", dest="async_mode", action="store_true", help="启用异步模式 (高性能低CPU)")

    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s {VERSION}")

    return parser


def main():
    parser = create_parser()
    args = parser.parse_args()

    if not os.path.exists(args.wordlist) and not os.path.isdir(args.wordlist):
        print(f"\033[93m[!] 字典路径不存在: {args.wordlist}\033[0m")
        print("[*] 将使用空字典开始扫描（仅爬虫模式）")

    scanner = Scanner(args)

    try:
        scanner.run()
    except KeyboardInterrupt:
        print("\n\033[91m[!] 用户中断\033[0m")
        scanner._save_results()
        sys.exit(0)
    except Exception as e:
        if args.debug:
            import traceback
            traceback.print_exc()
        else:
            print(f"\033[91m[!] 错误: {e}\033[0m")
        sys.exit(1)


if __name__ == "__main__":
    main()
