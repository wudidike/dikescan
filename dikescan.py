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
from typing import Set, List, Dict, Optional, Tuple
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from html.parser import HTMLParser

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

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]):
        self.tag_stack.append(tag)
        attrs_dict = dict(attrs)

        if tag in ("a", "link", "area"):
            href = attrs_dict.get("href")
            if href:
                self._process_link(href)
        elif tag in ("img", "script", "iframe", "source", "video", "audio", "embed"):
            src = attrs_dict.get("src")
            if src:
                self._process_link(src)
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
        elif tag == "img":
            srcset = attrs_dict.get("srcset")
            if srcset:
                for src in srcset.split(","):
                    self._process_link(src.strip().split()[0])

    def handle_endtag(self, tag: str):
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
            full_url = link if link.startswith(("http://", "https://")) else f"{urllib.parse.urlparse(self.base_url).scheme}://{parsed.netloc}{path}"
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
    @staticmethod
    def normalize_path(path: str) -> str:
        path = path.replace('//', '/')
        path = path.split('#')[0]
        path = path.split('?')[0]
        path = path.strip()
        if not path.endswith('/') and '.' in path.split('/')[-1]:
            pass
        else:
            if not path.endswith('/'):
                path += '/'
        return path

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
        normalized = set()
        for path in paths:
            norm = PathCombiner.normalize_path(path)
            parts = norm.strip('/').split('/')
            if len(parts) != len(set(parts)):
                continue
            normalized.add(norm)
        return normalized


class FingerprintCache:
    def __init__(self):
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

    def check_and_add(self, status: int, content: bytes, url: str, is_sensitive: bool = False) -> Tuple[bool, bool]:
        if status not in (200,):
            return True, False
        key = self._make_key(status, content)
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


class Soft404Detector:
    def __init__(self, scanner: 'Scanner', size_threshold: int = 3):
        self.scanner = scanner
        self.invalid_features: List[Dict] = []
        self.fake_404_pattern: Optional[str] = None
        self.min_sample_count = 5
        self.is_soft_404_site = False
        self.suspicious_sizes: Set[int] = set()
        self.size_count: Dict[int, int] = defaultdict(int)
        self.size_threshold = size_threshold
        self.content_similarity_threshold = 0.85
        self.homepage_hash = ""
        self.homepage_size = 0

    def _compute_hash(self, content: bytes) -> str:
        if len(content) > 1024 * 1024:
            data = content[:1024] + content[-1024:]
        else:
            data = content
        return hashlib.md5(data).hexdigest()

    def _compute_content_similarity(self, content1: bytes, content2: bytes) -> float:
        if len(content1) == 0 or len(content2) == 0:
            return 0.0
        if content1 == content2:
            return 1.0
        
        import re
        
        def normalize_html(html: str) -> str:
            html_lower = html.lower()
            html_lower = re.sub(r'<script[^>]*>.*?</script>', '', html_lower, flags=re.DOTALL)
            html_lower = re.sub(r'<style[^>]*>.*?</style>', '', html_lower, flags=re.DOTALL)
            html_lower = re.sub(r'<[^>]+>', '', html_lower)
            html_lower = re.sub(r'[\d]{10,}', 'TS', html_lower)
            html_lower = re.sub(r'[\da-f]{6,}', 'H', html_lower)
            html_lower = re.sub(r'sessionid=[^&\s"\']+', '', html_lower)
            html_lower = re.sub(r'csrf_token=[^&\s"\']+', '', html_lower)
            html_lower = re.sub(r'[\s]+', ' ', html_lower)
            return html_lower.strip()
        
        text1 = content1.decode('utf-8', errors='ignore')
        text2 = content2.decode('utf-8', errors='ignore')
        
        norm1 = normalize_html(text1)
        norm2 = normalize_html(text2)
        
        if norm1 == norm2:
            return 1.0
        
        norm1_clean = re.sub(r'[\d]+', 'N', norm1)
        norm2_clean = re.sub(r'[\d]+', 'N', norm2)
        
        if norm1_clean == norm2_clean:
            return 0.95
        
        len1, len2 = len(norm1), len(norm2)
        if len1 == 0 or len2 == 0:
            return 0.0
        
        max_len = max(len1, len2)
        min_len = min(len1, len2)
        
        common_prefix = 0
        for i in range(min_len):
            if norm1[i] == norm2[i]:
                common_prefix += 1
            else:
                break
        
        common_suffix = 0
        for i in range(1, min_len + 1):
            if norm1[-i] == norm2[-i]:
                common_suffix += 1
            else:
                break
        
        similarity = (common_prefix + common_suffix) / (2 * max_len)
        return similarity

    def detect(self) -> bool:
        print(f"\n[*] 正在检测软404 (采样 {self.min_sample_count} 个无效页面)...")
        
        test_paths = [
            f"/notexist-{uuid.uuid4().hex[:8]}/",
            f"/null-{uuid.uuid4().hex[:8]}/",
            f"/undefined-{uuid.uuid4().hex[:8]}/",
            f"/test-{uuid.uuid4().hex[:8]}/",
            f"/404-{uuid.uuid4().hex[:8]}-test/",
        ]
        
        for i in range(self.min_sample_count):
            random_str = f"notexist-{uuid.uuid4().hex[:8]}-{i}"
            test_paths.append(f"/{random_str}/")

        try:
            resp = self.scanner.session.get(
                urllib.parse.urljoin(self.scanner.args.url, "/"),
                timeout=self.scanner.args.timeout,
                verify=False
            )
            self.homepage_size = len(resp.content) if resp.status_code == 200 else 0
            self.homepage_hash = self._compute_hash(resp.content) if resp.status_code == 200 else ""
            print(f"[*] 主页响应: {resp.status_code}, 大小: {self.homepage_size}B")
        except Exception:
            self.homepage_size = 0
            self.homepage_hash = ""

        for test_path in test_paths:
            try:
                resp = self.scanner.session.get(
                    urllib.parse.urljoin(self.scanner.args.url, test_path),
                    timeout=self.scanner.args.timeout,
                    verify=False
                )
                if resp.status_code == 200:
                    content = resp.content
                    content_size = len(content)
                    content_hash = self._compute_hash(content)
                    title = self._extract_title(resp.text)

                    if content_hash == self.homepage_hash:
                        continue

                    feature = {
                        "size": content_size,
                        "hash": content_hash,
                        "title": title,
                        "pattern": test_path,
                        "content": content
                    }
                    self.invalid_features.append(feature)
                    print(f"[*] 采样到无效页面: {test_path} - 大小:{content_size}B hash:{content_hash[:8]}...")
            except Exception:
                pass

        if len(self.invalid_features) > 0:
            self.fake_404_pattern = self.invalid_features[0]["pattern"]
            sizes = [f["size"] for f in self.invalid_features]
            print(f"[*] 软404检测完成，采集到 {len(self.invalid_features)} 个无效页面特征")
            print(f"[*] 无效页面大小: {set(sizes)}")
            self.is_soft_404_site = True
            return True
        
        print(f"[!] 软404检测失败，所有测试路径都返回非200状态或与主页相同")
        print(f"[*] 将使用默认过滤规则：相同大小的200页面将被视为潜在重复内容")
        self.is_soft_404_site = False
        return False

    def record_size(self, content_size: int):
        self.size_count[content_size] += 1
        if self.size_count[content_size] >= self.size_threshold:
            self.suspicious_sizes.add(content_size)

    def _extract_title(self, html: str) -> str:
        try:
            match = re.search(r"<title[^>]*>([^<]+)</title>", html, re.IGNORECASE)
            if match:
                return match.group(1).strip().lower()
        except Exception:
            pass
        return ""

    def is_soft_404(self, content: bytes, url: str) -> bool:
        if not self.invalid_features:
            return False

        if self.fake_404_pattern and self.fake_404_pattern in url:
            return True

        content_hash = self._compute_hash(content)
        content_size = len(content)

        for feature in self.invalid_features:
            if feature["hash"] == content_hash:
                return True
            if abs(feature["size"] - content_size) <= 20:
                return True

        return False

    def is_invalid_content(self, content: bytes, url: str, title: str = "") -> Tuple[bool, str]:
        content_hash = self._compute_hash(content)
        content_size = len(content)

        if self.invalid_features:
            for feature in self.invalid_features:
                if feature["hash"] == content_hash:
                    return True, f"hash_match({feature['size']}B)"

                size_diff = abs(feature["size"] - content_size)
                if size_diff <= 50:
                    sample_content = feature.get("content", b"")
                    if sample_content and content_size > 0:
                        similarity = self._compute_content_similarity(content, sample_content)
                        if similarity >= self.content_similarity_threshold:
                            return True, f"content_similar({content_size}B≈{feature['size']}B, sim:{similarity:.2f})"
                    if size_diff <= 20:
                        return True, f"size_near({content_size}B≈{feature['size']}B)"

                if feature["size"] < 1024 and size_diff <= 100:
                    return True, f"small_size_near({content_size}B)"

        if content_size in self.suspicious_sizes:
            return True, f"size_repeated({content_size}B)"

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

    async def crawl_single_url(self, current_url: str, depth: int) -> Tuple[Set[str], Set[str], List[Tuple[str, int]]]:
        local_crawled: Set[str] = set()
        local_css_js_paths: Set[str] = set()
        local_new_links: List[Tuple[str, int]] = []

        if not self.session:
            return local_crawled, local_css_js_paths, local_new_links

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

        return local_crawled, local_css_js_paths, local_new_links

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

            local_crawled, local_css_js_paths, local_new_links = await self.crawl_single_url(current_url, depth)

            async with self._lock:
                self.crawled.update(local_crawled)
                self.css_js_paths.update(local_css_js_paths)

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
        self.max_concurrency = getattr(args, 'threads', 1) * 10
        self.timeout = getattr(args, 'timeout', 10)
        self.delay = getattr(args, 'delay', 0.1)
        self.debug = getattr(args, 'debug', False)

        self.session: Optional[aiohttp.ClientSession] = None
        self.semaphore: Optional[asyncio.Semaphore] = None
        self._async_lock = asyncio.Lock()

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
        self.semaphore = asyncio.Semaphore(self.max_concurrency)

    async def close_session(self):
        if self.session:
            await self.session.close()

    async def scan_single_path(self, path: str) -> Optional[Dict]:
        async with self.semaphore:
            if GLOBAL_STATE.should_exit:
                return None

            while GLOBAL_STATE.paused:
                await asyncio.sleep(0.1)

            await asyncio.sleep(random.uniform(self.delay * 0.5, self.delay * 1.5))

            url = path if path.startswith(("http://", "https://")) else urllib.parse.urljoin(self.args.url, path)

            try:
                async with self.session.get(url, allow_redirects=True) as resp:
                    status = resp.status
                    final_url = str(resp.url)

                    if status == 200:
                        content = await resp.read()
                        title = self.scanner._extract_title(content.decode('utf-8', errors='ignore'))
                        content_size = len(content)

                        self.scanner.soft_404_detector.record_size(content_size)
                        is_invalid, invalid_reason = self.scanner.soft_404_detector.is_invalid_content(content, final_url, title)
                        if is_invalid:
                            return None

                        is_sensitive = self.scanner.is_sensitive_path(final_url)
                        deduplicate = getattr(self.args, 'deduplicate', True)
                        is_sensitive_duplicate = False
                        if deduplicate:
                            is_new, is_sensitive_duplicate = self.scanner.fingerprint_cache.check_and_add(status, content, final_url, is_sensitive)
                            if not is_new:
                                return None

                        if content_size < 1024:
                            size_str = f"{content_size}B"
                        elif content_size < 1024 * 1024:
                            size_str = f"{content_size/1024:.1f}KB"
                        else:
                            size_str = f"{content_size/1024/1024:.1f}MB"

                        result = {
                            "url": final_url,
                            "status_code": status,
                            "status_desc": self.scanner._get_status_desc(status),
                            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "title": title,
                            "is_sensitive": 1 if is_sensitive else 0,
                            "is_sensitive_duplicate": 1 if is_sensitive_duplicate else 0,
                            "content_size": size_str
                        }
                        return result
                    elif status in (301, 302, 403):
                        result = {
                            "url": final_url,
                            "status_code": status,
                            "status_desc": self.scanner._get_status_desc(status),
                            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "title": "",
                            "is_sensitive": 1 if self.scanner.is_sensitive_path(final_url) else 0,
                            "is_sensitive_duplicate": 0,
                            "content_size": ""
                        }
                        return result

            except asyncio.CancelledError:
                raise
            except Exception:
                pass

            return None

    async def worker(self, paths: List[str], results_queue: Optional[asyncio.Queue] = None, progress_callback=None):
        for path in paths:
            if GLOBAL_STATE.should_exit:
                break

            async with self._async_lock:
                self.scanner.scanned_count += 1
                self.scanner.scanned_urls.add(path)
                count = self.scanner.scanned_count

            result = await self.scan_single_path(path)

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

    async def run_async(self, paths: List[str]):
        await self.init_session()
        print(f"\n\033[94m[*] 启动异步扫描模式，并发: {self.max_concurrency}\033[0m")

        self.scanner.start_time = time.time()
        self.scanner.args.total_paths = len(paths)

        total = len(paths)
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
        for i in range(0, len(paths), batch_size):
            if GLOBAL_STATE.should_exit:
                break

            batch = paths[i:i + batch_size]
            workers = [asyncio.create_task(self.worker(batch, None, progress_callback)) for _ in range(min(self.max_concurrency, len(batch)))]
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

        self.fingerprint_cache = FingerprintCache()
        dup_threshold = getattr(args, 'dup_size_threshold', 3)
        self.soft_404_detector = Soft404Detector(self, dup_threshold)
        self.adaptive_thread_controller = AdaptiveThreadController(
            args.threads, args.threads
        )
        self.ban_recovery_manager = BanRecoveryManager()
        self.proxy_pool: Optional[ProxyPool] = None
        self.failed_paths: List[str] = []
        self.failed_lock = threading.Lock()

        self.all_discovered_paths: Set[str] = set()
        self.scanned_urls: Set[str] = set()
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

        def crawl_single_url(current_url: str, depth: int) -> Tuple[Set[str], Set[str], List[Tuple[str, int]]]:
            nonlocal is_spa_detected
            local_crawled: Set[str] = set()
            local_css_js_paths: Set[str] = set()
            local_new_links: List[Tuple[str, int]] = []

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

            return local_crawled, local_css_js_paths, local_new_links

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

                    local_crawled, local_css_js_paths, local_new_links = future.result()

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

    def scan_path(self, path: str) -> Optional[Dict]:
        if self.ban_recovery_manager.should_wait():
            time.sleep(self.ban_recovery_manager.get_wait_time())
            self.session.headers.update({"User-Agent": random.choice(DEFAULT_USER_AGENTS)})

        if self.proxy_pool:
            proxy = self.proxy_pool.get_next_proxy()
            if proxy:
                self.session.proxies = proxy

        for attempt in range(self.args.retry + 1):
            try:
                url = path if path.startswith(("http://", "https://")) else urllib.parse.urljoin(self.args.url, path)

                self._enhance_request_headers()

                resp = self.session.get(
                    url,
                    timeout=self.args.timeout,
                    allow_redirects=True,
                    verify=False
                )

                final_url = resp.url
                status = resp.status_code

                retry_after = resp.headers.get('Retry-After')
                self.ban_recovery_manager.record_response(status, retry_after)

                if 'Set-Cookie' in resp.headers:
                    self._update_cookies(resp.headers.get('Set-Cookie', ''))

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
                else:
                    if status in exclude_codes:
                        return None

                if status == 200:
                    title = self._extract_title(resp.text)
                    content_size = len(resp.content)
                    
                    self.soft_404_detector.record_size(content_size)
                    is_invalid, invalid_reason = self.soft_404_detector.is_invalid_content(resp.content, final_url, title)
                    if is_invalid:
                        if self.args.debug:
                            print(f"[D] 过滤无效页面: {final_url} ({invalid_reason})")
                        return None

                    valid_keywords = getattr(self.args, 'valid_keywords', None)
                    if valid_keywords:
                        keyword_list = [kw.strip().lower() for kw in valid_keywords.split(',') if kw.strip()]
                        content_lower = resp.text.lower()
                        if not any(kw in content_lower for kw in keyword_list):
                            return None

                    invalid_keywords = getattr(self.args, 'invalid_keywords', None)
                    if invalid_keywords:
                        keyword_list = [kw.strip().lower() for kw in invalid_keywords.split(',') if kw.strip()]
                        content_lower = resp.text.lower()
                        if any(kw in content_lower for kw in keyword_list):
                            return None

                    is_sensitive = self.is_sensitive_path(final_url)
                    deduplicate = getattr(self.args, 'deduplicate', True)
                    is_sensitive_duplicate = False
                    if deduplicate:
                        is_new, is_sensitive_duplicate = self.fingerprint_cache.check_and_add(status, resp.content, final_url, is_sensitive)
                        if not is_new:
                            self.soft_404_detector.record_size(content_size)
                            return None

                    title = self._extract_title(resp.text)

                    content_size = len(resp.content)
                    if content_size < 1024:
                        size_str = f"{content_size}B"
                    elif content_size < 1024 * 1024:
                        size_str = f"{content_size/1024:.1f}KB"
                    else:
                        size_str = f"{content_size/1024/1024:.1f}MB"

                    result = {
                        "url": final_url,
                        "status_code": status,
                        "status_desc": self._get_status_desc(status),
                        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "title": title,
                        "is_sensitive": 1 if is_sensitive else 0,
                        "is_sensitive_duplicate": 1 if is_sensitive_duplicate else 0,
                        "content_size": size_str
                    }
                    return result

            except requests.exceptions.Timeout:
                self.adaptive_thread_controller.record_timeout()
                if attempt < self.args.retry:
                    self.session.headers.update({"User-Agent": random.choice(DEFAULT_USER_AGENTS)})
                    time.sleep(0.5)
                    continue
                with self.failed_lock:
                    self.failed_paths.append(path)
                return None
            except Exception as e:
                if attempt < self.args.retry:
                    self.session.headers.update({"User-Agent": random.choice(DEFAULT_USER_AGENTS)})
                    time.sleep(0.5)
                    continue
                if self.args.debug:
                    print(f"请求错误 {path}: {e}")
                with self.failed_lock:
                    self.failed_paths.append(path)
                return None

        return None

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

    def worker(self, path: str, progress_callback=None):
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
            if random_delay:
                delay = random.uniform(0.1, 0.5)
            else:
                delay = self.args.delay
            time.sleep(delay)

        result = self.scan_path(path)

        with self.scanned_lock:
            self.scanned_count += 1

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

        sensitive_prefix = "\033[91m[敏感]\033[0m " if result["is_sensitive"] == 1 else ""
        size_str = result.get("content_size", "")
        print(f"{sensitive_prefix}{color}{result['url']} [{status}] {result['status_desc']} {size_str}{COLOR_RESET}")

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
            "threads": self.args.threads,
            "wordlist": self.args.wordlist
        })

        if self.args.resume:
            self._load_resume_point()
            return

        if hasattr(self.args, 'soft_404_detect') and self.args.soft_404_detect:
            print(f"\n[*] 正在检测软404...")
            try:
                if self.soft_404_detector.detect():
                    print(f"[*] 软404检测完成")
                else:
                    print(f"[!] 软404检测失败，将跳过软404过滤")
            except Exception as e:
                print(f"[!] 软404检测异常，将跳过: {e}")

        wordlist_paths: Set[str] = set()
        crawler_paths: Optional[Set[str]] = None
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
                print(f"字典路径数: {len(wordlist_paths)}")
            else:
                print(f"\033[93m[!] 字典路径不存在: {self.args.wordlist}\033[0m")

        if self.args.mode in ("crawl", "mixed"):
            if use_async:
                async_crawler = AsyncCrawler(self.args, self)
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                crawler_paths = loop.run_until_complete(async_crawler.run_async())
                crawler_paths = PathCombiner.deduplicate_paths(crawler_paths)
                print(f"爬虫路径数: {len(crawler_paths)}")
            else:
                crawler_paths = self.crawl(normalized_url, self.args.crawl_depth)
                crawler_paths = PathCombiner.deduplicate_paths(crawler_paths)
                print(f"爬虫路径数: {len(crawler_paths)}")

        all_paths = self.build_scan_queue(wordlist_paths, crawler_paths)

        normalized_all_paths = []
        seen = set()
        for path in all_paths:
            norm = PathCombiner.normalize_path(path)
            if norm not in seen:
                seen.add(norm)
                normalized_all_paths.append(path)

        all_paths = normalized_all_paths

        self.args.total_paths = len(all_paths)
        print(f"总扫描路径数: {len(all_paths)}")

        if self.args.schedule_time or self.args.schedule_interval:
            self._schedule_scan(all_paths)
            return

        deduplicate = getattr(self.args, 'deduplicate', True)
        if use_async:
            print(f"请求延时: {self.args.delay}秒")
            print(f"去重功能: {'开启' if deduplicate else '关闭'}\n")

            async_scanner = AsyncScanner(self.args, self)
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(async_scanner.run_async(all_paths))
            self._finish_scan()
        else:
            print(f"线程数: {self.args.threads}")
            print(f"请求延时: {self.args.delay}秒")
            print(f"重试次数: {self.args.retry}")
            random_delay = getattr(self.args, 'random_delay', True)
            print(f"随机延时: {'开启' if random_delay else '关闭'}")
            print(f"去重功能: {'开启' if deduplicate else '关闭'}\n")

            self._run_iterative_scan(all_paths)

    def _run_scan(self, paths: List[str]):
        progress_lock = threading.Lock()
        last_update = [time.time()]
        update_interval = 0.5
        current_threads = self.args.threads

        def progress_callback(count):
            with progress_lock:
                now = time.time()
                if now - last_update[0] >= update_interval:
                    last_update[0] = now
                    total = self.args.total_paths
                    percent = (count / total * 100) if total > 0 else 0
                    speed = count / (now - self.start_time) if self.start_time else 0
                    remaining = (total - count) / speed if speed > 0 else 0

                    bar_length = 30
                    filled = int(bar_length * count / total) if total > 0 else 0
                    bar = "=" * filled + "-" * (bar_length - filled)

                    sys.stdout.write(f"\r[{bar}] {percent:.1f}% {count}/{total} 速度:{speed:.1f}/s 剩余:{remaining:.0f}s 敏感:{self.sensitive_count} 线程:{current_threads} ")
                    sys.stdout.flush()

        while True:
            current_threads = self.adaptive_thread_controller.get_threads()

            with ThreadPoolExecutor(max_workers=current_threads) as executor:
                futures = {executor.submit(self.worker, path, progress_callback): path for path in paths}

                for future in as_completed(futures):
                    if GLOBAL_STATE.should_exit:
                        for f in futures:
                            f.cancel()
                        break

            if not self.failed_paths:
                break

            print(f"\n\033[94m[*] 重试失败路径: {len(self.failed_paths)}\033[0m")
            paths = self.failed_paths[:]
            self.failed_paths = []

        self._finish_scan()

    def _run_iterative_scan(self, initial_paths: List[str]):
        iteration = 0
        max_iterations = getattr(self.args, 'max_iterations', 10)
        self.all_discovered_paths.update(initial_paths)
        new_paths_this_iteration = len(initial_paths) > 0

        print(f"\n\033[94m[*] 启动迭代扫描模式，最大迭代次数: {max_iterations}\033[0m\n")

        while new_paths_this_iteration and iteration < max_iterations:
            iteration += 1
            print(f"\033[94m[*] ========== 迭代 {iteration} ==========\033[0m")

            current_paths = list(self.all_discovered_paths - self.scanned_urls)
            if not current_paths:
                print(f"\033[94m[*] 没有新路径可扫描，停止迭代\033[0m")
                break

            self.args.total_paths = len(current_paths)
            print(f"待扫描路径数: {len(current_paths)}")

            self._scan_paths(current_paths)

            if GLOBAL_STATE.should_exit:
                break

            new_200_paths = self._get_new_200_paths()
            if not new_200_paths:
                print(f"\n\033[94m[*] 未发现新的200路径，停止迭代\033[0m")
                break

            print(f"\n\033[94m[*] 发现 {len(new_200_paths)} 个新200路径，开始二次爬虫...\033[0m")

            for url in new_200_paths:
                with self.discovered_lock:
                    if url not in self.scanned_urls:
                        continue
                self._crawl_single_url(url)

            combined_new_paths = self._get_combined_paths_from_discovered()
            if combined_new_paths:
                print(f"\033[94m[*] 拼接路径发现 {len(combined_new_paths)} 个新路径，扫描...\033[0m")
                self._scan_paths(list(combined_new_paths))

                combined_200 = self._get_new_200_paths()
                if combined_200:
                    print(f"\033[94m[*] 拼接路径中发现 {len(combined_200)} 个200路径，继续爬虫...\033[0m")
                    for url in combined_200:
                        self._crawl_single_url(url)

            with self.discovered_lock:
                prev_count = len(self.scanned_urls)
                new_paths_this_iteration = len(self.all_discovered_paths) - prev_count

            print(f"\033[94m[*] 本轮迭代: 扫描了 {self.scanned_count} 条路径，发现 {new_paths_this_iteration} 个新路径\033[0m")

            if new_paths_this_iteration == 0:
                print(f"\033[94m[*] 无新路径产生，停止迭代\033[0m")
                break

        if iteration >= max_iterations:
            print(f"\033[93m[!] 达到最大迭代次数 {max_iterations}，停止扫描\033[0m")

        self._finish_scan()

    def _crawl_single_url(self, url: str):
        if GLOBAL_STATE.should_exit:
            return
        try:
            resp = self.session.get(url, timeout=self.args.timeout, verify=False)
            final_url = resp.url
            if self.args.debug and final_url != url:
                print(f"[D] 重定向: {url} -> {final_url}")
            if resp.status_code == 200:
                parser = LinkExtractor(final_url)
                parser.feed(resp.text)

                css_links = self._extract_css_links(resp.text, final_url)
                js_links = self._extract_js_links(resp.text, final_url)

                for css_url in css_links:
                    css_paths = self._fetch_and_parse_css(css_url)
                    with self.discovered_lock:
                        self.all_discovered_paths.update(css_paths)

                for js_url in js_links:
                    js_paths = self._fetch_and_parse_js(js_url)
                    with self.discovered_lock:
                        self.all_discovered_paths.update(js_paths)

                with self.discovered_lock:
                    for link in parser.links:
                        if link.startswith(self.args.url):
                            self.all_discovered_paths.add(link)

                    parent_paths = parser.extract_parent_paths(parser.links)
                    self.all_discovered_paths.update(parent_paths)

        except Exception:
            pass

    def _get_new_200_paths(self) -> Set[str]:
        new_200 = set()
        with self.results_lock:
            for result in self.results:
                if result["status_code"] == 200 and result.get("is_sensitive_duplicate", 0) == 0:
                    new_200.add(result["url"])
        return new_200

    def _get_combined_paths_from_discovered(self) -> Set[str]:
        combined = set()
        discovered_200 = self._get_new_200_paths()

        if not discovered_200:
            return combined

        fragments = set()
        for url in discovered_200:
            parsed = urllib.parse.urlparse(url)
            path_parts = parsed.path.strip('/').split('/')
            for part in path_parts:
                if part and '.' not in part and len(part) > 2:
                    fragments.add(part)

        if fragments:
            for base_url in discovered_200:
                combined.update(PathCombiner.combine_paths(base_url, list(fragments), max_up_levels=3))

        combined = PathCombiner.deduplicate_paths(combined)
        with self.discovered_lock:
            combined -= self.all_discovered_paths

        return combined

    def _scan_paths(self, paths: List[str]):
        progress_lock = threading.Lock()
        last_update = [time.time()]
        update_interval = 0.5
        current_threads = self.args.threads

        def progress_callback(count):
            with progress_lock:
                now = time.time()
                if now - last_update[0] >= update_interval:
                    last_update[0] = now
                    total = self.args.total_paths
                    percent = (count / total * 100) if total > 0 else 0
                    speed = count / (now - self.start_time) if self.start_time else 0
                    remaining = (total - count) / speed if speed > 0 else 0

                    bar_length = 30
                    filled = int(bar_length * count / total) if total > 0 else 0
                    bar = "=" * filled + "-" * (bar_length - filled)

                    sys.stdout.write(f"\r[{bar}] {percent:.1f}% {count}/{total} 速度:{speed:.1f}/s 剩余:{remaining:.0f}s 敏感:{self.sensitive_count} 线程:{current_threads} ")
                    sys.stdout.flush()

        while True:
            current_threads = self.adaptive_thread_controller.get_threads()

            with self.discovered_lock:
                paths_to_scan = [p for p in paths if p not in self.scanned_urls]

            if not paths_to_scan:
                break

            with ThreadPoolExecutor(max_workers=current_threads) as executor:
                futures = {executor.submit(self.worker, path, progress_callback): path for path in paths_to_scan}

                for future in as_completed(futures):
                    if GLOBAL_STATE.should_exit:
                        for f in futures:
                            f.cancel()
                        break

                    path = futures[future]
                    with self.discovered_lock:
                        self.scanned_urls.add(path)

            if not self.failed_paths:
                break

            print(f"\n\033[94m[*] 重试失败路径: {len(self.failed_paths)}\033[0m")
            self.failed_paths = []

    def _finish_scan(self):
        print("\n")
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
                    writer = csv.DictWriter(f, fieldnames=["url", "status_code", "status_desc", "scan_time", "title", "is_sensitive", "is_sensitive_duplicate", "content_size"])
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
                    writer = csv.DictWriter(f, fieldnames=["url", "status_code", "status_desc", "scan_time", "title", "is_sensitive", "is_sensitive_duplicate", "content_size"])
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

    def _generate_results_table(self, results: List, risk_class: str) -> str:
        if not results:
            return "<p>无</p>"
        rows = ""
        for r in results[:50]:
            badge_class = f"badge-{r['status_code']}"
            rows += f"""<tr>
                <td><span class="badge {badge_class}">{r['status_code']}</span></td>
                <td><a href="{r['url']}">{r['url']}</a></td>
                <td>{r.get('title', '')}</td>
                <td>{r.get('content_size', '')}</td>
            </tr>"""
        return f"""<table>
            <thead>
                <tr>
                    <th>状态码</th>
                    <th>URL</th>
                    <th>标题</th>
                    <th>大小</th>
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
            "crawl_depth": self.args.crawl_depth,
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
