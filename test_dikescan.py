#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""改造后的行为验证：不联网，只测纯逻辑与判定层。"""
import argparse
import io
import sys

sys.path.insert(0, ".")
import dikescan as D

ok = fail = 0


def check(name, cond, detail=""):
    global ok, fail
    if cond:
        ok += 1
        print(f"  [PASS] {name}")
    else:
        fail += 1
        print(f"  [FAIL] {name} {detail}")


print("=== 1. normalize_path：不再破坏协议头、保留 query、不强加尾斜杠 ===")
cases = {
    "http://a.com/admin": "http://a.com/admin",
    "https://a.com/api/v1?x=1": "https://a.com/api/v1?x=1",
    "http://a.com": "http://a.com/",
    "/a//b": "/a/b",
    "MyAdmin": "MyAdmin",
    "admin/x.php?a=1&b=2": "admin/x.php?a=1&b=2",
    "http://a.com/p#frag": "http://a.com/p",
}
for src_v, want in cases.items():
    got = D.PathCombiner.normalize_path(src_v)
    check(f"{src_v!r} -> {got!r}", got == want, f"(期望 {want!r})")

print("\n=== 2. deduplicate_paths：保留含重复片段的合法路径 + 保留 query ===")
paths = {"/admin", "/api/api/status", "/test/test/x", "/1/1/backup.zip",
         "/x.php?a=1", "/x.php?a=2", "/a/b/c"}
out = D.PathCombiner.deduplicate_paths(paths)
check("含重复片段路径未被丢弃", all(p in out for p in ("/api/api/status", "/test/test/x", "/1/1/backup.zip")))
check("不同 query 视为不同路径", "/x.php?a=1" in out and "/x.php?a=2" in out)

print("\n=== 3. apply_dir_slash ===")
slashed = D.PathCombiner.apply_dir_slash({"/admin", "/x.php", "/a/b"})
check("目录型生成尾斜杠变体", "/admin/" in slashed)
check("带扩展名不生成变体", "/x.php/" not in slashed)
check("原始条目保留", "/admin" in slashed and "/x.php" in slashed)

print("\n=== 4. Task.key 与去重维度 ===")
t1 = D.Task(url="http://a.com/x", method="GET")
t2 = D.Task(url="http://a.com/x", method="POST", data="a=1")
t3 = D.Task(url="http://a.com/x", method="POST", data="a=2")
check("GET 与 POST 不冲突", t1.key() != t2.key())
check("不同 body 不冲突", t2.key() != t3.key())

print("\n=== 5. LinkExtractor：表单解析 + query 不重复拼接 ===")
html = ('<html><body>'
        '<form action="/login" method="POST">'
        '<input name="username" value=""><input name="password" type="password">'
        '<input type="submit" value="go"></form>'
        '<form action="/search" method="get"><input name="q"></form>'
        '<a href="http://a.com/x?a=1">x</a>'
        '</body></html>')
p = D.LinkExtractor("http://a.com/")
p.feed(html)
p.close()
check("解析到 2 个表单", len(p.forms) == 2, f"got {len(p.forms)}")
post_form = [f for f in p.forms if f["method"] == "POST"]
check("识别 POST method", len(post_form) == 1, f"got {[f['method'] for f in p.forms]}")
check("提取 input name（跳过 submit）",
      post_form and [i["name"] for i in post_form[0]["inputs"]] == ["username", "password"],
      f"got {post_form[0]['inputs'] if post_form else None}")
check("query 不被重复拼接",
      "http://a.com/x?a=1" in p.links, f"got {p.links}")

print("\n=== 6. _form_to_task ===")
form_task = D.Scanner._form_to_task(None, p.forms[0], "http://a.com/")
check("POST 表单生成 POST 任务", form_task is not None and form_task.method == "POST")
check("POST body 带上参数名", form_task and "username=" in (form_task.data or ""))
get_task = D.Scanner._form_to_task(None, p.forms[1], "http://a.com/")
check("GET 表单参数进 query", get_task and get_task.method == "GET" and "q=" in get_task.url)

print("\n=== 7. match_secrets：PII / 凭据识别 ===")
samples = {
    "PRC_ID": b'{"id":"110101199003071234"}',
    "CN_MOBILE": b'{"phone":"13800138000"}',
    "AWS_AKIA": b'key=AKIAIOSFODNN7EXAMPLE',
    "PRIVATE_KEY": b'-----BEGIN RSA PRIVATE KEY-----',
    "JWT": b'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w',
    "JDBC_URL": b'jdbc:mysql://10.0.0.5:3306/prod',
    "CREDENTIAL": b'password: Sup3rSecretValue',
}
for label, payload in samples.items():
    hits = D.match_secrets(payload)
    check(f"识别 {label}", label in hits, f"got {hits}")
check("干净内容不误报", D.match_secrets(b'<html><body>hello world</body></html>') == [],
      f"got {D.match_secrets(b'<html><body>hello world</body></html>')}")

print("\n=== 8. 判定层 evaluate：非 200 不再被丢弃 ===")
args = argparse.Namespace(
    url="http://a.com/", headers=None, proxy=None, threads=1,
    dup_size_threshold=3, wordlist="dict", debug=False, resume=False,
    dedup_mode="off", save_evidence=False, method="GET", timeout=5, retry=1,
    include_status=None, exclude_status=None, valid_keywords=None, invalid_keywords=None,
)
sc = D.Scanner(args)

def mk(status, url, headers=None, content=b"", history=None):
    return D.RespInfo(status=status, url=url, headers=headers or {},
                      content=content, history=history or [], elapsed=0.1)

r403 = sc.evaluate(D.Task(url="http://a.com/admin/"),
                   mk(403, "http://a.com/admin/"))
check("403 生成结果（原实现丢弃）", r403 is not None and r403["status_code"] == 403)

r302 = sc.evaluate(D.Task(url="http://a.com/admin"),
                   mk(302, "http://a.com/login", history=["http://a.com/admin"]))
check("302 生成结果", r302 is not None)
check("302 记录重定向链", r302 and "http://a.com/admin" in r302["redirect_chain"], f"got {r302}")

r301 = sc.evaluate(D.Task(url="http://a.com/old"), mk(301, "http://a.com/new", history=["http://a.com/old"]))
check("301 生成结果", r301 is not None)

r200 = sc.evaluate(D.Task(url="http://a.com/hi"),
                   mk(200, "http://a.com/hi", headers={"content-type": "text/html"},
                      content=b"<html><title>Hi</title></html>"))
check("200 生成结果", r200 is not None)
check("200 提取 title", r200 and r200["title"] == "Hi")

r404 = sc.evaluate(D.Task(url="http://a.com/nope"), mk(404, "http://a.com/nope"))
check("404 被默认排除", r404 is None)

print("\n=== 9. 去重模式 ===")
sc.args.dedup_mode = "redirect"
sc.fingerprint_cache = D.FingerprintCache("redirect")
redirect_a = sc.evaluate(D.Task(url="http://a.com/p1"),
                         mk(200, "http://a.com/login", history=["http://a.com/p1"]))
redirect_b = sc.evaluate(D.Task(url="http://a.com/p2"),
                         mk(200, "http://a.com/login", history=["http://a.com/p2"]))
check("redirect 模式：都跳登录页只留一条", redirect_a is not None and redirect_b is None,
      f"a={redirect_a is not None} b={redirect_b is not None}")

sc.fingerprint_cache = D.FingerprintCache("redirect")
x1 = sc.evaluate(D.Task(url="http://a.com/spa/a"),
                 mk(200, "http://a.com/spa/a", headers={"content-type": "text/html"}, content=b"<html>app</html>"))
x2 = sc.evaluate(D.Task(url="http://a.com/spa/b"),
                 mk(200, "http://a.com/spa/b", headers={"content-type": "text/html"}, content=b"<html>app</html>"))
check("redirect 模式：SPA 同内容不再被吞掉", x1 is not None and x2 is not None)

# 模板聚类：同一 Akamai 拒绝页（路径不同 + Reference # 不同）应折叠
sc.args.dedup_mode = "template"
t1 = sc.evaluate(D.Task(url="http://a.com/admin/.env"),
                 mk(403, "http://a.com/admin/.env",
                    headers={"content-type": "text/html"},
                    content=b'<HTML><TITLE>Access Denied</TITLE>You don\'t have permission to access "http://a.com/admin/.env" on this server. Reference #18.e20c0317.1788856190.3ee90e67</HTML>'.replace(b"#18.", b"#18.")))
t2 = sc.evaluate(D.Task(url="http://a.com/site/.env"),
                 mk(403, "http://a.com/site/.env",
                    headers={"content-type": "text/html"},
                    content=b'<HTML><TITLE>Access Denied</TITLE>You don\'t have permission to access "http://a.com/site/.env" on this server. Reference #18.d7b31402.1788856191.92043e97</HTML>'))
check("template 模式：Akamai 403 模板归一化折叠", t1 is not None and t2 is None,
      f"t1={t1 is not None} t2={t2 is not None}")

sc.args.dedup_mode = "off"

print("\n=== 10. 敏感路径标记 ===")
check("admin 判为敏感", sc.is_sensitive_path("http://a.com/admin/") is True)
check("普通路径不敏感", sc.is_sensitive_path("http://a.com/about/") is False)

print("\n=== 11. 证据落盘 ===")
import os, tempfile, shutil
tmpdir = tempfile.mkdtemp()
sc.args.save_evidence = True
sc.args.evidence_dir = tmpdir
ev = sc.evaluate(D.Task(url="http://a.com/admin/", method="POST", data="a=1"),
                 mk(200, "http://a.com/admin/", headers={"content-type": "text/html"},
                    content=b"<html><title>Admin</title></html>"))
check("证据文件已生成", bool(ev and ev.get("evidence_file") and os.path.exists(ev["evidence_file"])))
if ev and ev.get("evidence_file"):
    body = io.open(ev["evidence_file"], encoding="utf-8").read()
    check("证据含请求方法", "POST /admin/" in body, f"got: {body.splitlines()[:2]}")
    check("证据含请求体", "a=1" in body)
    check("证据含响应状态行", "HTTP/1.1 200 OK" in body)
shutil.rmtree(tmpdir, ignore_errors=True)
sc.args.save_evidence = False

print("\n=== 12. 异步 worker 切片：每条任务只被消费一次 ===")
async def _slice_test():
    import asyncio as A
    seen = []

    class FakeScanner:
        scanned_count = 0
        scanned_urls = set()
        scanned_keys = set()
        results = []
        found_count = 0
        sensitive_count = 0

    class FakeAS(D.AsyncScanner):
        def __init__(self):
            self.args = argparse.Namespace(threads=1, timeout=5, delay=0, debug=False,
                                           headers=None, proxy=None)
            self.scanner = FakeScanner()
            self.max_concurrency = 4
            self.delay = 0
            self.debug = False
            self.proxy = None
            self.base_headers = {}
            self.session = None
            self.semaphore = A.Semaphore(4)
            self._async_lock = A.Lock()

        async def scan_single_task(self, task):
            seen.append(task.url)
            return None

    fa = FakeAS()
    tasks = [D.Task(url=f"http://a.com/{i}") for i in range(20)]
    n = 4
    batch = tasks
    workers = [A.create_task(fa.worker(batch[j::n], None)) for j in range(n)]
    await A.gather(*workers)
    return tasks, seen

import asyncio
tasks, seen = asyncio.run(_slice_test())
check("20 条任务各被消费一次", len(seen) == len(tasks), f"请求了 {len(seen)} 次，应为 {len(tasks)}")
check("无重复请求", len(set(seen)) == len(seen))

print(f"\n{'='*50}\n通过 {ok} 项，失败 {fail} 项\n{'='*50}")
sys.exit(1 if fail else 0)
