DEFAULT_TIMEOUT = 120

ALLOWED_SCHEMES = [
    "http://",
    "https://"
]

REQUIRED_TOOLS = [
    "nmap",
    "whatweb",
    "ffuf",
    "curl"
]

WORDLISTS = {
    "small": "/usr/share/wordlists/dirb/common.txt",
    "medium": "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
    "raft": "/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt"
}

COMMON_EXTENSIONS = [
    "php",
    "txt",
    "bak",
    "old",
    "zip",
    "sql",
    "json",
    "env",
    "log"
]

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Strict-Transport-Security"
]

INTERESTING_KEYWORDS = [
    "admin",
    "login",
    "dashboard",
    "backup",
    "database",
    "db",
    "config",
    "vendor",
    "uploads",
    "files",
    "server-status",
    "phpinfo",
    ".git",
    ".env"
]

SQL_ERROR_SIGNATURES = [
    "SQL syntax",
    "mysql_fetch",
    "mysqli_fetch",
    "MariaDB",
    "MySQL",
    "PostgreSQL",
    "SQLite",
    "ODBC",
    "ORA-",
    "syntax error",
    "unclosed quotation"
]

DEBUG_ERROR_SIGNATURES = [
    "Fatal error",
    "Warning:",
    "Notice:",
    "Stack trace",
    "Traceback",
    "Undefined index",
    "Undefined variable",
    "Exception",
    "RuntimeError"
]

CRAWLER_MAX_PAGES = 30
CRAWLER_MAX_DEPTH = 2
CRAWLER_TIMEOUT = 10

CRAWLER_ALLOWED_CONTENT_TYPES = [
    "text/html",
    "application/xhtml+xml"
]