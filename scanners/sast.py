"""SAST scanner — pattern-based analysis across Python, JS/TS, Go, Ruby, Java, PHP."""
import re
from pathlib import Path
from typing import List, Set

from core.models import Finding, Severity

PATTERNS = [
    (
        "Hardcoded Secret",
        re.compile(
            r'(?i)(password|passwd|secret|api_key|apikey|auth_token|access_token|private_key'
            r'|client_secret|db_pass|database_password)\s*[=:]\s*["\']([^"\']{8,})["\']'
        ),
        Severity.HIGH,
        "Hardcoded credential detected in source code",
        "Use environment variables or a secrets manager. Never commit secrets to source control.",
        None,
    ),
    (
        "AWS Access Key ID",
        re.compile(r'(?<![A-Z0-9])(AKIA|ABIA|ACCA|ASCA)[0-9A-Z]{16}(?![A-Z0-9])'),
        Severity.CRITICAL,
        "AWS Access Key ID found in source code",
        "Rotate this key immediately via AWS IAM. Use IAM roles or environment variables instead.",
        None,
    ),
    (
        "Private Key Material",
        re.compile(r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'),
        Severity.CRITICAL,
        "Private key material detected in source code",
        "Remove private keys from source control. Use secure key storage (e.g. AWS Secrets Manager, Vault).",
        None,
    ),
    (
        "GitHub Personal Access Token",
        re.compile(r'ghp_[0-9A-Za-z]{36}|github_pat_[0-9A-Za-z_]{82}'),
        Severity.CRITICAL,
        "GitHub personal access token detected",
        "Revoke this token immediately at github.com/settings/tokens.",
        None,
    ),
    (
        "Generic Bearer Token",
        re.compile(r'[Bb]earer\s+[A-Za-z0-9\-_]{20,}'),
        Severity.MEDIUM,
        "Hardcoded Bearer token detected",
        "Load tokens from environment variables at runtime, never embed in source code.",
        {".py", ".js", ".ts", ".go", ".java", ".rb", ".php"},
    ),

    (
        "Shell Injection (shell=True)",
        re.compile(r'subprocess\.(call|run|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True'),
        Severity.HIGH,
        "subprocess called with shell=True enables shell injection via user input",
        "Pass arguments as a list and set shell=False. Validate all inputs before use.",
        {".py"},
    ),
    (
        "os.system / os.popen",
        re.compile(r'\bos\.(system|popen|execvpe?|spawnl[pe]?)\s*\('),
        Severity.HIGH,
        "Dangerous OS command execution that may allow injection",
        "Use subprocess with a list of arguments and shell=False instead.",
        {".py"},
    ),
    (
        "child_process.exec (Node.js)",
        re.compile(r'(?:child_process\.)?exec\s*\((?!.*execFile)'),
        Severity.HIGH,
        "child_process.exec passes the command through a shell, enabling injection",
        "Use execFile() or spawn() with a list of arguments instead.",
        {".js", ".ts"},
    ),

    (
        "SQL String Formatting",
        re.compile(
            r'(?i)(execute|cursor\.execute|raw|query)\s*\(\s*[f"\'](SELECT|INSERT|UPDATE|DELETE|DROP)'
            r'|(?:SELECT|INSERT|UPDATE|DELETE).*?[+%]\s*\w+'
            r'|f"(SELECT|INSERT|UPDATE|DELETE)'
        ),
        Severity.HIGH,
        "SQL query constructed via string formatting — vulnerable to SQL injection",
        "Use parameterized queries or an ORM. Never interpolate user input into SQL.",
        {".py", ".php", ".java", ".js", ".ts", ".rb"},
    ),

    (
        "Pickle Deserialization",
        re.compile(r'\bpickle\.(loads?|Unpickler)\s*\('),
        Severity.HIGH,
        "Deserializing untrusted pickle data can lead to Remote Code Execution",
        "Use JSON or another safe format for untrusted data. Never unpickle user-supplied data.",
        {".py"},
    ),
    (
        "yaml.load() Without SafeLoader",
        re.compile(r'\byaml\.load\s*\((?!.*Loader\s*=\s*yaml\.(?:Safe|Base)Loader)'),
        Severity.MEDIUM,
        "yaml.load() with the default Loader can execute arbitrary Python code",
        "Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader) instead.",
        {".py"},
    ),
    (
        "Java ObjectInputStream",
        re.compile(r'new\s+ObjectInputStream\s*\('),
        Severity.HIGH,
        "Java ObjectInputStream deserialization of untrusted data can lead to RCE",
        "Validate the source before deserializing. Consider using JSON/XML with schema validation.",
        {".java"},
    ),

    (
        "eval() Usage",
        re.compile(r'\beval\s*\('),
        Severity.HIGH,
        "eval() on untrusted input enables arbitrary code execution",
        "Avoid eval(). Use ast.literal_eval() for safe Python expression evaluation.",
        {".py", ".js", ".ts", ".php"},
    ),
    (
        "exec() Usage",
        re.compile(r'\bexec\s*\('),
        Severity.MEDIUM,
        "exec() on untrusted input enables code execution",
        "Avoid exec() on user-controlled data.",
        {".py"},
    ),

    (
        "Weak Hash — MD5",
        re.compile(r'(?i)\b(md5|hashlib\.md5)\s*[\(.]'),
        Severity.MEDIUM,
        "MD5 is cryptographically broken — do not use for security-sensitive hashing",
        "Use SHA-256 or SHA-3 for security. MD5 is acceptable only for non-security checksums.",
        {".py", ".js", ".ts", ".go", ".java", ".php", ".rb"},
    ),
    (
        "Weak Hash — SHA-1",
        re.compile(r'(?i)\b(sha1|hashlib\.sha1|SHA-?1)\s*[\(.]'),
        Severity.MEDIUM,
        "SHA-1 is cryptographically weak — collision attacks are practical",
        "Use SHA-256 or stronger for all security-sensitive hashing.",
        {".py", ".js", ".ts", ".go", ".java", ".php", ".rb"},
    ),
    (
        "Insecure Random (Python)",
        re.compile(r'\brandom\.(random|randint|choice|shuffle|uniform|sample|getrandbits)\s*\('),
        Severity.MEDIUM,
        "Python's random module is not cryptographically secure",
        "Use the secrets module for tokens, passwords, and security-sensitive values.",
        {".py"},
    ),
    (
        "Insecure Random (Math.random)",
        re.compile(r'\bMath\.random\s*\('),
        Severity.MEDIUM,
        "Math.random() is not cryptographically secure",
        "Use crypto.getRandomValues() or the Node.js crypto module for security-sensitive randomness.",
        {".js", ".ts"},
    ),
    (
        "DES / 3DES Cipher",
        re.compile(r'(?i)\b(DES|TripleDES|3DES|DESede)\b'),
        Severity.MEDIUM,
        "DES/3DES are deprecated weak ciphers vulnerable to known attacks",
        "Use AES-256-GCM or ChaCha20-Poly1305 instead.",
        {".py", ".js", ".ts", ".java", ".go", ".rb"},
    ),

    (
        "Path Traversal — open() with Request Input",
        re.compile(r'\bopen\s*\(\s*(?:request\.|req\.|flask\.request|cherrypy\.request)'),
        Severity.HIGH,
        "Opening files with user-controlled paths may allow path traversal (../../etc/passwd)",
        "Validate paths with os.path.realpath() and ensure the result is within an allowed directory.",
        {".py"},
    ),
    (
        "Path Traversal — fs.readFile with Input",
        re.compile(r'fs\.(?:readFile|writeFile|createReadStream)\s*\(\s*(?:req\.|request\.)'),
        Severity.HIGH,
        "Reading files with user-controlled paths may allow path traversal",
        "Sanitize and validate file paths. Use path.resolve() and check against an allowed base directory.",
        {".js", ".ts"},
    ),

    (
        "innerHTML Assignment (XSS)",
        re.compile(r'\.innerHTML\s*=\s*(?!["\'`])'),
        Severity.HIGH,
        "Direct innerHTML assignment with a non-literal value can lead to XSS",
        "Use textContent instead, or sanitize with DOMPurify before assigning to innerHTML.",
        {".js", ".ts", ".jsx", ".tsx", ".html"},
    ),
    (
        "dangerouslySetInnerHTML (React XSS)",
        re.compile(r'dangerouslySetInnerHTML\s*='),
        Severity.MEDIUM,
        "dangerouslySetInnerHTML bypasses React's built-in XSS protection",
        "Sanitize the HTML string with DOMPurify before passing to dangerouslySetInnerHTML.",
        {".jsx", ".tsx", ".js", ".ts"},
    ),
    (
        "document.write()",
        re.compile(r'\bdocument\.write\s*\('),
        Severity.MEDIUM,
        "document.write() with user input can lead to XSS",
        "Avoid document.write(). Use DOM manipulation APIs instead.",
        {".js", ".ts", ".html"},
    ),

    (
        "XML External Entity (XXE) — Python",
        re.compile(r'(?i)(etree\.parse|minidom\.parse|expat\.ParserCreate|lxml\.etree)'),
        Severity.MEDIUM,
        "XML parsers may be vulnerable to XXE if external entities are not disabled",
        "Disable external entity processing: use defusedxml or set resolve_entities=False.",
        {".py"},
    ),

    (
        "SSRF Risk — requests with user input",
        re.compile(r'requests\.(get|post|put|delete|head|patch)\s*\(\s*(?:request\.|req\.|flask\.request|f")'),
        Severity.HIGH,
        "Making HTTP requests to user-controlled URLs can lead to Server-Side Request Forgery (SSRF)",
        "Validate URLs against an allowlist. Block requests to internal IP ranges and metadata endpoints.",
        {".py"},
    ),

    (
        "Insecure HTTP URL (non-localhost)",
        re.compile(r'http://(?!(?:localhost|127\.|0\.0\.0\.0|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.))[a-zA-Z0-9]'),
        Severity.LOW,
        "Unencrypted HTTP URL — data transmitted in plaintext",
        "Use HTTPS for all external communications.",
        {".py", ".js", ".ts", ".go", ".java", ".rb", ".yaml", ".yml"},
    ),

    (
        "Debug Mode Enabled",
        re.compile(r'(?i)\b(debug\s*=\s*True|DEBUG\s*=\s*True|app\.run\([^)]*debug\s*=\s*True)'),
        Severity.MEDIUM,
        "Debug mode exposes stack traces and may enable interactive debuggers in production",
        "Disable debug mode in production. Control via environment variables.",
        {".py", ".js", ".ts", ".yaml", ".yml", ".cfg", ".ini", ".env"},
    ),
    (
        "Assert for Security Check",
        re.compile(r'\bassert\s+.*?(?:auth|login|permission|admin|role|password|token|access)'),
        Severity.MEDIUM,
        "Python assert statements are stripped when running with -O (optimized) flag",
        "Replace security-critical assert statements with explicit if/raise blocks.",
        {".py"},
    ),
    (
        "Hardcoded IP Address",
        re.compile(r'\b(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b'),
        Severity.LOW,
        "Hardcoded private IP address — may expose internal network topology",
        "Use configuration files or environment variables for network addresses.",
        {".py", ".js", ".ts", ".go", ".java", ".yaml", ".yml"},
    ),
]

# File extensions to scan
SCANNABLE_EXTENSIONS: Set[str] = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rb", ".php",
    ".java", ".cs", ".cpp", ".c", ".h", ".yaml", ".yml", ".json",
    ".toml", ".cfg", ".ini", ".env", ".html", ".htm", ".xml",
}

_SKIP_DIRS: Set[str] = {
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    "env", "dist", "build", ".pytest_cache", ".mypy_cache",
    "vendor", "third_party", ".tox", "site-packages", ".next",
}

# Files that define SAST rules — skip to avoid self-detection (eval, exec, yaml, etc.)
_SAST_SKIP_FILES: Set[str] = {"scanners/sast.py"}

# Lines beginning with these tokens are likely comments — skip to reduce noise
_COMMENT_PREFIXES = ("#", "//", "/*", "*", "<!--", "--", ";")


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def scan(path: str, progress_callback=None) -> List[Finding]:
    """Run SAST patterns against all source files under path."""
    root = Path(path)
    findings: List[Finding] = []

    for file_path in _iter_files(root):
        if any(skip in str(file_path) for skip in _SAST_SKIP_FILES):
            continue
        file_findings = _scan_file(file_path)
        if file_findings:
            findings.extend(file_findings)
        if progress_callback:
            progress_callback()

    return findings


def _iter_files(root: Path):
    if root.is_file():
        if root.suffix.lower() in SCANNABLE_EXTENSIONS:
            yield root
        return
    for p in root.rglob("*"):
        if p.is_file() and p.suffix.lower() in SCANNABLE_EXTENSIONS:
            if not any(part in _SKIP_DIRS for part in p.parts):
                yield p


def _scan_file(file_path: Path) -> List[Finding]:
    try:
        content = file_path.read_text(errors="replace")
    except OSError:
        return []

    ext = file_path.suffix.lower()
    lines = content.splitlines()
    findings: List[Finding] = []
    # Track (pattern_name, line_number) to avoid duplicates in the same file
    seen = set()

    for pattern_name, regex, severity, description, remediation, file_types in PATTERNS:
        if file_types is not None and ext not in file_types:
            continue

        for lineno, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith(_COMMENT_PREFIXES):
                continue
            if regex.search(line):
                key = (pattern_name, lineno)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(Finding(
                    title=pattern_name,
                    description=description,
                    scanner="sast",
                    severity=severity,
                    location=str(file_path),
                    line_number=lineno,
                    evidence=stripped[:200],
                    remediation=remediation,
                ))

    return findings
