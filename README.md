# pr0xywall - Layer 7 Proxy Firewall

A production-grade HTTP/1.1 proxy server with deep packet inspection, rule-based filtering, rate limiting, and threat scoring.

## Features

- **HTTP/1.1 Proxy Server**: Intercepts and forwards HTTP requests
- **Layer 7 Inspection**: Deep packet inspection of HTTP requests
- **Rule Engine**: Flexible rule system with scoring
  - Block HTTP methods (GET, POST, etc.)
  - Block specific paths (/admin, /config, etc.)
  - Detect keywords in body (password, token, SQL injection)
  - Check headers (User-Agent, etc.)
- **Rate Limiting**: Thread-safe per-IP rate limiting
- **Threat Scoring**: Cumulative scoring system for threat assessment
- **Structured Logging**: Clean, colored log output

## Project Structure

```
pr0xywall/
├── main.py                 # CLI entry point
├── proxy/
│   └── server.py          # HTTP proxy server
├── parser/
│   └── request_parser.py  # HTTP request parser
├── rules/
│   └── rules.py           # Rule engine
├── engine/
│   └── decision_engine.py # Decision engine
├── ratelimit/
│   └── limiter.py         # Rate limiting
├── logger/
│   └── logger.py          # Logging system
└── utils/
    └── helpers.py         # Utility functions
```

## Installation

No external dependencies required. Uses Python standard library only.

```bash
# Python 3.10+ required
python --version

# Clone or download the project
cd pr0xywall
```

## Usage

### Basic Usage

```bash
# Run on default port 8080
python main.py

# Run on custom port
python main.py --port 9090

# Custom configuration
python main.py --port 8080 --threshold 30 --rate-limit 20
```

### Command Line Options

```
usage: pr0xywall [-h] [--port PORT] [--host HOST] [--threshold THRESHOLD]
                 [--rate-limit RATE_LIMIT] [--burst-size BURST_SIZE]
                 [--block-duration BLOCK_DURATION] [--no-color] [--version]

Layer 7 Application-Level Proxy Firewall

optional arguments:
  -h, --help            show this help message and exit
  --port PORT, -p PORT  Proxy server port (default: 8080)
  --host HOST, -H HOST  Bind address (default: 0.0.0.0)
  --threshold THRESHOLD, -t THRESHOLD
                        Rule scoring threshold for blocking (default: 25)
  --rate-limit RATE_LIMIT, -r RATE_LIMIT
                        Requests per second limit per IP (default: 10)
  --burst-size BURST_SIZE, -b BURST_SIZE
                        Burst request limit (default: 20)
  --block-duration BLOCK_DURATION
                        Seconds to block after limit exceeded (default: 60)
  --no-color            Disable colored output
  --version, -v         show program's version number and exit
```

## Default Security Rules

pr0xywall comes with pre-configured security rules:

| Rule | Severity | Score | Description |
|------|----------|-------|-------------|
| block_trace | MEDIUM | 10 | Blocks TRACE method |
| block_admin | HIGH | 20 | Blocks /admin endpoints |
| block_config | HIGH | 20 | Blocks config file access |
| detect_sql_injection | CRITICAL | 50 | Detects SQL injection patterns |
| detect_password_leak | MEDIUM | 10 | Detects password exposure |
| detect_token_leak | MEDIUM | 10 | Detects token/key exposure |
| block_sqlmap | HIGH | 20 | Blocks SQLMap scanner |
| block_nmap | HIGH | 20 | Blocks Nmap scanner |
| block_bots | LOW | 5 | Detects automated tools |

**Default threshold**: 25 (requests with score >= 25 are blocked)

## Log Output

```
[2024-01-15 10:30:45] [ALLOW] 192.168.1.10 GET /index
[2024-01-15 10:30:46] [BLOCK] 192.168.1.10 POST /admin (Reason: Access to admin endpoint blocked) [Score: 20]
[2024-01-15 10:30:47] [BLOCK] 192.168.1.10 GET /search (Reason: SQL injection pattern detected) [Score: 50]
[2024-01-15 10:30:48] [BLOCK] 192.168.1.10 GET / (Reason: Rate limit exceeded: 15 req/sec)
```

## Testing

### Test with curl

```bash
# Configure proxy
curl -x http://localhost:8080 http://example.com

# Test blocked method
curl -x http://localhost:8080 -X TRACE http://example.com

# Test blocked path
curl -x http://localhost:8080 http://example.com/admin

# Test SQL injection detection
curl -x http://localhost:8080 -d "query=' OR 1=1 --" http://example.com/search

# Test rate limiting (run multiple times quickly)
for i in {1..25}; do curl -x http://localhost:8080 http://example.com; done
```

### Configure Browser

Set your browser's HTTP proxy to `localhost:8080` to route all traffic through pr0xywall.

## Architecture

```
Incoming Request → HTTP Parser → Rule Engine → Decision → Forward / Block
                                      ↓
                                Rate Limiter
```

### Flow

1. **HTTP Parser**: Extracts client IP, method, path, headers, body
2. **Rule Engine**: Evaluates request against security rules, calculates threat score
3. **Rate Limiter**: Checks per-IP request rate
4. **Decision Engine**: Combines rule score and rate limit status
5. **Action**: Forward to target server or return 403 Forbidden

## API Usage

```python
from main import ProxyWall

# Create and configure
app = ProxyWall()
app.setup(
    port=8080,
    threshold=25,
    rate_limit=10.0,
    burst_size=20
)

# Run server
app.run()
```

### Custom Rules

```python
from rules.rules import RuleSet, Severity

# Get rule set from decision engine
rule_set = app.decision_engine.rule_set

# Add custom rule
rule_set.add_method_block_rule(
    name="block_delete",
    methods=["DELETE"],
    severity=Severity.HIGH,
    reason="DELETE method not allowed"
)

# Add path block with regex
rule_set.add_path_block_rule(
    name="block_api",
    paths=[r"/api/v\d+/admin"],
    severity=Severity.CRITICAL,
    reason="API admin access blocked",
    regex=True
)

# Add keyword detection
rule_set.add_keyword_rule(
    name="detect_malware",
    keywords=["eval(", "exec(", "system("],
    severity=Severity.CRITICAL,
    reason="Potential malware detected"
)

# Disable a rule
rule_set.disable_rule("block_bots")

# List all rules
print(rule_set.list_rules())
```

## Performance

- Uses threading for concurrent connections
- Thread-safe rate limiting with RLock
- Efficient sliding window algorithm
- Periodic cleanup of stale entries

## License

MIT License

## Author

pr0xywall
