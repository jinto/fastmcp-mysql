# FastMCP MySQL Server

A FastMCP server implementation for MySQL database operations, providing secure and efficient access to MySQL databases for LLM applications.

## Features

- 🔒 **Secure by Default**: Read-only access with optional write permissions
- ⚡ **High Performance**: Connection pooling and async operations
- 🛡️ **SQL Injection Protection**: Built-in query validation and prepared statements
- 📊 **Comprehensive Monitoring**: Structured JSON logging
- 🔧 **Flexible Configuration**: Environment variable based configuration
- 🚀 **Easy Deployment**: Install and run with `uvx`

## Installation

### Using uvx (Recommended)

```bash
# Run directly with uvx
uvx fastmcp-mysql

# With environment variables
MYSQL_HOST=localhost MYSQL_USER=myuser MYSQL_PASSWORD=mypass MYSQL_DB=mydb uvx fastmcp-mysql
```

### Using pip

```bash
pip install fastmcp-mysql
```

### From source

```bash
git clone https://github.com/jinto/fastmcp-mysql
cd fastmcp-mysql
uv sync --all-extras
```

## Configuration

Configure the server using environment variables:

### Required Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `MYSQL_USER` | Database username | - |
| `MYSQL_PASSWORD` | Database password | - |
| `MYSQL_DB` | Database name | - |

### Optional Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `MYSQL_HOST` | Database host | "127.0.0.1" |
| `MYSQL_PORT` | Database port | "3306" |
| `MYSQL_ALLOW_INSERT` | Enable INSERT queries | false |
| `MYSQL_ALLOW_UPDATE` | Enable UPDATE queries | false |
| `MYSQL_ALLOW_DELETE` | Enable DELETE queries | false |
| `MYSQL_POOL_SIZE` | Connection pool size | 10 |
| `MYSQL_QUERY_TIMEOUT` | Query timeout (ms) | 30000 |
| `MYSQL_LOG_LEVEL` | Log level (DEBUG, INFO, WARNING, ERROR) | INFO |

## Usage

### Claude Desktop Configuration

Add to your Claude Desktop configuration:

```json
{
  "mcpServers": {
    "mysql": {
      "command": "uvx",
      "args": ["fastmcp-mysql"],
      "env": {
        "MYSQL_HOST": "localhost",
        "MYSQL_PORT": "3306",
        "MYSQL_USER": "your_username",
        "MYSQL_PASSWORD": "your_password",
        "MYSQL_DB": "your_database"
      }
    }
  }
}
```

### Available Tools

#### mysql_query

Execute SQL queries against the configured MySQL database.

**Parameters:**
- `query` (string, required): The SQL query to execute
- `params` (array, optional): Query parameters for prepared statements
- `database` (string, optional): Target database (for multi-db mode)

**Example:**
```python
# Simple query
result = await mysql_query("SELECT * FROM users WHERE active = 1")

# With parameters (SQL injection safe)
result = await mysql_query(
    "SELECT * FROM users WHERE age > %s AND city = %s",
    params=[18, "New York"]
)
```

## Security

### Default Security Features

- **Read-only by default**: Write operations must be explicitly enabled
- **SQL injection prevention**: All queries use prepared statements
- **Query validation**: Dangerous patterns are detected and blocked
- **Rate limiting**: Prevents abuse through request throttling

### Enabling Write Operations

Write operations are disabled by default. Enable them with caution:

```bash
# Enable all write operations
MYSQL_ALLOW_INSERT=true \
MYSQL_ALLOW_UPDATE=true \
MYSQL_ALLOW_DELETE=true \
uvx fastmcp-mysql
```

## Development

### Setup Development Environment

```bash
# Clone the repository
git clone https://github.com/jinto/fastmcp-mysql
cd fastmcp-mysql

# Create virtual environment with uv
uv venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
uv sync --all-extras

# Install pre-commit hooks
pre-commit install
```

### Running Tests

```bash
# Run all tests
uv run pytest tests/

# Run with coverage
uv run pytest tests/ --cov=fastmcp_mysql

# Run specific test file
uv run pytest tests/unit/test_query.py

# Run integration tests only
uv run pytest tests/integration/
```

### Code Quality

```bash
# Format code
uv run black src tests

# Lint code
uv run ruff check src tests

# Type checking
uv run mypy src
```

## Architecture

The server follows Clean Architecture principles:

```
src/fastmcp_mysql/
├── __init__.py         # Package initialization
├── __main__.py         # Entry point for uvx
├── config.py           # Configuration management
├── server.py           # FastMCP server setup
├── connection.py       # Database connection management
└── tools/              # MCP tools
    ├── __init__.py
    └── query.py        # Query execution tool
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

Please ensure:
- All tests pass
- Code is formatted with black
- Type hints are added
- Documentation is updated

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Based on the [MCP Server MySQL](https://github.com/benborla/mcp-server-mysql) Node.js implementation
- Built with [FastMCP](https://github.com/jlowin/fastmcp) framework
- MySQL connectivity via [aiomysql](https://github.com/aio-libs/aiomysql)

## Support

- 📖 [Documentation](https://github.com/jinto/fastmcp-mysql/wiki)
- 🐛 [Issue Tracker](https://github.com/jinto/fastmcp-mysql/issues)
- 💬 [Discussions](https://github.com/jinto/fastmcp-mysql/discussions)