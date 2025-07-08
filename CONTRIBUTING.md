# Contributing to FastMCP MySQL Server

Thank you for your interest in contributing to FastMCP MySQL Server! This guide will help you get started with contributing to the project.

## Table of Contents

1. [Code of Conduct](#code-of-conduct)
2. [Getting Started](#getting-started)
3. [Development Setup](#development-setup)
4. [How to Contribute](#how-to-contribute)
5. [Code Style Guide](#code-style-guide)
6. [Testing Guidelines](#testing-guidelines)
7. [Pull Request Process](#pull-request-process)
8. [Security Issues](#security-issues)

## Code of Conduct

This project and everyone participating in it is governed by our Code of Conduct. By participating, you are expected to uphold this code. Please report unacceptable behavior to the project maintainers.

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally
3. **Create a branch** for your changes
4. **Make your changes** and commit them
5. **Push to your fork** and submit a pull request

## Development Setup

### Prerequisites

- Python 3.10 or higher
- MySQL 5.7+ (8.0+ recommended)
- uv (for dependency management)
- git

### Setting Up Your Development Environment

1. **Clone the repository:**
   ```bash
   git clone https://github.com/jinto/fastmcp-mysql.git
   cd fastmcp-mysql
   ```

2. **Create a virtual environment:**
   ```bash
   uv venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   uv sync --all-extras
   ```

4. **Install pre-commit hooks:**
   ```bash
   pre-commit install
   ```

5. **Set up test database:**
   ```sql
   CREATE DATABASE fastmcp_test;
   CREATE USER 'test_user'@'localhost' IDENTIFIED BY 'test_password';
   GRANT ALL PRIVILEGES ON fastmcp_test.* TO 'test_user'@'localhost';
   FLUSH PRIVILEGES;
   ```

6. **Configure environment variables:**
   ```bash
   cp .env.example .env
   # Edit .env with your database credentials
   ```

## How to Contribute

### Reporting Bugs

Before creating bug reports, please check existing issues to avoid duplicates. When creating a bug report, include:

1. **Clear title and description**
2. **Steps to reproduce**
3. **Expected behavior**
4. **Actual behavior**
5. **Environment details** (OS, Python version, MySQL version)
6. **Relevant logs or error messages**

### Suggesting Enhancements

Enhancement suggestions are welcome! Please provide:

1. **Clear use case**
2. **Proposed solution**
3. **Alternative solutions considered**
4. **Additional context**

### Contributing Code

1. **Check existing issues** for something to work on
2. **Comment on the issue** to let others know you're working on it
3. **Follow TDD principles** - write tests first
4. **Follow the code style guide**
5. **Ensure all tests pass**
6. **Update documentation** as needed

## Code Style Guide

### Python Code Style

We follow PEP 8 with some modifications:

1. **Line length**: Maximum 100 characters (docstrings can be up to 120)
2. **Imports**: Group in order: standard library, third-party, local
3. **Type hints**: Required for all public functions
4. **Docstrings**: Google style for all public functions/classes

### Code Formatting

We use automated formatting tools:

```bash
# Format code
uv run black src tests

# Sort imports
uv run isort src tests

# Check style
uv run ruff check src tests

# Type checking
uv run mypy src
```

### Naming Conventions

- **Classes**: PascalCase (e.g., `ConnectionManager`)
- **Functions/methods**: snake_case (e.g., `execute_query`)
- **Constants**: UPPER_SNAKE_CASE (e.g., `MAX_POOL_SIZE`)
- **Private members**: Leading underscore (e.g., `_internal_method`)

### Architecture Principles

1. **Clean Architecture**: Separate business logic from infrastructure
2. **SOLID Principles**: Follow all five principles
3. **Dependency Injection**: Use interfaces and dependency injection
4. **Error Handling**: Use specific exception types

Example structure:
```python
# Interface (abstractions)
class QueryFilterInterface(ABC):
    @abstractmethod
    async def is_allowed(self, query: str) -> tuple[bool, str]:
        pass

# Implementation (concrete)
class BlacklistFilter(QueryFilterInterface):
    async def is_allowed(self, query: str) -> tuple[bool, str]:
        # Implementation
        pass

# Usage (dependency injection)
class SecurityManager:
    def __init__(self, query_filter: QueryFilterInterface):
        self.query_filter = query_filter
```

## Testing Guidelines

### Test Structure

```
tests/
├── unit/           # Unit tests (no external dependencies)
├── integration/    # Integration tests (may use database)
└── security/       # Security-specific tests
```

### Writing Tests

1. **Follow TDD**: Write tests before implementation
2. **Use descriptive names**: `test_should_reject_sql_injection_attempt`
3. **Arrange-Act-Assert pattern**:
   ```python
   def test_connection_pool_returns_connection():
       # Arrange
       pool = ConnectionPool(size=5)
       
       # Act
       connection = await pool.get_connection()
       
       # Assert
       assert connection is not None
       assert pool.active_connections == 1
   ```

4. **Use fixtures** for common setup:
   ```python
   @pytest.fixture
   async def connection_manager():
       manager = ConnectionManager(test_config)
       yield manager
       await manager.close()
   ```

5. **Test edge cases** and error conditions
6. **Mock external dependencies** in unit tests
7. **Use real database** for integration tests

### Running Tests

```bash
# Run all tests
uv run pytest

# Run with coverage
uv run pytest --cov=fastmcp_mysql --cov-report=html

# Run specific test file
uv run pytest tests/unit/test_connection.py

# Run specific test
uv run pytest tests/unit/test_connection.py::test_connection_timeout

# Run tests in parallel
uv run pytest -n auto

# Run only unit tests
uv run pytest tests/unit/

# Run with verbose output
uv run pytest -v
```

### Test Coverage

- Minimum coverage: 80%
- Critical modules (security, connection): 90%+
- New features must include tests
- Coverage report in pull requests

## Pull Request Process

### Before Submitting

1. **Ensure all tests pass**
2. **Update documentation**
3. **Run linting and formatting**
4. **Update CHANGELOG.md** if applicable
5. **Rebase on latest main branch**

### PR Checklist

- [ ] Tests pass locally
- [ ] Code follows style guidelines
- [ ] Documentation updated
- [ ] Type hints added
- [ ] No security vulnerabilities
- [ ] Performance impact considered
- [ ] Breaking changes documented

### PR Title Format

Use conventional commit format:
- `feat: Add connection pooling`
- `fix: Handle connection timeout correctly`
- `docs: Update API reference`
- `test: Add security injection tests`
- `refactor: Extract query validator`
- `perf: Optimize cache lookup`
- `chore: Update dependencies`

### PR Description Template

```markdown
## Description
Brief description of changes

## Motivation and Context
Why is this change needed?

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Manual testing completed

## Screenshots (if applicable)
Add screenshots for UI changes

## Additional Notes
Any additional information
```

### Review Process

1. **Automated checks** must pass
2. **Code review** by at least one maintainer
3. **Address feedback** promptly
4. **Squash commits** if requested
5. **Maintainer merges** when approved

## Security Issues

### Reporting Security Vulnerabilities

**DO NOT** create public issues for security vulnerabilities. Instead:

1. Email security details to: security@example.com (update with actual email)
2. Include:
   - Description of vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### Security Review Checklist

When contributing security-related code:

- [ ] No hardcoded credentials
- [ ] Input validation implemented
- [ ] SQL injection prevention verified
- [ ] Rate limiting considered
- [ ] Logging doesn't expose sensitive data
- [ ] Error messages are safe
- [ ] Dependencies are secure

## Development Tips

### Debugging

1. **Enable debug logging:**
   ```bash
   export MYSQL_LOG_LEVEL=DEBUG
   ```

2. **Use debugger:**
   ```python
   import pdb; pdb.set_trace()
   # or
   breakpoint()  # Python 3.7+
   ```

3. **Test specific scenarios:**
   ```bash
   pytest -k "sql_injection" -v
   ```

### Performance Testing

1. **Profile code:**
   ```python
   import cProfile
   cProfile.run('await main()')
   ```

2. **Benchmark queries:**
   ```python
   import timeit
   time = timeit.timeit(lambda: query(), number=1000)
   ```

### Common Issues

1. **Import errors**: Ensure you're in the virtual environment
2. **Database connection**: Check MySQL is running and credentials are correct
3. **Test failures**: Update test database schema
4. **Type errors**: Run `mypy` to check type hints

## Questions?

Feel free to:
- Open an issue for questions
- Join our discussions
- Contact maintainers

Thank you for contributing to FastMCP MySQL Server! 🎉