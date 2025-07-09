# Changelog

All notable changes to FastMCP MySQL Server will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Comprehensive API documentation
- Additional example scripts for common use cases
- Performance optimization guide

## [0.1.2] - 2025-01-09

### Fixed
- Fixed SpanKind import in observability module
- Fixed AsyncMock usage in tests for Python 3.13
- Applied comprehensive code formatting with ruff
- Fixed deprecated type hints (Optional[X] to X | None)
- Fixed import ordering and removed unused imports
- Fixed trailing whitespace and missing newlines
- Fixed CI/CD pipeline issues with uv/uvx commands

### Changed
- Upgraded GitHub Actions: artifact actions v3→v4, CodeQL v2→v3
- Modernized type hints throughout the codebase
- Improved code consistency and formatting

## [0.1.1] - 2025-01-09

### Added
- Database selection is now optional - can connect to MySQL server without specifying a database
- Support for `USE` command to switch databases after connection
- Support for `SHOW` commands (SHOW DATABASES, SHOW TABLES, etc.)
- PyPI publishing guide (PUBLISH.md)
- Claude MCP CLI usage examples in README

### Changed
- `MYSQL_DB` environment variable is now optional
- Updated query validator to allow USE and SHOW commands
- Enhanced README with more installation examples

### Fixed
- Connection issues when database is not specified

## [0.1.0] - 2025-01-09

### Added
- Initial release of FastMCP MySQL Server
- Core MySQL query execution functionality
- Comprehensive security features:
  - SQL injection detection and prevention
  - Query filtering (blacklist/whitelist/combined modes)
  - Rate limiting (Token Bucket, Sliding Window, Fixed Window)
- Performance optimization:
  - Connection pooling
  - Query result caching (TTL and LRU)
  - Streaming support for large datasets
  - Pagination support
- Monitoring and observability:
  - Structured JSON logging
  - Metrics collection (queries, connections, cache, errors)
  - Health check system
  - Prometheus metrics export
- CI/CD pipeline with GitHub Actions
- Comprehensive test coverage
- Clean Architecture implementation
- FastMCP framework integration
- CONTRIBUTING.md with development guidelines

### Security
- Read-only access by default
- Optional write permissions (INSERT/UPDATE/DELETE)
- DDL operations blocked
- Advanced SQL injection pattern detection
- Parameter validation and sanitization

---

## Version History Legend

### Added
New features or capabilities

### Changed
Changes in existing functionality

### Deprecated
Features that will be removed in future versions

### Removed
Features that have been removed

### Fixed
Bug fixes

### Security
Security improvements or fixes

---

## Upgrade Guide

### From 0.1.0 to 0.1.1

1. **Database Configuration**
   - `MYSQL_DB` is now optional
   - If not specified, connect to MySQL server without selecting a database
   - Use `USE database_name` command to switch databases

### From 0.9.0 to 1.0.0

1. **Security Configuration**
   - Add new security environment variables:
     ```bash
     MYSQL_ENABLE_SECURITY=true
     MYSQL_FILTER_MODE=blacklist
     MYSQL_RATE_LIMIT_RPM=60
     ```

2. **Connection Pool**
   - Configure pool size: `MYSQL_POOL_SIZE=10`

3. **Caching**
   - Enable caching: `MYSQL_CACHE_ENABLED=true`
   - Configure cache: `MYSQL_CACHE_MAX_SIZE=1000`

4. **API Changes**
   - Query result format now includes `metadata` field
   - New tools available: `mysql_health`, `mysql_metrics`

---

## Roadmap

### Version 1.1.0 (Planned)
- Transaction support
- Multi-database mode
- Query result streaming for large datasets
- Schema introspection tools

### Version 1.2.0 (Planned)
- Query builder interface
- Advanced caching strategies
- Performance analytics dashboard
- Migration tools

### Version 2.0.0 (Future)
- GraphQL support
- Real-time query monitoring
- Multi-region support
- Advanced security features (RBAC)

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.