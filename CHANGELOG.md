# Changelog

All notable changes to FastMCP MySQL Server will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Comprehensive API documentation
- Additional example scripts for common use cases
- Performance optimization guide
- CONTRIBUTING.md with development guidelines

## [1.0.0] - 2024-01-15

### Added
- Initial release of FastMCP MySQL Server
- Core query execution tool (`mysql_query`)
- Comprehensive security features:
  - SQL injection detection and prevention
  - Query filtering (blacklist/whitelist modes)
  - Rate limiting with multiple algorithms
  - Security event logging
- Connection pooling for improved performance
- Environment-based configuration
- Clean Architecture implementation
- Observability features:
  - Health checks (`mysql_health`)
  - Metrics collection (`mysql_metrics`)
  - Prometheus metrics export (`mysql_metrics_prometheus`)
  - Structured JSON logging
  - OpenTelemetry tracing support
- Query result caching with LRU eviction
- Support for prepared statements
- Comprehensive test suite (85%+ coverage)
- Docker support
- Claude Desktop integration

### Security
- Read-only access by default
- Optional write permissions (INSERT/UPDATE/DELETE)
- DDL operations blocked
- Advanced SQL injection pattern detection
- Parameter validation and sanitization

## [0.9.0] - 2024-01-08 (Pre-release)

### Added
- Basic FastMCP server structure
- MySQL connection management using aiomysql
- Environment variable configuration
- Basic query validation
- Initial test framework

### Changed
- Migrated from Node.js implementation to Python
- Adopted FastMCP framework

## [0.1.0] - 2024-01-01 (Concept)

### Added
- Project initialization
- Basic requirements gathering
- Architecture design based on mcp-server-mysql

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