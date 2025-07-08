# FastMCP MySQL Server 관찰성(Observability) 가이드

## 개요

FastMCP MySQL Server는 포괄적인 관찰성 시스템을 제공하여 애플리케이션의 상태, 성능, 문제를 모니터링할 수 있습니다.

## 1. 로깅 시스템

### 1.1 Enhanced JSON Formatter

구조화된 JSON 로깅으로 로그 분석 및 검색이 용이합니다:

```python
{
  "timestamp": "2024-01-15T10:30:45.123Z",
  "level": "INFO",
  "logger": "fastmcp_mysql",
  "message": "Query executed successfully",
  "location": {
    "file": "query.py",
    "line": 123,
    "function": "execute"
  },
  "context": {
    "request_id": "req-123",
    "user_id": "user-456",
    "session_id": "session-789"
  },
  "metrics": {
    "duration_ms": 45.2,
    "rows_affected": 10
  }
}
```

### 1.2 로그 로테이션

자동 로그 로테이션으로 디스크 공간 관리:

```bash
# 환경 변수 설정
export MYSQL_LOG_DIR=/var/log/fastmcp-mysql
export MYSQL_ENABLE_FILE_LOGGING=true

# 생성되는 로그 파일
# - fastmcp-mysql.log (모든 로그)
# - fastmcp-mysql-errors.log (에러만)
# - 각 파일은 100MB 도달 시 로테이션
# - 최대 10개 백업 파일 유지
```

### 1.3 컨텍스트 로깅

요청 컨텍스트를 자동으로 포함하는 로깅:

```python
from fastmcp_mysql.observability import request_context, ContextLogger

logger = ContextLogger(logging.getLogger(__name__))

with request_context(user_id="user123", session_id="session456"):
    logger.info("Processing user request")
    # 자동으로 user_id와 session_id가 로그에 포함됨
```

## 2. 메트릭 수집 시스템

### 2.1 쿼리 메트릭

```python
# 수집되는 메트릭
- total_queries: 전체 쿼리 수
- successful_queries: 성공한 쿼리 수
- failed_queries: 실패한 쿼리 수
- query_duration_ms: 쿼리 실행 시간 (p50, p90, p95, p99)
- queries_by_type: 타입별 쿼리 수 (SELECT, INSERT, UPDATE, DELETE)
- slow_queries: 느린 쿼리 목록 (기본 1초 이상)
```

### 2.2 연결 풀 메트릭

```python
# 수집되는 메트릭
- total_connections: 전체 연결 수
- active_connections: 활성 연결 수
- idle_connections: 유휴 연결 수
- utilization_percent: 연결 풀 사용률
- avg_wait_time_ms: 평균 연결 대기 시간
- connection_errors: 연결 오류 수
```

### 2.3 캐시 메트릭

```python
# 수집되는 메트릭
- hits: 캐시 히트 수
- misses: 캐시 미스 수
- hit_rate_percent: 캐시 히트율
- evictions: 캐시 제거 수
- current_size: 현재 캐시 크기
- utilization_percent: 캐시 사용률
```

### 2.4 에러 메트릭

```python
# 수집되는 메트릭
- errors_by_type: 타입별 에러 수
- error_rate_per_minute: 분당 에러율
- recent_errors: 최근 에러 목록 (최대 1000개)
```

## 3. Health Check 시스템

### 3.1 Health Check 엔드포인트

```python
# Health check 도구 사용
result = await server.mysql_health()

# 응답 형식
{
  "status": "healthy",  # healthy, degraded, unhealthy
  "timestamp": "2024-01-15T10:30:45.123Z",
  "version": "1.0.0",
  "components": [
    {
      "name": "database",
      "status": "healthy",
      "message": "Database is healthy",
      "details": {
        "pool_metrics": {...},
        "utilization_percent": 25.0
      },
      "check_duration_ms": 5.2
    },
    ...
  ],
  "summary": {
    "total_components": 4,
    "healthy": 3,
    "degraded": 1,
    "unhealthy": 0
  }
}
```

### 3.2 컴포넌트별 Health Check

1. **Database Health**
   - 연결 가능 여부
   - 연결 풀 사용률 (90% 이상 시 degraded)

2. **Query Performance**
   - 쿼리 에러율 (10% 이상 시 unhealthy)
   - 느린 쿼리 비율 (p95 > 1초 시 degraded)

3. **Cache Health**
   - 캐시 히트율 (50% 미만 시 degraded)
   - 캐시 풀 여부

4. **Error Rates**
   - 분당 에러 수 (10개 이상 시 degraded)

### 3.3 커스텀 Health Check

```python
from fastmcp_mysql.observability import HealthChecker, ComponentHealth, HealthStatus

async def check_custom_component() -> ComponentHealth:
    # 커스텀 체크 로직
    if some_condition:
        return ComponentHealth(
            name="custom_service",
            status=HealthStatus.HEALTHY,
            message="Custom service is healthy"
        )
    else:
        return ComponentHealth(
            name="custom_service",
            status=HealthStatus.UNHEALTHY,
            message="Custom service is down"
        )

# Health checker에 등록
health_checker.register_check("custom_service", check_custom_component)
```

## 4. 분산 추적 (Distributed Tracing)

### 4.1 OpenTelemetry 통합

```bash
# 환경 변수 설정
export MYSQL_ENABLE_TRACING=true
export MYSQL_OTLP_ENDPOINT=localhost:4317
```

### 4.2 자동 추적

모든 쿼리는 자동으로 추적됩니다:

```python
@trace_query
async def mysql_query(...):
    # 자동으로 span 생성
    # - operation_name: "query_execution"
    # - attributes: db.statement, db.type, duration_ms
```

### 4.3 수동 추적

```python
from fastmcp_mysql.observability import TracingManager, SpanKind

manager = get_tracing_manager()

async with manager.span("custom_operation", SpanKind.INTERNAL) as span:
    span.set_attribute("custom_key", "custom_value")
    span.add_event("important_event", {"detail": "value"})
    
    # 작업 수행
    result = await do_something()
    
    span.set_attribute("result_size", len(result))
```

## 5. Prometheus 메트릭 노출

### 5.1 메트릭 엔드포인트

```python
# Prometheus 형식으로 메트릭 가져오기
prometheus_metrics = await server.mysql_metrics_prometheus()

# 출력 예시
# HELP mysql_queries_total Total number of queries
# TYPE mysql_queries_total counter
mysql_queries_total 1234

# HELP mysql_query_duration_ms Query duration in milliseconds
# TYPE mysql_query_duration_ms summary
mysql_query_duration_ms{quantile="50"} 10.5
mysql_query_duration_ms{quantile="90"} 45.2
mysql_query_duration_ms{quantile="95"} 89.7
mysql_query_duration_ms{quantile="99"} 234.1
```

### 5.2 Grafana 대시보드

Prometheus 메트릭을 사용한 Grafana 대시보드 예시:

```promql
# 쿼리 성공률
(rate(mysql_queries_successful[5m]) / rate(mysql_queries_total[5m])) * 100

# 연결 풀 사용률
mysql_connection_pool_utilization

# 캐시 히트율
mysql_cache_hit_rate

# 에러율
rate(mysql_errors_total[1m])
```

## 6. 모범 사례

### 6.1 로깅 레벨 설정

```bash
# 프로덕션
export MYSQL_LOG_LEVEL=INFO

# 개발/디버깅
export MYSQL_LOG_LEVEL=DEBUG
```

### 6.2 성능 임계값 조정

```python
# Health check 임계값 설정
health_checker.set_threshold("query_error_rate", 5.0)  # 5% 에러율
health_checker.set_threshold("connection_utilization", 80.0)  # 80% 사용률
health_checker.set_threshold("slow_query_threshold_ms", 500.0)  # 500ms
```

### 6.3 메트릭 수집 주기

```bash
# 메트릭 수집 주기 설정 (초)
export MYSQL_METRICS_EXPORT_INTERVAL=30  # 30초마다
```

### 6.4 알림 설정

```python
# 메트릭 콜백 등록
def alert_on_high_error_rate(metrics: Dict[str, Any]):
    error_rate = metrics["query"]["error_rate"]
    if error_rate > 10.0:
        send_alert(f"High query error rate: {error_rate}%")

metrics_collector.register_callback(alert_on_high_error_rate)
```

## 7. 문제 해결

### 7.1 느린 쿼리 분석

```python
# 느린 쿼리 확인
metrics = await server.mysql_metrics()
slow_queries = metrics["query"]["slow_queries"]

for query in slow_queries:
    print(f"Query: {query['query']}")
    print(f"Duration: {query['duration_ms']}ms")
    print(f"Time: {query['timestamp']}")
```

### 7.2 연결 풀 부족

```python
# 연결 풀 상태 확인
health = await server.mysql_health()
db_component = next(c for c in health["components"] if c["name"] == "database")

if db_component["status"] == "degraded":
    pool_metrics = db_component["details"]["pool_metrics"]
    print(f"Active connections: {pool_metrics['active_connections']}")
    print(f"Pool size: {pool_metrics['max_size']}")
    # 풀 크기 증가 필요
```

### 7.3 캐시 효율성

```python
# 캐시 성능 확인
metrics = await server.mysql_metrics()
cache = metrics["cache"]

if cache["hit_rate_percent"] < 50:
    print(f"Low cache hit rate: {cache['hit_rate_percent']}%")
    print(f"Consider adjusting cache size or TTL")
```

## 8. 통합 예제

완전한 관찰성 설정 예제:

```python
import os
from pathlib import Path

# 환경 변수 설정
os.environ.update({
    # 로깅
    "MYSQL_LOG_LEVEL": "INFO",
    "MYSQL_LOG_DIR": "/var/log/fastmcp-mysql",
    "MYSQL_ENABLE_FILE_LOGGING": "true",
    
    # 메트릭
    "MYSQL_ENABLE_METRICS": "true",
    "MYSQL_SLOW_QUERY_THRESHOLD_MS": "1000",
    
    # Health checks
    "MYSQL_ENABLE_HEALTH_CHECKS": "true",
    
    # 추적
    "MYSQL_ENABLE_TRACING": "true",
    "MYSQL_OTLP_ENDPOINT": "localhost:4317",
})

# 서버 생성
from fastmcp_mysql.server_enhanced import create_enhanced_server

server = await create_enhanced_server()

# 메트릭 모니터링
import asyncio

async def monitor():
    while True:
        metrics = await server.mysql_metrics()
        health = await server.mysql_health()
        
        print(f"Status: {health['status']}")
        print(f"Query rate: {metrics['query']['total']} queries")
        print(f"Error rate: {metrics['query']['error_rate']}%")
        
        await asyncio.sleep(60)

# 백그라운드에서 모니터링 실행
asyncio.create_task(monitor())
```