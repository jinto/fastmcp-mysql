# FastMCP MySQL Server Features

## 개요
이 문서는 [mcp-server-mysql](https://github.com/benborla/mcp-server-mysql)의 모든 기능을 [FastMCP](https://gofastmcp.com/)로 포팅하기 위한 기능 명세서입니다.

## 구현 상태

### 1. 데이터베이스 상호작용
- ✅ MySQL 데이터베이스에 대한 읽기 전용 접근 (기본값)
- ✅ 선택적 쓰기 작업 지원 (INSERT, UPDATE, DELETE)
- ✅ SQL 쿼리 실행
- ⏳ 트랜잭션 관리 (개발 예정)
- ✅ Prepared Statement를 통한 안전한 파라미터 처리
- ⏳ 스키마 검사 및 메타데이터 조회 (개발 예정)

### 2. 도구 및 메서드

#### mysql_query 도구 (구현 완료)
- **기능**: SQL 쿼리 실행
- **매개변수**:
  - `query`: 실행할 SQL 쿼리
  - `params`: 쿼리 파라미터 (옵션)
  - `database`: 대상 데이터베이스 (옵션, 멀티 DB 모드)
- **반환값**: 
  - 성공 시: `{"success": true, "data": [...], "message": "..."}`
  - 실패 시: `{"success": false, "error": "...", "message": "..."}`

### 3. 보안 기능
- ✅ SQL 인젝션 방지 (Prepared Statement)
- ✅ SQL 인젝션 고급 패턴 감지 (URL/Unicode/Hex 인코딩 탐지)
- ✅ 쿼리 유형 검증 (DDL 차단)
- ✅ 권한 기반 쓰기 작업 제어
- ✅ 쿼리 화이트리스트/블랙리스트
- ✅ 요청 속도 제한 (Token Bucket, Sliding Window, Fixed Window)
- ⏳ 쿼리 복잡도 분석 (개발 예정)
- ✅ SSL/TLS 연결 지원

### 4. 성능 최적화
- ✅ 연결 풀링 (Connection Pooling)
- ⏳ 쿼리 결과 캐싱 (개발 예정)
- ⏳ 대용량 결과 세트 스트리밍 (개발 예정)
- ✅ 쿼리 타임아웃 설정
- ⏳ 쿼리 실행 계획 분석 (개발 예정)

### 5. 모니터링 기능
- ✅ 구조화된 JSON 로깅
- ✅ 연결 풀 메트릭
- ✅ 오류 로깅
- ✅ 헬스 체크 기능
- ⏳ 쿼리 실행 통계 (개발 예정)

## 구성 옵션

### 필수 환경 변수
| 변수명 | 설명 | 기본값 |
|--------|------|--------|
| `MYSQL_HOST` | 데이터베이스 호스트 | "127.0.0.1" |
| `MYSQL_PORT` | 데이터베이스 포트 | 3306 |
| `MYSQL_USER` | 데이터베이스 사용자명 | - |
| `MYSQL_PASSWORD` | 데이터베이스 비밀번호 | - |
| `MYSQL_DB` | 대상 데이터베이스 이름 | - |

### 쓰기 작업 플래그
| 변수명 | 설명 | 기본값 |
|--------|------|--------|
| `MYSQL_ALLOW_INSERT` | INSERT 작업 허용 | false |
| `MYSQL_ALLOW_UPDATE` | UPDATE 작업 허용 | false |
| `MYSQL_ALLOW_DELETE` | DELETE 작업 허용 | false |

### 성능 관련 변수
| 변수명 | 설명 | 기본값 |
|--------|------|--------|
| `MYSQL_POOL_SIZE` | 연결 풀 크기 | 10 |
| `MYSQL_QUERY_TIMEOUT` | 쿼리 타임아웃 (ms) | 30000 |
| `MYSQL_LOG_LEVEL` | 로그 레벨 (DEBUG, INFO, WARNING, ERROR, CRITICAL) | INFO |
| `MYSQL_STREAMING_CHUNK_SIZE` | 스트리밍 쿼리 청크 크기 | 1000 |
| `MYSQL_PAGINATION_DEFAULT_SIZE` | 기본 페이지 크기 | 10 |
| `MYSQL_PAGINATION_MAX_SIZE` | 최대 페이지 크기 | 1000 |

### 캐시 관련 변수
| 변수명 | 설명 | 기본값 |
|--------|------|--------|
| `MYSQL_CACHE_ENABLED` | 쿼리 결과 캐싱 활성화 | true |
| `MYSQL_CACHE_MAX_SIZE` | 최대 캐시 항목 수 | 1000 |
| `MYSQL_CACHE_TTL` | 캐시 TTL (밀리초) | 60000 |
| `MYSQL_CACHE_EVICTION_POLICY` | 캐시 제거 정책 (lru/ttl/fifo) | lru |
| `MYSQL_CACHE_CLEANUP_INTERVAL` | 캐시 정리 간격 (초) | 60.0 |
| `MYSQL_CACHE_INVALIDATION_MODE` | 캐시 무효화 전략 (aggressive/conservative/targeted) | aggressive |

### 보안 관련 변수
| 변수명 | 설명 | 기본값 |
|--------|------|--------|
| `MYSQL_ENABLE_SECURITY` | 모든 보안 기능 활성화 | true |
| `MYSQL_ENABLE_INJECTION_DETECTION` | SQL 인젝션 탐지 활성화 | true |
| `MYSQL_ENABLE_RATE_LIMITING` | 속도 제한 활성화 | true |
| `MYSQL_FILTER_MODE` | 필터 모드 (blacklist/whitelist/combined) | blacklist |
| `MYSQL_RATE_LIMIT_RPM` | 분당 요청 제한 | 60 |
| `MYSQL_RATE_LIMIT_BURST` | 버스트 크기 | 10 |
| `MYSQL_RATE_LIMIT_ALGORITHM` | 속도 제한 알고리즘 (token_bucket/sliding_window/fixed_window) | token_bucket |
| `MYSQL_MAX_QUERY_LENGTH` | 최대 쿼리 길이 (문자) | 10000 |
| `MYSQL_MAX_PARAMETER_LENGTH` | 최대 파라미터 길이 | 1000 |
| `MYSQL_LOG_SECURITY_EVENTS` | 보안 이벤트 로깅 | true |
| `MYSQL_LOG_REJECTED_QUERIES` | 거부된 쿼리 로깅 | true |
| `MYSQL_AUDIT_ALL_QUERIES` | 모든 쿼리 감사 (성능 영향) | false |

## 멀티 데이터베이스 모드
- ⏳ 여러 데이터베이스 동시 쿼리 지원 (개발 예정)
- ⏳ 완전한 테이블 이름 지정 필요 (개발 예정)
- ⏳ 스키마별 권한 설정 가능 (개발 예정)

## 구현 진행 상황

### Phase 1: MVP (완료) ✅
- ✅ FastMCP 서버 초기화
- ✅ MySQL 연결 관리자 (aiomysql)
- ✅ 환경 변수 기반 설정
- ✅ `mysql_query` 도구 구현
- ✅ 기본 보안 (쿼리 검증, DDL 차단)
- ✅ 연결 풀링
- ✅ JSON 구조화 로깅
- ✅ 단위/통합 테스트 (85% 커버리지)

### Phase 2: 보안 강화 (완료) ✅
- ✅ SQL 인젝션 고급 패턴 감지
- ✅ 쿼리 화이트리스트/블랙리스트
- ✅ 속도 제한 (Rate Limiting)
- ✅ Clean Architecture 기반 보안 모듈
- ✅ 보안 테스트 (52개 테스트, 100% 통과)
- ⏳ 쿼리 복잡도 분석

### Phase 3: 성능 최적화 (계획)
- ⏳ 쿼리 결과 캐싱
- ⏳ 대용량 결과 스트리밍
- ⏳ 쿼리 실행 계획 분석

### Phase 4: 고급 기능 (계획)
- ⏳ 트랜잭션 관리
- ⏳ 멀티 데이터베이스 지원
- ⏳ 스키마 검사 도구
- ⏳ 모니터링 대시보드

## 설치 및 실행

### uvx를 사용한 실행
```bash
# 직접 실행
uvx fastmcp-mysql

# 환경 변수와 함께 실행
MYSQL_HOST=localhost MYSQL_USER=myuser MYSQL_PASSWORD=mypass MYSQL_DB=mydb uvx fastmcp-mysql

# 쓰기 작업 활성화와 함께 실행
MYSQL_ALLOW_INSERT=true MYSQL_ALLOW_UPDATE=true uvx fastmcp-mysql
```

### Claude Desktop 설정
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
        "MYSQL_DB": "your_database",
        "MYSQL_ALLOW_INSERT": "false",
        "MYSQL_ALLOW_UPDATE": "false",
        "MYSQL_ALLOW_DELETE": "false",
        "MYSQL_ENABLE_SECURITY": "true",
        "MYSQL_FILTER_MODE": "blacklist",
        "MYSQL_RATE_LIMIT_RPM": "60"
      }
    }
  }
}
```

## 예상 구현 예제

```python
from fastmcp import FastMCP
import aiomysql
from typing import Optional, Dict, Any, List
import os

mcp = FastMCP("MySQL Server")

# 환경 변수 로드
MYSQL_CONFIG = {
    "host": os.getenv("MYSQL_HOST", "127.0.0.1"),
    "port": int(os.getenv("MYSQL_PORT", "3306")),
    "user": os.getenv("MYSQL_USER"),
    "password": os.getenv("MYSQL_PASSWORD"),
    "db": os.getenv("MYSQL_DB"),
}

# 쓰기 작업 권한
ALLOW_INSERT = os.getenv("MYSQL_ALLOW_INSERT", "false").lower() == "true"
ALLOW_UPDATE = os.getenv("MYSQL_ALLOW_UPDATE", "false").lower() == "true"
ALLOW_DELETE = os.getenv("MYSQL_ALLOW_DELETE", "false").lower() == "true"

@mcp.tool
async def mysql_query(
    query: str,
    params: Optional[List[Any]] = None,
    database: Optional[str] = None
) -> Dict[str, Any]:
    """Execute MySQL query with optional parameters"""
    # 구현 로직
    pass
```

## 테스트 요구사항
- ✅ 단위 테스트 작성
- ✅ 통합 테스트
- ✅ 보안 테스트
- ✅ 성능 테스트
- ✅ 테스트 데이터베이스 설정

## 호환성
- Python 3.10+
- MySQL 5.7+ (권장: 8.0+)
- FastMCP 최신 버전

## 향후 개선 사항
- GraphQL 지원 추가
- 더 많은 데이터베이스 엔진 지원
- 고급 쿼리 빌더
- 시각적 스키마 탐색기