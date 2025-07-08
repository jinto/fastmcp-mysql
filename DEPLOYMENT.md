# FastMCP MySQL Server 배포 가이드

## 목차
1. [CI/CD 파이프라인 개요](#cicd-파이프라인-개요)
2. [테스트 전략](#테스트-전략)
3. [릴리즈 프로세스](#릴리즈-프로세스)
4. [모니터링 및 관찰성](#모니터링-및-관찰성)
5. [롤백 전략](#롤백-전략)

## CI/CD 파이프라인 개요

### 1. Continuous Integration (CI)

**파일**: `.github/workflows/ci.yml`

CI 파이프라인은 모든 push와 PR에서 실행되며 다음 단계를 포함합니다:

- **Linting & Formatting**: Black, Ruff, MyPy를 사용한 코드 품질 검사
- **Security Scanning**: Bandit, Safety, pip-audit를 통한 보안 취약점 스캔
- **Test Matrix**: Python 3.10-3.12, MySQL 8.0-8.2 조합으로 테스트
- **Build Validation**: 패키지 빌드 및 배포 가능성 검증

### 2. PR Validation

**파일**: `.github/workflows/pr-validation.yml`

PR 검증은 다음을 포함합니다:

- **PR 제목 검증**: Conventional Commits 형식 준수
- **PR 크기 분석**: 변경 사항이 너무 크지 않은지 확인
- **코드 품질**: 변경된 파일에 대한 집중 검사
- **테스트 커버리지**: 최소 85% 커버리지 유지
- **보안 검사**: Trivy를 통한 취약점 스캔

### 3. Release Pipeline

**파일**: `.github/workflows/release.yml`, `.github/workflows/auto-release.yml`

릴리즈 프로세스:

- **자동 버전 관리**: Conventional Commits 기반 시맨틱 버저닝
- **릴리즈 PR 생성**: 자동으로 변경 사항과 버전 업데이트 포함
- **PyPI 배포**: 태그 생성 시 자동 배포
- **GitHub Release**: 자동 생성된 changelog와 함께 릴리즈 생성

## 테스트 전략

### 1. 다중 환경 테스트

```yaml
matrix:
  python-version: ["3.10", "3.11", "3.12"]
  mysql-version: ["8.0", "8.1", "8.2"]
```

총 9개 조합의 환경에서 테스트가 실행됩니다.

### 2. 테스트 구조

```
tests/
├── unit/           # 단위 테스트
├── integration/    # 통합 테스트
├── security/       # 보안 관련 테스트
└── performance/    # 성능 벤치마크
```

### 3. 테스트 실행

```bash
# 로컬에서 전체 테스트 실행
pytest

# 특정 환경에서 테스트
docker-compose up -d mysql
pytest --mysql-host=localhost --mysql-port=3306

# 커버리지 리포트 생성
pytest --cov=fastmcp_mysql --cov-report=html
```

## 릴리즈 프로세스

### 1. 자동 릴리즈 (권장)

main 브랜치에 푸시되면 자동으로 릴리즈 필요성을 판단:

```bash
# feat: 새 기능 추가 -> minor 버전 증가
git commit -m "feat: add connection pooling support"

# fix: 버그 수정 -> patch 버전 증가
git commit -m "fix: handle connection timeout properly"

# BREAKING CHANGE -> major 버전 증가
git commit -m "feat!: change API interface"
```

### 2. 수동 릴리즈

```bash
# 태그 생성으로 릴리즈 트리거
git tag v1.2.3
git push origin v1.2.3

# 또는 GitHub Actions UI에서 수동 실행
```

### 3. 릴리즈 체크리스트

- [ ] 모든 테스트 통과
- [ ] CHANGELOG.md 업데이트
- [ ] 버전 번호 업데이트
- [ ] 보안 스캔 통과
- [ ] 문서 업데이트

## 모니터링 및 관찰성

### 1. 정기 모니터링

**파일**: `.github/workflows/monitoring.yml`

주간 실행되는 모니터링:

- **의존성 건강성 체크**: 오래된 패키지 및 보안 취약점
- **성능 베이스라인**: 성능 저하 감지
- **코드 품질 메트릭**: 복잡도, 유지보수성 지수
- **문서 커버리지**: docstring 커버리지 확인

### 2. 메트릭 수집

```python
# 애플리케이션 내 메트릭 예시
from prometheus_client import Counter, Histogram

query_counter = Counter('mysql_queries_total', 'Total MySQL queries')
query_duration = Histogram('mysql_query_duration_seconds', 'Query duration')
```

### 3. 로깅 전략

```python
import logging
import structlog

logger = structlog.get_logger()

# 구조화된 로깅
logger.info("query_executed", 
    query_type="SELECT",
    duration=0.123,
    rows_affected=42
)
```

## 롤백 전략

### 1. PyPI 롤백

```bash
# 이전 버전으로 되돌리기
pip install fastmcp-mysql==0.1.0

# 특정 커밋으로 설치
pip install git+https://github.com/jinto/fastmcp-mysql@commit_hash
```

### 2. 긴급 패치 프로세스

```bash
# 1. hotfix 브랜치 생성
git checkout -b hotfix/v1.2.4 v1.2.3

# 2. 수정 적용
# ... 코드 수정 ...

# 3. 직접 릴리즈
git tag v1.2.4
git push origin v1.2.4
```

### 3. 데이터베이스 호환성

```python
# 버전별 기능 플래그
if mysql_version >= (8, 0):
    # MySQL 8.0+ 전용 기능
    use_caching_sha2_password()
else:
    # 이전 버전 폴백
    use_mysql_native_password()
```

## 보안 고려사항

### 1. 시크릿 관리

GitHub Secrets에 저장되어야 하는 항목:
- `PYPI_API_TOKEN`: PyPI 배포용
- `CODECOV_TOKEN`: 코드 커버리지 업로드용

### 2. 의존성 관리

- Dependabot을 통한 자동 업데이트
- 주간 보안 스캔
- 취약점 발견 시 자동 PR 생성

### 3. 코드 서명

```bash
# GPG 서명된 태그 생성
git tag -s v1.2.3 -m "Release version 1.2.3"
```

## 문제 해결

### CI 실패 시

1. 로그 확인: Actions 탭에서 상세 로그 확인
2. 로컬 재현: 동일한 환경에서 테스트 실행
3. 의존성 확인: `uv.lock` 파일 업데이트 필요 여부

### 배포 실패 시

1. PyPI 토큰 확인
2. 버전 충돌 확인 (이미 존재하는 버전)
3. 패키지 메타데이터 검증

### 성능 저하 감지 시

1. 벤치마크 히스토리 확인
2. 프로파일링 실행
3. 최근 변경 사항 검토