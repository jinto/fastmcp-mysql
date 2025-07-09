# 📦 FastMCP MySQL 패키지 배포 가이드

이 문서는 FastMCP MySQL 패키지를 PyPI에 배포하는 전체 과정을 설명합니다.

## 📋 사전 준비

### 1. PyPI 계정 설정
1. [PyPI](https://pypi.org/account/register/)에서 계정 생성
2. [API 토큰 생성](https://pypi.org/manage/account/token/)
   - Token name: `fastmcp-mysql`
   - Scope: `Entire account` (첫 배포) 또는 `Project: fastmcp-mysql` (이후)
3. 토큰을 안전한 곳에 저장 (형식: `pypi-AgEIcHlwaS5vcmc...`)

### 2. TestPyPI 계정 설정 (선택사항, 권장)
1. [TestPyPI](https://test.pypi.org/account/register/)에서 계정 생성
2. [TestPyPI API 토큰 생성](https://test.pypi.org/manage/account/token/)

### 3. GitHub Secrets 설정
GitHub 저장소의 Settings → Secrets and variables → Actions에서:
- `PYPI_API_TOKEN`: PyPI API 토큰 추가
- `TEST_PYPI_API_TOKEN`: TestPyPI API 토큰 추가 (선택사항)

## 🚀 배포 프로세스

### 1. 버전 업데이트

```bash
# src/fastmcp_mysql/__init__.py 에서 버전 업데이트
# 현재: __version__ = "0.1.0"
# 변경: __version__ = "0.2.0"  # 예시
```

### 2. 변경사항 문서화

```bash
# CHANGELOG.md 업데이트
# 새 버전의 변경사항 추가
```

### 3. 코드 품질 확인

```bash
# 린팅
uv run ruff check src tests
uv run black --check src tests
uv run mypy src

# 테스트 실행
uv run pytest

# 보안 검사
uvx bandit -r src/ -ll
```

### 4. 패키지 빌드

```bash
# 이전 빌드 제거
rm -rf dist/

# 새로 빌드
uvx --from build pyproject-build .

# 빌드 결과 확인
ls -la dist/
# 출력:
# fastmcp_mysql-0.1.0-py3-none-any.whl
# fastmcp_mysql-0.1.0.tar.gz
```

### 5. 패키지 검증

```bash
# 패키지 무결성 확인
uvx twine check dist/*

# 로컬 설치 테스트
uv pip install dist/*.whl

# 설치 확인
python -c "from fastmcp_mysql import __version__; print(__version__)"

# 제거
uv pip uninstall fastmcp-mysql
```

### 6. TestPyPI에 업로드 (권장)

```bash
# TestPyPI에 업로드
uvx twine upload --repository testpypi dist/*

# 또는 환경변수 사용
export TWINE_USERNAME=__token__
export TWINE_PASSWORD=<your-test-pypi-token>
uvx twine upload --repository testpypi dist/*

# TestPyPI에서 설치 테스트
pip install --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ fastmcp-mysql

# 기능 테스트
MYSQL_HOST=localhost MYSQL_USER=test MYSQL_PASSWORD=test MYSQL_DB=test fastmcp-mysql

# 테스트 후 제거
pip uninstall fastmcp-mysql
```

### 7. Git 커밋 및 태그

```bash
# 모든 변경사항 커밋
git add -A
git commit -m "chore: release v0.1.0"

# 태그 생성 (v 접두사 사용)
git tag -a v0.1.0 -m "Release version 0.1.0"

# 또는 더 자세한 태그 메시지
git tag -a v0.1.0 -m "Release version 0.1.0

- Feature: 기능 추가 내용
- Fix: 버그 수정 내용
- Docs: 문서 개선 내용"

# 태그 확인
git tag -l
git show v0.1.0
```

### 8. PyPI에 수동 업로드

```bash
# PyPI에 업로드
uvx twine upload dist/*

# 또는 환경변수 사용
export TWINE_USERNAME=__token__
export TWINE_PASSWORD=<your-pypi-token>
uvx twine upload dist/*
```

### 9. GitHub에 푸시 (자동 배포)

```bash
# 코드와 태그를 함께 푸시
git push origin main
git push origin v0.1.0

# 또는 한 번에
git push origin main --tags
```

GitHub Actions가 자동으로:
1. 태그 감지
2. 패키지 빌드
3. PyPI 업로드
4. GitHub Release 생성

### 10. 배포 확인

```bash
# PyPI에서 설치
pip install fastmcp-mysql

# 버전 확인
pip show fastmcp-mysql

# 기능 테스트
MYSQL_HOST=localhost MYSQL_USER=test MYSQL_PASSWORD=test MYSQL_DB=test fastmcp-mysql
```

## 📝 버전 관리 규칙

[Semantic Versioning](https://semver.org/)을 따릅니다:

- **MAJOR** (1.0.0): 호환되지 않는 API 변경
- **MINOR** (0.1.0): 하위 호환되는 기능 추가
- **PATCH** (0.0.1): 하위 호환되는 버그 수정

### 프리릴리즈 버전
```bash
# 알파 버전
git tag v0.2.0a1

# 베타 버전
git tag v0.2.0b1

# 릴리즈 후보
git tag v0.2.0rc1
```

## 🚨 문제 해결

### 업로드 실패 시

1. **인증 오류**
   ```bash
   # 토큰 확인
   echo $TWINE_PASSWORD
   
   # .pypirc 사용
   uvx twine upload --config-file ~/.pypirc dist/*
   ```

2. **버전 충돌**
   - PyPI는 같은 버전을 재업로드할 수 없음
   - 버전 번호를 올리고 다시 빌드

3. **파일 누락**
   ```bash
   # MANIFEST.in 확인
   # pyproject.toml의 include 설정 확인
   ```

### 롤백이 필요한 경우

1. PyPI에서는 버전을 삭제할 수 없음 (yank만 가능)
2. 새 패치 버전으로 수정사항 배포
3. 중요한 경우 PyPI 지원팀에 문의

## 🔄 자동화된 배포 (GitHub Actions)

`.github/workflows/release.yml`이 설정되어 있어, 태그 푸시 시 자동으로:

1. 패키지 빌드
2. PyPI 업로드
3. GitHub Release 생성

필요한 설정:
- GitHub Secrets에 `PYPI_API_TOKEN` 추가

## 📌 체크리스트

배포 전 확인사항:

- [ ] 버전 번호 업데이트 (`__init__.py`)
- [ ] CHANGELOG.md 업데이트
- [ ] 모든 테스트 통과
- [ ] 문서 최신화
- [ ] 의존성 버전 확인
- [ ] 라이선스 파일 존재
- [ ] README.md 최신화

## 🔗 유용한 링크

- [PyPI 프로젝트 페이지](https://pypi.org/project/fastmcp-mysql/)
- [TestPyPI 프로젝트 페이지](https://test.pypi.org/project/fastmcp-mysql/)
- [GitHub Releases](https://github.com/jinto/fastmcp-mysql/releases)
- [패키지 통계](https://pepy.tech/project/fastmcp-mysql)