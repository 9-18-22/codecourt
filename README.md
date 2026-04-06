# Static Verifier Pipeline

> **"이거 진짜 결함 맞아요?"** — 정적 분석 도구가 탐지한 결함을 자동으로 검증하는 end-to-end 파이프라인

졸업프로젝트: 이가은 · 조은주 · 한진주 (충남대학교 컴퓨터융합학부)

---

## 개요

정적 분석 도구(Infer)가 탐지한 C/C++ 결함 경고를, LLM(Claude)이 재현 입력값을 자동 생성하고 AddressSanitizer(ASan)로 실행 검증하여 **True Positive / False Positive를 자동 분류**하는 파이프라인입니다.

```
[Infer report.json]
       ↓ 파싱
[결함 정보 추출 모듈]  ← infer_parser.py
  bug_type / file / line / procedure / bug_trace
       ↓ 소스코드 + 결함 정보
[LLM 입력값 생성 모듈]  ← llm_generator.py
  Claude API 호출 → 결함 재현 입력값 JSON
       ↓ 생성된 입력값
[ASan 동적 검증 모듈]  ← asan_verifier.py
  -fsanitize=address 컴파일 → 실행 → 결과 파싱
       ↓
[결과 리포트]  ← reporter.py
  TP / UNCONFIRMED / COMPILE_ERROR 분류
  성공률 · 오탐 제거율 산출
```

---

## 폴더 구조

```
static-verifier/
├── main.py                      # CLI 진입점 및 파이프라인 오케스트레이터
├── config.py                    # 전역 설정 (API키, 타임아웃, 버그 타입 등)
├── requirements.txt
│
├── pipeline/
│   ├── infer_parser.py          # Infer report.json 파싱 모듈
│   ├── llm_generator.py         # Claude API 기반 입력값 생성 모듈
│   ├── asan_verifier.py         # ASan 동적 검증 모듈
│   └── reporter.py              # 결과 집계 및 JSON 리포트 생성
│
├── utils/
│   ├── file_utils.py            # 소스 코드 읽기, JSON 저장 등 유틸
│   └── logger.py                # 로깅 설정
│
├── benchmarks/
│   ├── samples/                 # 벤치마크 C 샘플 파일
│   │   ├── null_deref.c         # NULL_DEREFERENCE 예제
│   │   ├── use_after_free.c     # USE_AFTER_FREE 예제
│   │   └── buffer_overflow.c    # BUFFER_OVERRUN 예제
│   ├── infer-out/
│   │   └── report.json          # 사전 생성된 Infer 결과 (mock)
│   ├── results/                 # 파이프라인 실행 결과 저장
│   └── run_benchmark.py         # 벤치마크 실행 스크립트
│
├── tests/
│   ├── test_infer_parser.py     # InferParser 단위 테스트 (14개)
│   ├── test_llm_generator.py    # LLMGenerator 단위 테스트 (11개)
│   ├── test_asan_verifier.py    # ASanVerifier 단위+통합 테스트 (16개)
│   ├── test_reporter.py         # Reporter 단위 테스트 (11개)
│   └── test_pipeline_integration.py  # end-to-end 통합 테스트 (5개)
│
├── scripts/
│   └── run_infer.sh             # Docker로 Infer 실행 헬퍼 스크립트
└── docker/
    └── Dockerfile               # Infer + Clang/ASan 통합 환경
```

---

## 설치 및 환경 설정

### 1. 필수 요구사항

| 도구 | 버전 | 용도 |
|------|------|------|
| Python | 3.10+ | 파이프라인 실행 |
| gcc / clang | 11+ | ASan 컴파일 (`-fsanitize=address`) |
| Docker | 20+ | Infer 실행 환경 |

### 2. 설치

```bash
git clone https://github.com/your-repo/static-verifier
cd static-verifier
pip install -r requirements.txt
```

### 3. API 키 설정

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
```

---

## 사용법

### 기본 실행

```bash
# Infer report.json과 소스 루트 경로 지정
python main.py --report infer-out/report.json --source-root src/
```

### 옵션

```
--report       PATH     Infer의 report.json 경로 (필수)
--source-root  PATH     소스 코드 루트 디렉터리 (필수)
--bug-types    LIST     분석할 버그 타입 제한 (예: NULL_DEREFERENCE USE_AFTER_FREE)
--output-dir   PATH     결과 저장 디렉터리 (기본: results/)
--dry-run               LLM/ASan 없이 파싱 결과만 출력
--benchmark             번들 샘플로 벤치마크 실행
--log-file     PATH     상세 로그를 파일에 저장
```

### 예시

```bash
# 특정 버그 타입만 분석
python main.py \
  --report report.json \
  --source-root src/ \
  --bug-types NULL_DEREFERENCE USE_AFTER_FREE

# Dry-run으로 파싱 결과 미리 확인
python main.py --report report.json --source-root src/ --dry-run

# 번들 벤치마크 실행
python main.py --benchmark
```

### Infer 실행 (Docker)

```bash
# 소스 디렉터리에 Infer 분석 수행
bash scripts/run_infer.sh src/ infer-out/
```

---

## 파이프라인 상세

### 1단계: Infer 파싱 (`infer_parser.py`)

`report.json`에서 결함 정보를 추출합니다.

```python
from pipeline.infer_parser import InferParser

parser  = InferParser("infer-out/report.json", source_root="src/")
reports = parser.parse()
# → List[BugReport]
```

지원 버그 타입:
- ASan 직접 검증: `NULL_DEREFERENCE`, `USE_AFTER_FREE`, `BUFFER_OVERRUN_L1/L2/L3/U`, `MEMORY_LEAK`
- Assertion 삽입: `DIVIDE_BY_ZERO`, `INTEGER_OVERFLOW_L5`

### 2단계: LLM 입력값 생성 (`llm_generator.py`)

Claude API에 결함 정보 + 소스 코드를 제공하여 재현 입력값을 생성합니다.

```python
from pipeline.llm_generator import LLMGenerator

gen    = LLMGenerator()
result = gen.generate(report)
# result.args         → ["--input", "-1"]
# result.stdin_data   → "4\n"
# result.confidence   → "high"
```

실패 시 최대 3회 재시도, 지수 백오프 적용.

### 3단계: ASan 동적 검증 (`asan_verifier.py`)

생성된 입력값으로 `-fsanitize=address,undefined` 플래그와 함께 컴파일·실행합니다.

```python
from pipeline.asan_verifier import ASanVerifier

verifier = ASanVerifier()
result   = verifier.verify(report, llm_result)
# result.verdict    → Verdict.TRUE_POSITIVE | UNCONFIRMED | COMPILE_ERROR | TIMEOUT
# result.crash_type → "heap-use-after-free"
```

#### 판정 기준

| 판정 | 조건 |
|------|------|
| `TP` (True Positive) | ASan 에러 탐지 또는 시그널 크래시 |
| `UNCONFIRMED` | 정상 종료 (False Positive 후보) |
| `COMPILE_ERROR` | 컴파일 실패 |
| `TIMEOUT` | 실행 10초 초과 |
| `SKIPPED` | ASan 검증 불가 버그 타입 |

---

## 테스트 실행

```bash
# 전체 테스트 (57개)
python -m pytest tests/ -v

# 모듈별 테스트
python -m pytest tests/test_infer_parser.py -v
python -m pytest tests/test_llm_generator.py -v
python -m pytest tests/test_asan_verifier.py -v        # 통합 테스트 포함
python -m pytest tests/test_reporter.py -v
python -m pytest tests/test_pipeline_integration.py -v
```

> **참고**: ASan 통합 테스트(`TestASanIntegration`)는 gcc/clang이 설치된 환경에서만 실행됩니다. 컴파일러가 없으면 자동으로 skip됩니다.

---

## 출력 결과 예시

```
══════════════════════════════════════════════════════════════════════
  STATIC VERIFIER  –  PIPELINE RESULTS
══════════════════════════════════════════════════════════════════════
  Total bugs analysed     : 3
  LLM input generation    : 3 / 3  (100.0%)
  True Positives (ASan TP): 2  (66.7%)
  Unconfirmed (FP cand.)  : 1  (33.3%)
  FP Reduction Rate       : 66.7%

  Bug type breakdown:
    NULL_DEREFERENCE               1
    USE_AFTER_FREE                 1
    BUFFER_OVERRUN_L1              1

  Per-bug results:
  FILE:LINE                        TYPE             LLM    VERDICT
  ─────────────────────────────────────────────────────────────────
  samples/null_deref.c:42          NULL_DEREFERENCE ✓      TP
  samples/use_after_free.c:43      USE_AFTER_FREE   ✓      TP
  samples/buffer_overflow.c:18     BUFFER_OVERRUN_L1 ✓     UNCONFIRMED
══════════════════════════════════════════════════════════════════════
```

`results/verification_report.json`에 상세 결과가 저장됩니다.

---

## 평가 지표

| 지표 | 설명 |
|------|------|
| LLM 입력값 생성 성공률 | LLM이 유효한 입력값을 생성한 비율 |
| True Positive Rate | ASan으로 실제 결함을 재현한 비율 |
| FP Reduction Rate | 재현 성공 / (재현 성공 + 미확인) |

---

## 참고 문헌

- [LLM4FPM] Shi et al., "LLM-Based False Positive Mitigation for Static Analysis Tools", 2024
- [SkipAnalyzer] Hasan et al., arXiv:2310.18532, 2023
- [Infer] Calcagno et al., NASA Formal Methods, 2011
- [ASan] Serebry et al., USENIX ATC, 2012
