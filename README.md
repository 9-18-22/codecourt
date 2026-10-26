# CodeCourt

실행 증거를 이용해 Infer 정적 분석 경고를 검증하는 대심형 에이전트입니다.
Prosecutor가 결함 가설과 실험을 만들고, 실제 C 코드를 ASan/UBSan으로 실행한 뒤,
Defense가 caller 조건·mock·다른 결함 가능성을 반박합니다. Evidence Verifier는
저장된 코드와 로그를 규칙 기반으로 검사하고 Judge는 추가 실험 또는 최종 판정을
선택합니다.

현재 버전은 정답 라벨이 없는 리얼월드 C 프로젝트를 대상으로 합니다. Toyota ITC와
파일명 기반 ground truth 기능은 제거했습니다.

## 판정

- `CONFIRMED_TRUE`: 대상 유형과 원본 위치가 일치하는 sanitizer 증거가 적격 실행
  조건에서 독립적으로 재현되고, 근거가 확인된 Defense 반론이 남지 않음
- `UNRESOLVED`: 실험 예산 안에서 결함을 확정할 증거나 오탐을 증명할 근거가 부족함
- `INVALID_EXPERIMENT`: 개별 실험의 schema, 경로, source provenance가 유효하지 않음

`INVALID_EXPERIMENT`는 경고의 최종 판정이 아니라 라운드 상태입니다. 현재
`BOUNDED_FALSE_POSITIVE` 자동 판정은 비활성화되어 있습니다. 단순 미재현만으로 실제
오탐을 확정할 수 없기 때문입니다.

## 요구 사항

- Python 3.10+
- clang 또는 gcc
- Infer `report.json`
- Anthropic, OpenAI 또는 Gemini API 키

```bash
pip install -r requirements.txt
export LLM_PROVIDER=anthropic
export ANTHROPIC_API_KEY=...
```

## 실행

```bash
python main.py \
  --codecourt \
  --report /project/infer-out/report.json \
  --source-root /project \
  --output-dir results/realworld
```

같은 실행은 다음 wrapper로도 시작할 수 있습니다.

```bash
./scripts/run_codecourt.sh /project/infer-out/report.json /project results/realworld /project/build_config.json
```

주요 옵션:

- `--bug-types NULL_DEREFERENCE USE_AFTER_FREE`: 분석할 Infer 유형 제한
- `--max-rounds 3`: 경고별 Prosecutor/Defense 라운드 수
- `--max-executions 6`: 재현 확인을 포함한 경고별 실행 수
- `--court-time-budget 180`: 경고별 전체 시간 제한(초)
- `--build-config build.json`: 실제 프로젝트의 추가 빌드 정보
- `--dry-run`: API와 실행 없이 경고 파싱만 확인
- `LLM_TIMEOUT_SECONDS`는 현재 설정 파일의 `llm_timeout_seconds` 값으로 API 호출
  timeout을 조정할 수 있습니다.

리얼월드 코드는 단일 C 파일만으로 링크되지 않는 경우가 많습니다. 그 경우 다음처럼
빌드 정보를 명시할 수 있습니다.

```json
{
  "include_dirs": ["/project/include"],
  "extra_sources": ["/project/src/dependency.c"],
  "compile_flags": ["-DFEATURE_X=1"],
  "link_flags": ["-lpthread", "-lm"]
}
```

빌드 설정은 사용자가 제공하며 Agent가 임의로 compiler flag나 추가 source를 만들지
않습니다. 설정 내용은 각 증거 manifest의 검증 범위에 기록됩니다.

## 동작 흐름

구성요소 책임과 evidence 디렉터리 구조는 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)에 정리되어 있습니다.

1. Infer 경고와 원본 source를 읽고 검증 범위를 고정합니다.
2. Prosecutor가 첫 재현 실험을 JSON 계약으로 제안합니다.
3. Runner가 원본 전체 source를 우선 빌드하고 ASan/UBSan 로그를 보관합니다.
4. Evidence Verifier가 결함 유형, 원본 파일·위치·함수, source 해시를 확인합니다.
5. Defense가 코드와 로그의 정확한 줄을 인용해 반론과 후속 실험을 제시합니다.
6. Judge가 다른 실험을 요청하거나, 같은 증거의 독립 재실행 후 판정합니다.

Agent 응답은 실행 결과를 직접 판정하지 않습니다. `CONFIRMED_TRUE`는 코드 기반 필수
검사와 재실행을 모두 통과해야 합니다. mock이 들어간 harness와 추출 함수 실험은 추가
단서로 기록되지만 그 결과만으로 확정하지 않습니다.

## 증거 산출물

결과는 `OUTPUT/codecourt/<warning-id>/` 아래에 저장됩니다.

- `warning.json`: 경고와 판정 정책
- `round_NN/plan.json`: 실행 계획과 전제조건
- `original.c`, `mock.c`, `harness.c`: 실행에 사용된 코드
- `inputs.json`: argv, stdin, 입력 파일
- `manifest.json`: source/binary hash, compiler, command, 환경, 실행 이력
- `compile.*`, `run_N.*`: 원본 빌드·실행 로그
- `prosecutor_*`, `defense_*`: Agent 요청과 응답
- `court_report.json`: 경고별 최종 판정과 전체 라운드
- `verification_report.json`: 전체 경고 요약

## 기존 파이프라인

`--codecourt`를 생략하면 기존 단일 LLM + ASan 검증 경로를 실행할 수 있습니다. 이
경로는 비교 실험용 baseline으로 남겨두었습니다. CodeCourt와 baseline 모두 정답
라벨을 판정 과정에서 사용하지 않습니다.

## 테스트

```bash
python -m pytest tests/test_codecourt.py tests/test_reporter.py -q
```
