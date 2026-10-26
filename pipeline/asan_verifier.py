"""
ASan Dynamic Verifier - PATCH v4 (Real-world C codebase support)
==================================================================

기존 asan_verifier.py 와 100% 호환되면서 다음을 추가:

  Patch 1: 헤더 경로 자동 발견 (_discover_include_dirs)
  Patch 3: compile_commands.json 활용 (_load_compile_commands)
  Patch 4: 점진적 폴백 (compile_commands → auto-discover → bare)

  + mock_code prepend 지원 (LLM이 생성한 stub을 source 앞에 삽입)

적용 방법:
  pipeline/asan_verifier.py 를 이 파일로 교체
"""

from __future__ import annotations

import json as _json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional

from config import config
from pipeline.infer_parser import BugReport
from pipeline.llm_generator import LLMResult
from utils.logger import get_logger

log = get_logger(__name__)


# ── Verdict ───────────────────────────────────────────────────────────────────

class Verdict(str, Enum):
    STRICT_TP        = "STRICT_TP"
    FAMILY_TP        = "FAMILY_TP"
    CROSS_DETECTION  = "CROSS_DETECTION"
    LIKELY_FP        = "LIKELY_FP"
    COMPILE_ERROR    = "COMPILE_ERROR"
    RUNTIME_ERROR    = "RUNTIME_ERROR"
    TIMEOUT          = "TIMEOUT"
    SKIPPED          = "SKIPPED"

    # Backward compat aliases. New logic must use is_tp_verdict().
    TRUE_POSITIVE    = "STRICT_TP"
    UNCONFIRMED      = "LIKELY_FP"


def is_tp_verdict(verdict: Verdict | str | None) -> bool:
    value = verdict.value if isinstance(verdict, Verdict) else str(verdict or "")
    return value in {
        Verdict.STRICT_TP.value,
        Verdict.FAMILY_TP.value,
        "TP",
        "TRUE_POSITIVE",
    }


@dataclass
class ASanResult:
    verdict:       Verdict
    crash_type:    str  = ""
    crash_line:    str  = ""
    asan_output:   str  = ""
    stderr:        str  = ""
    returncode:    int  = 0
    compile_cmd:   str  = ""
    run_cmd:       str  = ""
    match_level:   str  = ""
    type_matched:  bool = False
    matched_frame: str  = ""
    matched_line:  int  = 0

    def to_dict(self) -> dict:
        return {
            "verdict":       self.verdict.value,
            "crash_type":    self.crash_type,
            "crash_line":    self.crash_line,
            "asan_output":   self.asan_output[:2000],
            "stderr":        self.stderr[:2000],
            "returncode":    self.returncode,
            "compile_cmd":   self.compile_cmd,
            "run_cmd":       self.run_cmd,
            "match_level":   self.match_level,
            "type_matched":  self.type_matched,
            "matched_frame": self.matched_frame,
            "matched_line":  self.matched_line,
        }


# ── Sanitizer 출력 패턴 ──────────────────────────────────────────────────────

_ASAN_ERROR_RE = re.compile(
    r"ERROR: AddressSanitizer:\s*(.+?)(?:\n|$)", re.IGNORECASE
)
_UBSAN_ERROR_RE = re.compile(
    r"runtime error:\s*(.+?)(?:\n|$)", re.IGNORECASE
)
_UBSAN_LOCATION_RE = re.compile(
    r"^(.+?):(\d+)(?::\d+)?:\s+runtime error:", re.IGNORECASE | re.MULTILINE
)
_LSAN_ERROR_RE = re.compile(
    r"ERROR: LeakSanitizer:\s*(.+?)(?:\n|$)", re.IGNORECASE
)
_LSAN_LEAK_SUMMARY_RE = re.compile(
    r"SUMMARY:\s*AddressSanitizer:\s*\d+\s*byte\(s\)\s*leaked", re.IGNORECASE
)
_LSAN_DETECT_RE = re.compile(r"detected memory leaks", re.IGNORECASE)
_CRASH_LOC_RE  = re.compile(
    r"#\d+\s+(?:0x[0-9a-f]+\s+)?in\s+\S+\s+(.+:\d+)",
    re.IGNORECASE,
)
_SIGNAL_RE     = re.compile(r"signal \d+ \(SIG\w+\)", re.IGNORECASE)

# ── v4.5 패치: stack trace 전체에서 user-code frame 추출용 ─────────────────
# LSan은 leak 보고 시 첫 frame을 항상 malloc/calloc 자체 위치(asan_malloc_linux.cpp 등)
# 로 인쇄한다. 실제 user code 위치는 더 깊은 frame에 있다.
# → 첫 frame 만 보면 MEMORY_LEAK 부류는 100% loc_mismatch 가 된다.
_ALL_FRAMES_RE = re.compile(
    r"#\d+\s+(?:0x[0-9a-f]+\s+)?in\s+(\S+)\s+(.+?):(\d+)(?::\d+)?",
    re.IGNORECASE,
)
_SANITIZER_INTERNAL_RE = re.compile(
    r"(?:libsanitizer|sanitizer_common|asan_malloc|asan_interceptors|"
    r"asan_thread|asan_allocator|lsan_common|lsan_interceptors|lsan_allocator|"
    r"ubsan_handlers|compiler-rt[/\\]+lib[/\\]+(?:asan|lsan|ubsan|tsan|sanitizer_common)|"
    r"interception[/\\])",
    re.IGNORECASE,
)


def _extract_user_code_frames(output: str) -> list[tuple[str, str, int]]:
    """Sanitizer 출력 전체에서 user-code stack frame 추출.

    반환: [(func_name, file_path, line_no), ...]
    sanitizer 내부 frame 은 건너뛴다.
    """
    frames: list[tuple[str, str, int]] = []
    for m in _ALL_FRAMES_RE.finditer(output):
        func = m.group(1).strip()
        path = m.group(2).strip()
        try:
            line = int(m.group(3))
        except ValueError:
            continue
        if _SANITIZER_INTERNAL_RE.search(path):
            continue
        frames.append((func, path, line))
    return frames


def _procedure_in_frame(bug_proc: str, frame_func: str) -> bool:
    """Return True only when the procedure appears as a word-boundary token."""
    if not bug_proc or not frame_func:
        return False
    pat = re.compile(rf"(?:^|[^\w]){re.escape(bug_proc)}(?:$|[^\w])")
    return pat.search(frame_func) is not None


def _is_memory_leak_bug_type(bug_type: str) -> bool:
    return (bug_type or "").upper() in {
        "MEMORY_LEAK",
        "MEMORY_LEAK_C",
        "RESOURCE_LEAK",
        "PULSE_RESOURCE_LEAK",
    }


# ── v3 패치: Bug type ↔ Crash type 매칭 ─────────────────────────────────────
# Infer가 경고한 bug_type 과 ASan 이 잡은 crash 가 같은 부류인지 검증한다.
# 이게 없으면 NULL_DEREFERENCE 경고 파일에서 (다른 sub-function 의) leak 가
# 잡혔을 때도 TP 로 분류돼서 Specificity 가 깨진다.

def _crash_matches_bug_type(crash_type: str, bug_type: str) -> bool:
    """ASan crash_type 이 Infer bug_type 과 같은 부류인지 검증."""
    if not crash_type or not bug_type:
        return True  # 정보 부족 → 통과 (기존 동작 유지)

    ct = crash_type.lower()
    bt = bug_type.upper()

    # NULL_DEREFERENCE family
    if bt in ("NULL_DEREFERENCE", "NULLPTR_DEREFERENCE", "NULL_DEREF"):
        return any(p in ct for p in (
            "segv", "null", "deref", "signal:11", "signal:6",
        ))

    # MEMORY_LEAK / RESOURCE_LEAK family
    if _is_memory_leak_bug_type(bt):
        return any(p in ct for p in (
            "leak", "memory leaks", "byte(s) leaked",
        ))

    # USE_AFTER_FREE
    if bt in ("USE_AFTER_FREE", "PULSE_USE_AFTER_FREE"):
        return any(p in ct for p in (
            "use-after-free", "heap-use-after-free", "uaf",
        ))

    # BUFFER_OVERRUN family
    if "BUFFER_OVERRUN" in bt or "BUFFER_OVERFLOW" in bt or "STACK_OVERFLOW" in bt:
        return any(p in ct for p in (
            "buffer-overflow", "heap-buffer-overflow", "stack-buffer-overflow",
            "stack-overflow", "global-buffer-overflow",
        ))

    # DIVIDE_BY_ZERO / INTEGER_OVERFLOW (instrumentation 기반)
    if bt in ("DIVIDE_BY_ZERO", "INTEGER_OVERFLOW", "INTEGER_OVERFLOW_L1",
              "INTEGER_OVERFLOW_L2", "INTEGER_OVERFLOW_L5"):
        return any(p in ct for p in (
            "assertion", "ubsan", "divide", "overflow", "signal:8",
        ))

    # UNINITIALIZED_VALUE (MSan 영역 — ASan은 직접 못 잡음; assertion 만 의지)
    if bt in ("UNINITIALIZED_VALUE", "UNINITIALIZED"):
        return any(p in ct for p in (
            "assertion", "ubsan", "uninit",
        ))

    # 알려지지 않은 bug_type → 보수적으로 통과 (false negative 회피)
    return True


def _crash_location_matches(
    crash_line: str,
    bug_file: str,
    bug_line: int,
    *,
    asan_output: str = "",
    bug_type: str = "",
    bug_procedure: str = "",
    tolerance: int = 10,
) -> bool:
    """ASan/LSan crash 위치가 Infer 가 지목한 bug 위치와 일치하는지 검증.

    v4.5 PATCH (성능 회복 핵심):
      [기존 v4.4 한계]
        - 첫 stack frame(crash_line) 만 보고 basename·line 비교.
        - LSan 의 첫 frame 은 항상 sanitizer-internal 위치
          (asan_malloc_linux.cpp 등) → MEMORY_LEAK 부류는 구조적으로
          100% loc_mismatch 가 되어 Recall = 0% 였다.

      [v4.5 개선]
        1) stack trace 전체를 _extract_user_code_frames 로 파싱하여
           sanitizer-internal frame 을 제외한 user-code frame 만 후보로.
        2) MEMORY_LEAK 부류는 allocation site 와 leak 위치가 멀 수
           있으므로 tolerance 를 50 으로 확대.
        3) FP 데이터셋 (같은 파일의 다른 sub-function 이 우연히 crash)
           에 의한 오분류를 막기 위해, bug_procedure 정보가 있고
           stack trace 에 procedure 가 나타나지 않으면 reject
           → Specificity 100% 유지.

      [신뢰성 근거]
        - sanitizer 출력 포맷은 LLVM/GCC 양쪽 모두 동일한 `#N 0x... in
          <func> <path>:<line>` 패턴을 사용한다 (compiler-rt source).
        - frame 의 file path 가 'libsanitizer/...' 또는
          'compiler-rt/lib/(asan|lsan|...)' 로 시작하면 user code 가
          아님은 ASan/LSan 의 공식 빌드 구조에서 보장된다.
    """
    bug_basename = os.path.basename(bug_file) if bug_file else ""
    if not bug_basename:
        return True  # 정보 부족 → 통과

    bt_upper = (bug_type or "").upper()
    is_leak = bt_upper in {
        "MEMORY_LEAK", "MEMORY_LEAK_C", "RESOURCE_LEAK", "PULSE_RESOURCE_LEAK",
    }
    # leak 은 allocation site 와 Infer 가 지목한 라인이 멀 수 있으므로
    # tolerance 를 확대한다.
    effective_tol = max(tolerance, 50) if is_leak else tolerance

    # ── 1차: stack trace 전체에서 user-code frame 검사 (Patch 핵심) ──
    if asan_output:
        user_frames = _extract_user_code_frames(asan_output)
        same_file_frames = [
            (func, ln) for func, path, ln in user_frames
            if os.path.basename(path) == bug_basename
        ]
        if same_file_frames:
            # Specificity 보호: bug_procedure 정보가 있으면, stack 에
            # 해당 procedure 가 등장해야 진짜 매칭으로 본다. 같은 파일
            # 안의 *다른* 함수가 우연히 crash 한 케이스를 막는다.
            if bug_procedure:
                proc_present = any(
                    bug_procedure in func or func.endswith(bug_procedure)
                    for func, _ in same_file_frames
                )
                if not proc_present:
                    return False

            if bug_line <= 0:
                return True
            return any(
                abs(ln - bug_line) <= effective_tol
                for _, ln in same_file_frames
            )
        # user frame 자체에 same-file 이 없으면 → 불일치
        # (leak/non-leak 공통)
        return False

    # ── 2차: asan_output 정보가 없을 때 fallback (기존 호환 동작) ──
    if not crash_line:
        return True  # 정보 부족 → 통과 (bug_type matching 만 의지)

    m = re.match(r'(.+?):(\d+)(?::\d+)?\s*$', crash_line.strip())
    if not m:
        return True  # 파싱 실패 → 통과

    crash_file_path, crash_line_num_s = m.group(1), m.group(2)
    try:
        crash_line_num = int(crash_line_num_s)
    except ValueError:
        return True

    # 첫 frame 이 sanitizer 내부면 보수적으로 reject
    if _SANITIZER_INTERNAL_RE.search(crash_file_path):
        return False

    crash_basename = os.path.basename(crash_file_path)
    if crash_basename != bug_basename:
        return False

    if bug_line <= 0:
        return True

    return abs(crash_line_num - bug_line) <= effective_tol


# ── Verifier ─────────────────────────────────────────────────────────────────

class ASanVerifier:
    def __init__(self) -> None:
        self._compiler = (
            shutil.which(config.compiler)
            or shutil.which("clang")
            or shutil.which("gcc")
            or "clang"
        )
        log.debug("Using compiler: %s", self._compiler)

        # ── NEW (v4): Real-world 지원 캐시 ──────────────────────────
        self._compile_db_cache: Optional[list] = None
        self._compile_db_loaded_for: Optional[str] = None
        self._include_dirs_cache: Dict[str, List[str]] = {}

    # ─────────────────────────────────────────────────────────────────────
    # NEW (v4): compile_commands.json 로드
    # ─────────────────────────────────────────────────────────────────────

    def _load_compile_commands(self, source_root: Path) -> Optional[list]:
        """source_root 또는 그 부모에서 compile_commands.json 탐색."""
        root_key = str(source_root.resolve())
        if self._compile_db_loaded_for == root_key:
            return self._compile_db_cache

        candidates = [
            source_root / "compile_commands.json",
            source_root.parent / "compile_commands.json",
            source_root.parent.parent / "compile_commands.json",
            source_root / "src" / "compile_commands.json",  # Redis 같이 src/ 안에 있을 수도
        ]
        for path in candidates:
            if path.is_file():
                try:
                    with open(path) as f:
                        self._compile_db_cache = _json.load(f)
                    self._compile_db_loaded_for = root_key
                    log.info("✓ Loaded compile_commands.json from %s (%d entries)",
                             path, len(self._compile_db_cache))
                    return self._compile_db_cache
                except Exception as e:
                    log.warning("Failed to load %s: %s", path, e)
        self._compile_db_cache = []
        self._compile_db_loaded_for = root_key
        return None

    def _find_compile_commands_entry(
        self, source_path: Path, source_root: Path
    ) -> Optional[dict]:
        """compile_commands.json 에서 source_path와 매칭되는 엔트리 찾기."""
        db = self._load_compile_commands(source_root)
        if not db:
            return None

        # tmp dir 으로 복사된 파일이라면 원본 이름으로 매칭
        src_name = source_path.name
        # 원본 경로를 추정 (resolved_path 가 아닌 tmp 경로일 수 있으니)
        for entry in db:
            entry_file = Path(entry.get("file", ""))
            if entry_file.name == src_name:
                return entry
        return None

    def _extract_flags_from_entry(self, entry: dict) -> str:
        """compile_commands.json 엔트리에서 -I, -D, -isystem 만 안전하게 추출."""
        # arguments (배열) 또는 command (문자열) 둘 다 지원
        args = entry.get("arguments")
        if not args:
            cmd_str = entry.get("command", "")
            args = cmd_str.split() if cmd_str else []

        flags = []
        i = 0
        while i < len(args):
            a = args[i]
            # -I, -D, -isystem, -include 만 추출 (안전한 것들)
            if a.startswith("-I") or a.startswith("-D"):
                flags.append(a)
            elif a in ("-isystem", "-include"):
                if i + 1 < len(args):
                    flags.append(f"{a} {args[i+1]}")
                    i += 1
            elif a.startswith("-isystem=") or a.startswith("-include="):
                flags.append(a)
            i += 1
        return " ".join(flags)

    def _discover_include_dirs(self, source_root: Path) -> List[str]:
        """source_root 하위에서 .h 파일을 포함하는 디렉토리 자동 발견.

        Linux/GCC 환경이므로 MSVC/Windows 호환 헤더 폴더는 반드시 제외해야 함.
        (예: jemalloc/include/msvc_compat 안의 stdint.h 가 끼면 빌드 깨짐)
        """
        cache_key = str(source_root.resolve())
        if cache_key in self._include_dirs_cache:
            return self._include_dirs_cache[cache_key]

        dirs = set()
        max_depth = 6
        root_str = str(source_root.resolve())
        # 제외할 폴더 이름 (단순 이름)
        skip_dirs = {'.git', '.svn', 'build', 'docs', 'doc', 'test', 'tests',
                     '__pycache__', 'node_modules', '.cache', 'obj',
                     # ── v4.1: 플랫폼 호환 폴더 (Linux 빌드시 절대 포함하면 안됨) ──
                     'msvc_compat',     # Windows MSVC 호환 헤더 (jemalloc 등)
                     'msvc',            # 더 일반적 MSVC 폴더
                     'windows',         # Windows 전용
                     'win32', 'win64',
                     'mingw',           # MinGW 전용 (보통 cross-build)
                     'darwin', 'macos', 'osx',  # macOS 전용
                     'freebsd', 'openbsd', 'netbsd',
                     'solaris', 'aix',
                     'android', 'ios',
                     'arm', 'arm64', 'aarch64',  # 다른 아키텍처 (x86_64 환경)
                     'ppc', 'powerpc', 'sparc', 'mips',
                     # 가상환경 / 의존성 / 캐시
                     'venv', '.venv', 'env',
                     'cmake-build-debug', 'cmake-build-release',
                     'CMakeFiles',
                     # 단위 테스트 / 예제
                     'examples', 'samples', 'sample',
                     'fuzz', 'fuzzing', 'benchmarks',
        }
        # 경로에 다음 substring 이 들어가면 무조건 제외
        skip_path_substrs = (
            '/msvc_compat/', '/msvc/', '/windows/', '/win32/', '/win64/',
            '/mingw/', '/darwin/', '/macos/', '/osx/',
            '/freebsd/', '/openbsd/', '/netbsd/',
            '/android/', '/ios/',
            '/arm/', '/arm64/', '/aarch64/',
            # jemalloc 의 모든 include 경로 차단 (Redis 가 자체 빌드한 게 아니라
            # mock 환경에서 쓰는데 jemalloc 헤더 자체가 시스템 무관 추상화라
            # 컴파일에 도움이 안 됨)
            '/jemalloc/',
            # Redis tests 등
            '/tests/', '/test/',
        )

        for dirpath, dirnames, files in os.walk(root_str):
            rel = dirpath.replace(root_str, "").strip(os.sep)
            depth = rel.count(os.sep) if rel else 0
            if depth > max_depth:
                dirnames.clear()
                continue
            # 경로 substring 체크 (가장 강력한 필터)
            dirpath_lower = dirpath.lower()
            if any(s in dirpath_lower for s in skip_path_substrs):
                dirnames.clear()  # 하위로 더 들어가지 않음
                continue
            # 제외 폴더 in-place 필터
            dirnames[:] = [d for d in dirnames
                           if not d.startswith('.')
                           and d.lower() not in skip_dirs]
            # .h 파일 있으면 후보
            if any(f.endswith(('.h', '.hpp', '.hh')) for f in files):
                dirs.add(dirpath)

        result = sorted(dirs)
        self._include_dirs_cache[cache_key] = result
        log.info("✓ Auto-discovered %d include dirs under %s (after filtering)",
                 len(result), source_root)
        for d in result:
            log.debug("  -I %s", d)
        return result

    # ─────────────────────────────────────────────────────────────────────
    # Public API (기존과 동일)
    # ─────────────────────────────────────────────────────────────────────

    def verify(
        self,
        report: BugReport,
        llm_result: LLMResult,
        generator=None,  # NEW (v4.4): LLMGenerator 인스턴스 (feedback retry용)
    ) -> ASanResult:
        if not report.is_asan_verifiable and not report.needs_instrumentation:
            log.info("[%s] Skipping: not ASan-verifiable", report.id)
            return ASanResult(Verdict.SKIPPED, match_level="infra")

        source_path = report.resolved_path
        if source_path is None:
            log.error("[%s] No resolved source path; cannot compile.", report.id)
            return ASanResult(
                Verdict.COMPILE_ERROR,
                stderr="Source file missing",
                match_level="infra",
            )

        if config.dataset_mode == "juliet" and re.search(r'\d+[b-z]\.c$', str(source_path)):
            log.info("[%s] Skipping: Juliet sub-file", report.id)
            return ASanResult(Verdict.SKIPPED, match_level="infra")

        with tempfile.TemporaryDirectory(prefix="sv_asan_") as tmpdir:
            tmp = Path(tmpdir)
            result = self._run_in_tmpdir(report, llm_result, source_path, tmp)

        # ─── NEW (v4.4): Real-world COMPILE_ERROR 시 LLM feedback retry ───
        # generic 모드에서 컴파일 실패 + LLMGenerator 인스턴스 가용 시,
        # 컴파일 에러 메시지를 LLM 에게 보여주고 mock 수정 요청.
        # 최대 2번 재시도.
        if (config.dataset_mode in ("generic", "generic_realworld")
                and result.verdict == Verdict.COMPILE_ERROR
                and generator is not None
                and hasattr(llm_result, 'mock_code')
                and llm_result.mock_code):  # 첫 mock 이 있을 때만 의미있음

            max_feedback_retries = 2
            current_llm = llm_result
            for retry_num in range(1, max_feedback_retries + 1):
                log.info(
                    "[%s] COMPILE_ERROR detected → trying LLM feedback retry %d/%d",
                    report.id, retry_num, max_feedback_retries,
                )
                # LLM 에게 컴파일 에러 보여주고 mock 수정 요청
                new_llm = generator.retry_with_compile_feedback(
                    report,
                    previous_result=current_llm,
                    compile_error=result.stderr or result.asan_output or "",
                    attempt_num=retry_num,
                )
                if new_llm is None:
                    log.warning("[%s] Feedback retry %d failed (no new LLM result)",
                                report.id, retry_num)
                    break

                # 새 mock 으로 다시 컴파일/실행
                with tempfile.TemporaryDirectory(prefix=f"sv_asan_fb{retry_num}_") as tmpdir2:
                    tmp2 = Path(tmpdir2)
                    new_result = self._run_in_tmpdir(report, new_llm, source_path, tmp2)

                if is_tp_verdict(new_result.verdict):
                    log.info("[%s] ✓ Feedback retry %d → TP!", report.id, retry_num)
                    result = new_result
                    break
                elif new_result.verdict != Verdict.COMPILE_ERROR:
                    log.info("[%s] ✓ Feedback retry %d → %s (compile fixed)",
                             report.id, retry_num, new_result.verdict.value)
                    result = new_result
                    break
                else:
                    # 여전히 COMPILE_ERROR → 다음 retry 시도
                    log.info("[%s] Feedback retry %d still COMPILE_ERROR, trying again",
                             report.id, retry_num)
                    current_llm = new_llm
                    result = new_result

        return result

    # ─────────────────────────────────────────────────────────────────────
    # Internal flow
    # ─────────────────────────────────────────────────────────────────────

    def _run_in_tmpdir(
        self,
        report: BugReport,
        llm: LLMResult,
        source: Path,
        tmp: Path,
    ) -> ASanResult:
        src_file = self._prepare_source(report, llm, source, tmp)
        self._write_file_inputs(llm, tmp)
        binary = tmp / "target"
        compile_result = self._compile(src_file, binary, source_root=source)
        if compile_result is not None:
            return compile_result
        compile_cmd = self._make_compile_cmd(src_file, binary, source_root=source)
        return self._run(report, llm, binary, tmp, compile_cmd)

    def _prepare_source(
        self,
        report: BugReport,
        llm: LLMResult,
        source: Path,
        tmp: Path,
    ) -> Path:
        """
        Prepare a self-contained C source file for compilation.

        - Juliet / Toyota ITC: prepend mock to full source (legacy behavior)
        - generic (real-world): EXTRACT only the buggy function and build a
          minimal self-contained file with LLM mock + extracted function +
          LLM trigger code. Does NOT include the original 130KB file. (v4.3 옵션 A)
        """

        # ════════════════════════════════════════════════════════════════════
        # v4.3 옵션 A: Real-world 코드는 함수 단위 추출
        # ════════════════════════════════════════════════════════════════════
        # 기존 방식 (실패): 130KB acl.c 전체 + mock prepend
        #                  → mock 이 파일 전체의 globals/macros 못 커버 → 실패
        # 새 방식: LLM mock + 추출된 함수 본문 + LLM trigger = 1~2KB 자족적 .c
        if config.dataset_mode in ("generic", "generic_realworld"):
            return self._prepare_source_realworld(report, llm, source, tmp)

        # ════════════════════════════════════════════════════════════════════
        # Legacy 방식: Juliet, Toyota ITC (전체 파일 사용)
        # ════════════════════════════════════════════════════════════════════
        src_content = source.read_text(errors="replace")

        # ── Toyota ITC 전역변수 주입 (기존 로직 그대로) ─────────────────────
        if config.dataset_mode == "toyota_itc":
            def _has_definition(var: str, src: str) -> bool:
                pattern = (
                    rf'(?<!extern\s)'
                    rf'(?:^|\n)\s*'
                    rf'(?:static\s+|volatile\s+|const\s+)*'
                    rf'(?:int|double|float|long|char|void)\s+\*?\s*'
                    rf'(?:[a-zA-Z_]\w*\s*,\s*)*'
                    rf'{re.escape(var)}\s*[=,;\[]'
                )
                return bool(re.search(pattern, src, re.MULTILINE))

            def _has_extern_decl(var: str, src: str) -> Optional[str]:
                m = re.search(
                    rf'extern\s+((?:volatile\s+|const\s+)*'
                    rf'(?:int|double|float|long|char|void)\s*\*?)\s*'
                    rf'(?:[a-zA-Z_]\w*\s*,\s*)*'
                    rf'{re.escape(var)}\s*[;\[]',
                    src,
                )
                return m.group(1).strip() if m else None

            global_specs = [
                ("idx",   "int",          "0"),
                ("sink",  "int",          "0"),
                ("dsink", "double",       "0.0"),
                ("psink", "void *",       "(void*)0"),
                ("vflag", "volatile int", "0"),
            ]

            globals_to_inject = []
            for var, default_type, default_val in global_specs:
                if _has_definition(var, src_content):
                    continue
                extern_type = _has_extern_decl(var, src_content)
                use_type = extern_type if extern_type else default_type
                if use_type.endswith("*"):
                    globals_to_inject.append(f"{use_type}{var} = {default_val};")
                else:
                    globals_to_inject.append(f"{use_type} {var} = {default_val};")

            if globals_to_inject:
                global_defs = (
                    "/* Toyota ITC global variable definitions (auto-injected) */\n"
                    + "\n".join(globals_to_inject)
                    + "\n\n"
                )
                src_content = global_defs + src_content
                log.debug(
                    "[%s] Injected %d Toyota ITC globals (skipped %d already defined)",
                    report.id, len(globals_to_inject),
                    5 - len(globals_to_inject),
                )

        # ── NEW (v4.1): generic 모드는 위에서 _prepare_source_realworld 로
        # 빠졌으므로 여기는 juliet / toyota_itc 만 도달함. 그래서 이 블록은
        # 이제 사용되지 않지만 안전을 위해 남겨둠 (호환성).
        if (config.dataset_mode in ("generic", "generic_realworld")
                and hasattr(llm, 'mock_code') and llm.mock_code):
            # (deprecated path — should not reach here)
            original_includes = re.findall(r'#include\s+"([^"]+)"', src_content)
            src_content = re.sub(
                r'(#include\s+"[^"]+")',
                r'/* [v4.1 disabled by mock] \1 */',
                src_content,
            )

        # ── NEW (v4): mock_code prepend (real-world 의존성 stub) ──────────
        # LLM이 생성한 외부 함수/타입 mock 을 소스 맨 앞에 주입.
        # llm_generator 가 LLMResult.mock_code 필드에 담아 전달.
        if hasattr(llm, 'mock_code') and llm.mock_code:
            mock_block = (
                "/* ─── LLM-generated mock environment (v4) ─── */\n"
                f"{llm.mock_code}\n"
                "/* ─── end mock ─── */\n\n"
            )
            src_content = mock_block + src_content
            log.debug("[%s] Injected mock environment (%d chars)",
                      report.id, len(llm.mock_code))

        # ── Instrumentation 주입 (기존 로직) ────────────────────────────
        ASAN_NATIVE_BUG_TYPES = {
            "NULL_DEREFERENCE",
            "NULLPTR_DEREFERENCE",
            "MEMORY_LEAK",
            "MEMORY_LEAK_C",
            "USE_AFTER_FREE",
            "BUFFER_OVERRUN_L1",
            "BUFFER_OVERRUN_L2",
            "BUFFER_OVERRUN_L3",
            "BUFFER_OVERRUN_U",
            "STACK_BUFFER_OVERFLOW",
            "HEAP_BUFFER_OVERFLOW",
        }
        skip_instrumentation = report.bug_type in ASAN_NATIVE_BUG_TYPES

        if (llm.needs_instrumentation
                and llm.instrumentation_code
                and not skip_instrumentation):
            src_content = self._inject_assertion(
                src_content, report.line, llm.instrumentation_code
            )
            log.debug("[%s] Injected assertion: %s", report.id, llm.instrumentation_code)
        elif llm.needs_instrumentation and skip_instrumentation:
            log.debug(
                "[%s] Skipped instrumentation: %s is ASan-native",
                report.id, report.bug_type,
            )

        # ── main() 주입 (기존 로직 + real-world 확장) ───────────────────
        if "int main(" not in src_content and "void main(" not in src_content:
            if config.dataset_mode == "juliet":
                func_name = source.stem
                entry_func = f"{func_name}_bad"
                main_body = f"    {entry_func}();\n"
            elif config.dataset_mode == "toyota_itc":
                file_stem = source.stem
                dispatch_func = f"{file_stem}_main"
                if f"{dispatch_func}(" not in src_content and \
                   f"{dispatch_func} (" not in src_content:
                    main_funcs = re.findall(
                        r'(?:^|\n)\s*(?:void|int)\s+(\w+_main)\s*\(\s*(?:void)?\s*\)',
                        src_content,
                    )
                    if main_funcs:
                        dispatch_func = main_funcs[0]
                        log.debug(
                            "[%s] Resolved dispatch via fallback: %s",
                            report.id, dispatch_func,
                        )
                if f"{dispatch_func}(" in src_content or \
                   f"{dispatch_func} (" in src_content:
                    proc = report.procedure or ""
                    inferred_vflag: Optional[int] = None
                    proc_clean = re.sub(r'_func_\d+$', '', proc)
                    num_match = re.search(r'_(\d+)$', proc_clean)
                    if num_match and not proc_clean.endswith("_main"):
                        inferred_vflag = int(num_match.group(1))
                    if hasattr(report, '_override_vflag'):
                        vflag_val = report._override_vflag
                    elif inferred_vflag is not None:
                        vflag_val = inferred_vflag
                        if not hasattr(report, '_vflag_candidates'):
                            report._vflag_candidates = (
                                [i for i in range(1, 21) if i != inferred_vflag]
                                + [888]
                            )
                    else:
                        vflag_val = 888
                        if not hasattr(report, '_vflag_candidates'):
                            report._vflag_candidates = list(range(1, 21))
                    main_body = f"    vflag = {vflag_val};\n    {dispatch_func}();\n"
                else:
                    entry_func = report.procedure if report.procedure else file_stem
                    main_body = self._build_toyota_itc_main_call(src_content, entry_func)
            elif config.dataset_mode in ("generic", "generic_realworld"):
                # ── NEW (v4): real-world 함수 호출 main ──
                # LLM이 trigger_code 를 제공했으면 사용, 아니면 procedure 직접 호출
                if hasattr(llm, 'trigger_code') and llm.trigger_code:
                    main_body = f"    /* LLM trigger code */\n{llm.trigger_code}\n"
                else:
                    entry_func = report.procedure if report.procedure else source.stem
                    main_body = self._build_toyota_itc_main_call(src_content, entry_func)
            else:
                entry_func = report.procedure if report.procedure else source.stem
                main_body = f"    {entry_func}();\n"

            src_content += (
                "\n/* Auto-generated main for ASan verification */\n"
                "int main(void) {\n"
                f"{main_body}"
                "    return 0;\n"
                "}\n"
            )
            log.debug("[%s] Injected main()", report.id)

        dst = tmp / source.name
        dst.write_text(src_content)
        return dst

    # ════════════════════════════════════════════════════════════════════════
    # v4.3 옵션 A: Real-world 함수 단위 추출 — 핵심 신규 메서드
    # ════════════════════════════════════════════════════════════════════════

    def _prepare_source_realworld(
        self,
        report: BugReport,
        llm: LLMResult,
        source: Path,
        tmp: Path,
    ) -> Path:
        """
        Real-world (Redis 등) codebase 를 위한 함수 단위 자족 컴파일 환경.

        원본 100KB 파일 대신 다음 구성으로 작은 (1~3KB) .c 파일 생성:

          ┌─────────────────────────────────────────────┐
          │ 1. 표준 헤더 (stdint.h 등 — 항상 포함)         │
          │ 2. LLM mock_code (외부 타입/함수/매크로 stub) │
          │ 3. 추출된 함수 본문 (read_full_function 결과) │
          │ 4. LLM trigger_code 를 본문으로 하는 main()    │
          └─────────────────────────────────────────────┘

        Returns: 생성된 .c 파일 경로
        """
        src_content_full = source.read_text(errors="replace")

        # ── Step 1: 버그 함수 추출 ──────────────────────────────────────────
        # report.source_code 는 read_full_function 결과 (line-number prefix 있음)
        # 우리는 prefix 없는 순수 C 코드 필요
        extracted_func = self._extract_function_body(
            src_content_full, report.line, report.procedure
        )
        if not extracted_func:
            log.warning(
                "[%s] Could not extract function body for line %d, "
                "falling back to full file",
                report.id, report.line,
            )
            extracted_func = src_content_full  # 폴백

        log.debug(
            "[%s] Extracted function: %d chars (from %d-char file)",
            report.id, len(extracted_func), len(src_content_full),
        )

        # ── Step 2: 표준 헤더 ───────────────────────────────────────────────
        std_headers = (
            "/* ─── Standard C headers (always included) ─── */\n"
            "#include <stdlib.h>\n"
            "#include <string.h>\n"
            "#include <stdio.h>\n"
            "#include <stdint.h>\n"   # uint64_t 등
            "#include <stddef.h>\n"   # size_t 등
            "#include <assert.h>\n"
            "\n"
        )

        # ── Step 3: LLM mock_code ───────────────────────────────────────────
        mock_block = ""
        if hasattr(llm, 'mock_code') and llm.mock_code:
            mock_block = (
                "/* ─── LLM-generated mock (external dependencies) ─── */\n"
                f"{llm.mock_code}\n"
                "/* ─── end mock ─── */\n\n"
            )
        else:
            log.warning("[%s] LLM did not generate mock_code", report.id)

        # ── Step 4: 추출된 함수 + main() ──────────────────────────────────
        # trigger_code 가 있으면 main 본문으로, 없으면 procedure 직접 호출
        if re.search(r"\b(?:int|void)\s+main\s*\(", extracted_func):
            main_section = ""
        elif hasattr(llm, 'trigger_code') and llm.trigger_code:
            trigger = llm.trigger_code
            # trigger_code 가 'int main(' 을 포함하면 그대로 사용,
            # 아니면 main 본문으로 감싸기
            if "int main" in trigger or "void main" in trigger:
                main_section = trigger
            else:
                main_section = (
                    "\n/* Auto-generated main with LLM trigger */\n"
                    "int main(void) {\n"
                    f"{trigger}\n"
                    "    return 0;\n"
                    "}\n"
                )
        else:
            # trigger 가 없으면 procedure 를 인자 없이 호출 (대부분 실패하지만 시도)
            entry = report.procedure or "main"
            main_section = (
                "\n/* Auto-generated main (no LLM trigger provided) */\n"
                "int main(void) {\n"
                f"    /* call {entry} */\n"
                f"    {entry}();\n"
                "    return 0;\n"
                "}\n"
            )

        # ── Step 5: 모두 조립 ──────────────────────────────────────────────
        final_src = (
            std_headers
            + mock_block
            + "/* ─── Extracted buggy function ─── */\n"
            + extracted_func
            + "\n"
            + main_section
        )

        log.info(
            "[%s] Built self-contained file: %d chars "
            "(headers=%d, mock=%d, func=%d, main=%d)",
            report.id, len(final_src),
            len(std_headers), len(mock_block),
            len(extracted_func), len(main_section),
        )

        # ── Step 6: tmp 에 작성 ──
        dst = tmp / source.name
        dst.write_text(final_src)
        return dst

    @staticmethod
    def _extract_function_body(
        full_source: str,
        center_line: int,
        procedure_name: Optional[str] = None,
    ) -> Optional[str]:
        """
        Extract the complete function body containing center_line.

        Strategy:
          1. Find function start by walking backwards for matching '{'
          2. Walk forwards to find matching '}'
          3. Return the entire function (signature + body)

        Returns:
          Function source code as string, or None if extraction fails.
        """
        lines = full_source.splitlines()
        n = len(lines)
        if center_line < 1 or center_line > n:
            return None

        target = center_line - 1  # 0-indexed

        # ── Walk backwards from target line, tracking brace balance ──
        # find the function opening brace
        brace_depth = 0
        func_open_line = None
        for i in range(target, -1, -1):
            line = lines[i]
            # 주석/문자열은 단순화 — 그냥 카운트 (라인 단위라 보통 OK)
            brace_depth += line.count("{") - line.count("}")
            if brace_depth > 0:
                func_open_line = i
                break

        if func_open_line is None:
            return None  # 함수 밖이거나 추출 실패

        # ── 함수 시그니처는 함수 open brace 의 위쪽 몇 줄에 있음 ──
        # 시그니처는 보통 빈 줄 또는 ; 또는 } 가 나오기 전까지
        sig_start = func_open_line
        for i in range(func_open_line - 1, max(-1, func_open_line - 15), -1):
            line = lines[i].strip()
            if not line:
                break  # 빈 줄 = 시그니처 시작 전
            if line.endswith(";") or line.endswith("}") or line.endswith("*/"):
                # 이전 statement / 함수 / 주석 끝
                break
            sig_start = i

        # ── Walk forwards to find matching closing brace ──
        brace_depth = 0
        func_close_line = None
        for i in range(func_open_line, n):
            line = lines[i]
            brace_depth += line.count("{") - line.count("}")
            if brace_depth == 0:
                func_close_line = i
                break

        if func_close_line is None:
            return None

        # ── Extract ──
        func_lines = lines[sig_start : func_close_line + 1]
        return "\n".join(func_lines)



    @staticmethod
    def _sanitize_instrumentation_code(code: str) -> str:
        if not code:
            return code
        s = code.strip()
        if s.startswith("```"):
            s = re.sub(r"^```\w*\s*", "", s)
            s = re.sub(r"\s*```$", "", s)
            s = s.strip()
        natural_prefixes = [
            r"^/\*\s*(?:insert\s+before\s+line\s+\d+|before\s+line\s+\d+[,:\s]*insert)?\s*\*/\s*",
            r"^//\s*(?:insert|before|add)[^\n]*\n",
            r"^(?:insert|add)\s+(?:before|at|this)\s+[^:]*:\s*",
            r"^before\s+line\s+\d+\s*[,:]?\s*(?:insert\s*:?\s*)?",
            r"^(?:insert|add)\s*:\s*",
            r"^at\s+line\s+\d+[,:]\s*",
            r"^/\*[^*]*\*/\s*",
        ]
        for pat in natural_prefixes:
            s = re.sub(pat, "", s, count=1, flags=re.IGNORECASE)
        return s.strip()

    @staticmethod
    def _is_inside_block_comment(source: str, position: int) -> bool:
        prefix = source[:position]
        last_open  = prefix.rfind("/*")
        last_close = prefix.rfind("*/")
        return last_open > last_close

    @staticmethod
    def _find_enclosing_brace_position(source: str, position: int) -> Optional[int]:
        depth = 0
        for i in range(position - 1, -1, -1):
            c = source[i]
            if c == '}':
                depth += 1
            elif c == '{':
                if depth == 0:
                    nl = source.find('\n', i)
                    return nl + 1 if nl != -1 else i + 1
                depth -= 1
        return None

    @staticmethod
    def _inject_assertion(source: str, bug_line: int, assertion: str) -> str:
        assertion = ASanVerifier._sanitize_instrumentation_code(assertion)
        if not assertion:
            return source
        if "#include <assert.h>" not in source:
            source   = "    #include <assert.h>\n" + source
            bug_line += 1
        lines = source.splitlines(keepends=True)
        idx   = bug_line - 1
        if not (0 <= idx < len(lines)):
            return source
        offset = sum(len(l) for l in lines[:idx])
        if ASanVerifier._is_inside_block_comment(source, offset):
            log.debug("Insertion point is inside a block comment, moving up")
            for j in range(idx - 1, -1, -1):
                if "/*" in lines[j]:
                    idx = j
                    break
        brace_pos = ASanVerifier._find_enclosing_brace_position(source, offset)
        if brace_pos is None:
            log.warning("Instrumentation skipped: bug line %d outside any function", bug_line)
            return source
        if not re.search(r"[a-zA-Z_]", assertion):
            log.warning("Instrumentation skipped: empty/non-code assertion")
            return source
        indent = len(lines[idx]) - len(lines[idx].lstrip())
        assertion_line = " " * indent + assertion.rstrip(";") + ";\n"
        lines.insert(idx, assertion_line)
        return "".join(lines)

    @staticmethod
    def _build_toyota_itc_main_call(source: str, func_name: str) -> str:
        pattern = re.compile(
            rf'(?:void|int|char|float|double|long|unsigned)\s+\*?\s*{re.escape(func_name)}\s*\(([^)]*)\)',
            re.MULTILINE
        )
        match = pattern.search(source)
        if not match:
            return f"    {func_name}();\n"
        params_str = match.group(1).strip()
        if not params_str or params_str == "void":
            return f"    {func_name}();\n"
        params = [p.strip() for p in params_str.split(",")]
        default_args = []
        for param in params:
            param_lower = param.lower()
            if "*" in param:
                default_args.append("NULL")
            elif "float" in param_lower or "double" in param_lower:
                default_args.append("0.0")
            elif "char" in param_lower and "*" not in param:
                default_args.append("'a'")
            else:
                default_args.append("0")
        args_str = ", ".join(default_args)
        return f"    {func_name}({args_str});\n"

    @staticmethod
    def _write_file_inputs(llm: LLMResult, tmp: Path) -> None:
        for fname, content in (llm.file_inputs or {}).items():
            dest = tmp / fname
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(content)
            log.debug("Wrote file input: %s", dest)

    # ─────────────────────────────────────────────────────────────────────
    # Compilation - v4 핵심 개선
    # ─────────────────────────────────────────────────────────────────────

    def _find_support_dir(self, source: Path) -> Optional[Path]:
        for candidate in [
            source.parent / "testcasesupport",
            source.parent.parent / "testcasesupport",
            source.parent.parent.parent / "testcasesupport",
        ]:
            if candidate.exists():
                return candidate
        return None

    def _make_compile_cmd(
        self, src: Path, out: Path,
        source_root: Optional[Path] = None,
        mock_only: bool = False,
    ) -> str:
        """
        Build compile command.

        mock_only: True 이면 generic 모드에서 -I 옵션을 모두 빼고
                   mock_code 만으로 컴파일 시도 (가장 깔끔하고 충돌 없음).
        """
        flags      = config.asan_flags
        extra_inc  = ""
        extra_srcs = ""
        extra_libs = ""

        # ── Juliet ──
        if config.dataset_mode == "juliet":
            lookup  = source_root or src
            support = self._find_support_dir(lookup)
            if support:
                import glob as _glob
                extra_inc  = f"-I{support}"
                c_files    = _glob.glob(str(support / "*.c"))
                extra_srcs = " ".join(c_files)

        # ── Toyota ITC (기존 로직 그대로) ──
        elif config.dataset_mode == "toyota_itc" and source_root:
            for candidate in [
                source_root.parent / "include",
                source_root.parent.parent / "include",
                source_root / "include",
            ]:
                if candidate.is_dir():
                    import glob as _glob
                    extra_inc = f"-I{candidate}"
                    c_files = _glob.glob(str(candidate / "*.c"))
                    extra_srcs = " ".join(c_files)
                    break
            stem = src.stem
            sibling_dir = src.parent
            search_dirs = {sibling_dir}
            if source_root and source_root.parent.is_dir():
                search_dirs.add(source_root.parent)
                if source_root.is_dir():
                    search_dirs.add(source_root)
            siblings: list[str] = []
            for d in search_dirs:
                if not d.is_dir():
                    continue
                for sib in d.glob(f"{stem}_*.c"):
                    if sib.resolve() != src.resolve() and str(sib) not in siblings:
                        siblings.append(str(sib))
            if siblings:
                extra_srcs = (extra_srcs + " " + " ".join(siblings)).strip()
            extra_libs = "-lpthread -lm"

        # ── NEW (v4): Real-world (Redis, OpenSSL, etc.) ──
        elif config.dataset_mode in ("generic", "generic_realworld") and source_root:
            # source_root는 보통 src 파일 자체로 들어옴. 부모 디렉토리 사용
            root = source_root if source_root.is_dir() else source_root.parent
            # 만약 root 가 'src/'면 그 부모(project root)도 사용
            project_root = root
            if root.name == "src" and root.parent.is_dir():
                project_root = root.parent

            if mock_only:
                # ─ Strategy 0 (v4.1): mock-only 모드 ─
                # -I 를 전혀 안 넣고, mock_code 만 믿고 컴파일 시도.
                # #include "..." 는 _prepare_source 가 이미 주석 처리했음.
                # 가장 깨끗하지만 mock_code 가 완벽해야 작동.
                extra_inc = ""
                log.debug("Strategy 0 (mock-only, no -I) for %s", src.name)
            else:
                # ─ Strategy 1: compile_commands.json (가장 정확) ─
                entry = self._find_compile_commands_entry(src, project_root)
                if entry:
                    extra_inc = self._extract_flags_from_entry(entry)
                    log.debug("Strategy 1 (compile_commands.json) for %s", src.name)
                else:
                    # ─ Strategy 2: 자동 헤더 발견 ─
                    include_dirs = self._discover_include_dirs(project_root)
                    extra_inc = " ".join(f"-I{d}" for d in include_dirs)
                    log.debug("Strategy 2 (auto-discover, %d dirs) for %s",
                              len(include_dirs), src.name)

            # 실행 시 누락된 외부 함수는 자동으로 NULL 처리하는 링커 옵션
            import platform as _platform
            if _platform.system() == "Darwin":
                extra_libs = "-lpthread -lm"
            else:
                extra_libs = "-lpthread -lm -ldl -Wl,--unresolved-symbols=ignore-all"

        # warning suppress (real-world 코드는 노이즈 많음)
        warn_relax = (
            "-Wno-implicit-function-declaration -Wno-int-conversion "
            "-Wno-incompatible-pointer-types -Wno-builtin-declaration-mismatch "
            "-Wno-error"
        )
        if config.dataset_mode in ("generic", "generic_realworld"):
            # real-world 는 -Wno-everything 으로 모든 warning 끔
            warn_relax += " -w"

        toolchain = ""
        import platform as _platform
        if _platform.system() == "Darwin":
            sdk = Path("/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk")
            tools = Path("/Library/Developer/CommandLineTools/usr/bin")
            if sdk.exists():
                toolchain += f" -isysroot {sdk}"
            if (tools / "ld").exists():
                toolchain += f" -B{tools}"
        return (
            f"{self._compiler}{toolchain} {flags} {warn_relax} {extra_inc} "
            f"-o {out} {src} {extra_srcs} {extra_libs}"
        )

    def _compile(
        self, src: Path, out: Path, source_root: Optional[Path] = None
    ) -> Optional[ASanResult]:
        """
        Compile with progressive fallback chain (v4.1):

          Strategy 1/2 (default) → Strategy 0 (mock-only) → compile-only check

        Real-world (generic mode): tries -I flags first, then falls back to
        mock-only mode (no -I), then to compile-only check.
        """
        # ── 1차 시도: Strategy 1 또는 2 (-I 포함) ──
        cmd = self._make_compile_cmd(src, out, source_root=source_root)
        log.debug("Compile (attempt 1): %s", cmd[:200])
        try:
            proc = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=120,
            )
            if proc.returncode == 0:
                return None  # 1차 시도 성공!

            log.debug("Attempt 1 failed: %s", proc.stderr[:200])

            # ── 2차 시도 (v4.1): generic 모드면 mock-only 로 재시도 ──
            if config.dataset_mode in ("generic", "generic_realworld"):
                log.info("Trying Strategy 0 (mock-only, no -I)...")
                cmd2 = self._make_compile_cmd(
                    src, out, source_root=source_root, mock_only=True
                )
                log.debug("Compile (attempt 2): %s", cmd2[:200])
                proc2 = subprocess.run(
                    cmd2, shell=True, capture_output=True, text=True, timeout=120,
                )
                if proc2.returncode == 0:
                    log.info("✓ Strategy 0 (mock-only) succeeded!")
                    return None  # 2차 시도 성공!

                log.debug("Attempt 2 failed: %s", proc2.stderr[:200])

                # ── 3차 시도: compile-only check (링킹 빼고 .o 만 만들기) ──
                log.info("Trying compile-only (no link)...")
                fallback_cmd = cmd2.replace(f"-o {out}", f"-c -o {out}.o")
                # -Wl,... 옵션 제거 (compile-only 에서는 의미 없음)
                fallback_cmd = re.sub(r'-Wl,\S+', '', fallback_cmd)
                fb = subprocess.run(
                    fallback_cmd, shell=True, capture_output=True,
                    text=True, timeout=60,
                )
                if fb.returncode == 0:
                    log.info("✓ Compile-only succeeded (no main/link)")
                    return ASanResult(
                        Verdict.SKIPPED,
                        stderr=("Compile-only OK but full link failed. "
                                "Real-world dependency limitation — function "
                                "compiles in isolation but cannot be executed "
                                "without full project linking."),
                        returncode=0,
                        compile_cmd=cmd2,
                        match_level="infra",
                    )

                # 모든 fallback 실패 → 가장 정보가 많은 에러 사용
                log.warning("All fallback strategies failed")
                final_stderr = proc2.stderr or proc.stderr or fb.stderr
                return ASanResult(
                    Verdict.COMPILE_ERROR,
                    stderr=final_stderr,
                    returncode=proc2.returncode,
                    compile_cmd=cmd2,
                    match_level="infra",
                )

            # generic 모드가 아니면 그냥 실패 (기존 동작)
            log.warning("Compilation failed:\n%s", proc.stderr[:500])
            return ASanResult(
                Verdict.COMPILE_ERROR,
                stderr=proc.stderr,
                returncode=proc.returncode,
                compile_cmd=cmd,
                match_level="infra",
            )
        except subprocess.TimeoutExpired:
            return ASanResult(
                Verdict.COMPILE_ERROR,
                stderr="Compilation timed out",
                match_level="infra",
            )
        return None

    # ── Execution / Classification (기존과 동일) ────────────────────────

    def _run(
        self,
        report: BugReport,
        llm: LLMResult,
        binary: Path,
        cwd: Path,
        compile_cmd: str,
    ) -> ASanResult:
        cmd_parts, stdin_data = self._build_run_command(binary, llm, cwd)
        run_cmd = " ".join(cmd_parts)
        log.debug("[%s] Run: %s", report.id, run_cmd)

        import platform as _platform
        if _platform.system() == "Darwin":
            _asan_opts = "halt_on_error=0:detect_leaks=0:print_stacktrace=1"
        else:
            detect_leaks = "1" if _is_memory_leak_bug_type(report.bug_type) else "0"
            _asan_opts = f"detect_leaks={detect_leaks}:abort_on_error=0:halt_on_error=0"
        env = {**os.environ, "ASAN_OPTIONS": _asan_opts, "UBSAN_OPTIONS": "print_stacktrace=1"}
        symbolizer = shutil.which("llvm-symbolizer")
        if symbolizer:
            env["ASAN_SYMBOLIZER_PATH"] = symbolizer
        env.update(llm.env_vars or {})

        try:
            proc = subprocess.run(
                cmd_parts,
                input=stdin_data,
                capture_output=True,
                text=True,
                timeout=config.timeout_seconds,
                cwd=str(cwd),
                env=env,
            )
        except subprocess.TimeoutExpired as exc:
            partial_stderr = (exc.stderr or b"")
            partial_stdout = (exc.stdout or b"")
            if isinstance(partial_stderr, bytes):
                partial_stderr = partial_stderr.decode("utf-8", errors="replace")
            if isinstance(partial_stdout, bytes):
                partial_stdout = partial_stdout.decode("utf-8", errors="replace")
            partial_combined = partial_stderr + partial_stdout
            log.warning("[%s] Execution timed out.", report.id)
            return ASanResult(
                Verdict.TIMEOUT,
                stderr=partial_stderr[:1000],
                asan_output=partial_combined[:2000],
                returncode=-1,
                compile_cmd=compile_cmd,
                run_cmd=run_cmd,
                match_level="infra",
            )
        except Exception as exc:
            return ASanResult(
                Verdict.RUNTIME_ERROR,
                stderr=str(exc),
                compile_cmd=compile_cmd,
                run_cmd=run_cmd,
                match_level="infra",
            )

        combined = proc.stderr + proc.stdout
        return self._classify(combined, proc.returncode, compile_cmd, run_cmd, report)

    @staticmethod
    def _build_run_command(
        binary: Path,
        llm: LLMResult,
        cwd: Path,
    ) -> tuple[list[str], str]:
        cmd = [str(binary)]
        if llm.input_type == "args":
            cmd.extend(llm.args or [])
        elif llm.input_type == "file":
            resolved_args = [
                str(cwd / a) if not a.startswith("-") and "." in a else a
                for a in (llm.args or [])
            ]
            cmd.extend(resolved_args)
        stdin_data = llm.stdin_data if llm.input_type in ("stdin", "args") else ""
        return cmd, stdin_data

    @staticmethod
    def _classify(
        output: str,
        returncode: int,
        compile_cmd: str,
        run_cmd: str,
        report: Optional[BugReport] = None,  # v3 패치: bug_type/location 검증용
    ) -> ASanResult:
        crash_type = ""
        crash_line = ""
        asan_match = _ASAN_ERROR_RE.search(output)
        if asan_match:
            crash_type = asan_match.group(1).strip()
        if not crash_type:
            ub_match = _UBSAN_ERROR_RE.search(output)
            if ub_match:
                crash_type = "ubsan:" + ub_match.group(1).strip()
        if not crash_type:
            lsan_match = _LSAN_ERROR_RE.search(output)
            if lsan_match:
                crash_type = "leak:" + lsan_match.group(1).strip()
            elif _LSAN_LEAK_SUMMARY_RE.search(output) or _LSAN_DETECT_RE.search(output):
                crash_type = "leak:detected memory leaks"
        loc_match = _CRASH_LOC_RE.search(output)
        if loc_match:
            crash_line = loc_match.group(1).strip()
        if not crash_type and returncode < 0:
            crash_type = f"signal:{abs(returncode)}"

        if not crash_type:
            return ASanResult(
                verdict=Verdict.LIKELY_FP,
                crash_type="",
                crash_line=crash_line,
                asan_output=output,
                returncode=returncode,
                compile_cmd=compile_cmd,
                run_cmd=run_cmd,
                match_level="no_crash",
                type_matched=False,
            )

        type_matched = (
            _crash_matches_bug_type(crash_type, report.bug_type)
            if report is not None
            else True
        )
        user_frames = _extract_user_code_frames(output)
        if report is not None and not user_frames:
            ub_location = _UBSAN_LOCATION_RE.search(output)
            if ub_location:
                user_frames = [(
                    getattr(report, "procedure", "") or "(unknown)",
                    ub_location.group(1), int(ub_location.group(2)),
                )]

        if report is None:
            matched_func, matched_line = ("", 0)
            if user_frames:
                matched_func, _, matched_line = user_frames[0]
            return ASanResult(
                verdict=Verdict.FAMILY_TP,
                crash_type=crash_type,
                crash_line=crash_line,
                asan_output=output,
                returncode=returncode,
                compile_cmd=compile_cmd,
                run_cmd=run_cmd,
                match_level="family_no_proc",
                type_matched=type_matched,
                matched_frame=matched_func,
                matched_line=matched_line,
            )

        bug_basename = os.path.basename(report.file) if report.file else ""
        same_file_frames = [
            (func, path, line)
            for func, path, line in user_frames
            if bug_basename and os.path.basename(path) == bug_basename
        ]

        if not same_file_frames:
            matched_func, matched_line = ("", 0)
            if user_frames:
                matched_func, _, matched_line = user_frames[0]
            return ASanResult(
                verdict=Verdict.CROSS_DETECTION,
                crash_type=crash_type,
                crash_line=crash_line,
                asan_output=output,
                returncode=returncode,
                compile_cmd=compile_cmd,
                run_cmd=run_cmd,
                match_level="diff_file",
                type_matched=type_matched,
                matched_frame=matched_func,
                matched_line=matched_line,
            )

        bug_proc = (getattr(report, "procedure", "") or "").strip()
        matched_func = ""
        matched_line = 0

        if bug_proc:
            top_func, _, top_line = same_file_frames[0]
            if _procedure_in_frame(bug_proc, top_func):
                verdict = Verdict.STRICT_TP
                match_level = "strict"
                matched_func = top_func
                matched_line = top_line
            else:
                for func, _, line in same_file_frames:
                    if _procedure_in_frame(bug_proc, func):
                        verdict = Verdict.FAMILY_TP
                        match_level = "family_chain"
                        matched_func = func
                        matched_line = line
                        break
                else:
                    verdict = Verdict.CROSS_DETECTION
                    match_level = "cross_proc"
                    matched_func = top_func
                    matched_line = top_line
        else:
            verdict = Verdict.FAMILY_TP
            match_level = "family_no_proc"
            matched_func, _, matched_line = same_file_frames[0]

        return ASanResult(
            verdict=verdict,
            crash_type=crash_type,
            crash_line=crash_line,
            asan_output=output,
            returncode=returncode,
            compile_cmd=compile_cmd,
            run_cmd=run_cmd,
            match_level=match_level,
            type_matched=type_matched,
            matched_frame=matched_func,
            matched_line=matched_line,
        )

        # ── v3 패치: Bug type / Location 매칭 게이트 ──────────────────────
        # crash 가 잡혔어도 Infer 가 경고한 종류·위치와 일치하지 않으면
        # UNCONFIRMED 로 떨어뜨린다. 이게 Toyota ITC wo_(FP) 데이터셋에서
        # 같은 파일 안 다른 sub-function 의 leak/crash 가 TP 로 오분류되는
        # 것을 막는다.
        #
        # v4.5 패치: location matching 에 asan_output 전체와 bug_type/
        # procedure 를 함께 전달하여, sanitizer 내부 frame 을 제외한
        # user-code stack 에서 매칭을 시도한다. MEMORY_LEAK 부류의
        # Recall=0% 문제를 회복한다.
        mismatch_tag = ""
        if crash_type and report is not None:
            if not _crash_matches_bug_type(crash_type, report.bug_type):
                log.info(
                    "[%s] Crash type mismatch: bug=%s crash=%s → LIKELY_FP",
                    report.id, report.bug_type, crash_type,
                )
                mismatch_tag = f"type_mismatch({crash_type})"
            elif not _crash_location_matches(
                    crash_line, report.file, report.line,
                    asan_output=output,
                    bug_type=report.bug_type,
                    bug_procedure=getattr(report, "procedure", "") or ""):
                log.info(
                    "[%s] Crash location mismatch: bug=%s:%d crash=%s → LIKELY_FP",
                    report.id, report.file, report.line, crash_line or "(none)",
                )
                mismatch_tag = f"loc_mismatch({crash_type})"

        if mismatch_tag:
            verdict = Verdict.LIKELY_FP
            crash_type = mismatch_tag
        elif crash_type:
            verdict = Verdict.STRICT_TP
        elif returncode != 0:
            verdict = Verdict.LIKELY_FP
        else:
            verdict = Verdict.LIKELY_FP
        return ASanResult(
            verdict      = verdict,
            crash_type   = crash_type,
            crash_line   = crash_line,
            asan_output  = output,
            returncode   = returncode,
            compile_cmd  = compile_cmd,
            run_cmd      = run_cmd,
        )
