"""
Decision-tree smoke tests for ASan 5-case classification.

This replaces the old line-tolerance location test. The new model classifies
crashes by same-file stack frames and word-boundary procedure matching.
"""

import sys

sys.path.insert(0, ".")

from pipeline.asan_verifier import ASanVerifier, Verdict, _procedure_in_frame
from pipeline.infer_parser import BugReport


PASSED = []
FAILED = []


def check(name, got, expected):
    if got == expected:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append(name)
        print(f"  FAIL  {name}  got={got}  expected={expected}")


def report(file="null_pointer.c", procedure="null_pointer_001", bug_type="NULL_DEREFERENCE"):
    return BugReport(
        bug_type=bug_type,
        qualifier="test",
        severity="ERROR",
        line=30,
        column=-1,
        procedure=procedure,
        file=file,
    )


def classify(output, bug_report):
    verifier = ASanVerifier.__new__(ASanVerifier)
    return verifier._classify(output, 1, "clang ...", "./target", bug_report)


print("\n[Case 1] STRICT_TP: top same-file frame matches Infer procedure")
strict_output = """\
==1==ERROR: AddressSanitizer: SEGV on unknown address 0x0
    #0 0x401abc in null_pointer_001 /home/user/zolup/01.w_Defects/null_pointer.c:30
    #1 0x401def in main /home/user/zolup/01.w_Defects/null_pointer.c:600
"""
res = classify(strict_output, report())
check("top frame procedure match", res.verdict, Verdict.STRICT_TP)
check("strict match_level", res.match_level, "strict")
check("strict matched_frame", res.matched_frame, "null_pointer_001")


print("\n[Case 2] FAMILY_TP: procedure appears deeper in same-file call chain")
family_output = """\
==2==ERROR: AddressSanitizer: SEGV on unknown address 0x0
    #0 0x401111 in helper_wrapper /home/user/zolup/01.w_Defects/null_pointer.c:25
    #1 0x401222 in null_pointer_001 /home/user/zolup/01.w_Defects/null_pointer.c:30
"""
res = classify(family_output, report())
check("call-chain procedure match", res.verdict, Verdict.FAMILY_TP)
check("family match_level", res.match_level, "family_chain")


print("\n[Case 3] CROSS_DETECTION: same file, different procedure")
cross_proc_output = """\
==3==ERROR: AddressSanitizer: SEGV on unknown address 0x0
    #0 0x401111 in null_pointer_999 /home/user/zolup/01.w_Defects/null_pointer.c:90
"""
res = classify(cross_proc_output, report())
check("same file different procedure", res.verdict, Verdict.CROSS_DETECTION)
check("cross_proc match_level", res.match_level, "cross_proc")


print("\n[Case 4] CROSS_DETECTION: user frame is in a different file")
diff_file_output = """\
==4==ERROR: AddressSanitizer: SEGV on unknown address 0x0
    #0 0x401111 in null_pointer_001 /home/user/zolup/01.w_Defects/other.c:30
"""
res = classify(diff_file_output, report())
check("different file crash", res.verdict, Verdict.CROSS_DETECTION)
check("diff_file match_level", res.match_level, "diff_file")


print("\n[Case 5] LIKELY_FP: no crash detected")
verifier = ASanVerifier.__new__(ASanVerifier)
res = verifier._classify("program exited normally", 0, "", "", report())
check("no crash", res.verdict, Verdict.LIKELY_FP)
check("no_crash match_level", res.match_level, "no_crash")


print("\n[Case 6] FAMILY_TP: no Infer procedure info")
res = classify(strict_output, report(procedure=""))
check("missing procedure is conservative family", res.verdict, Verdict.FAMILY_TP)
check("family_no_proc match_level", res.match_level, "family_no_proc")


print("\n[Case 7] word-boundary procedure matching")
check(
    "exact procedure token matches",
    _procedure_in_frame("func_pointer_011", "func_pointer_011"),
    True,
)
check(
    "partial function-name collision rejected",
    _procedure_in_frame("func_pointer_011", "func_pointer_011_func_001"),
    False,
)


print("\n[Case 8] type mismatch is stored, not promoted into verdict")
type_output = """\
==8==ERROR: AddressSanitizer: SEGV on unknown address 0x0
    #0 0x401abc in main /tmp/test.c:10
"""
res = classify(type_output, report(file="test.c", procedure="main", bug_type="USE_AFTER_FREE"))
check("type mismatch keeps strict verdict", res.verdict, Verdict.STRICT_TP)
check("type_matched false", res.type_matched, False)


print("\n" + "=" * 60)
print(f"  PASSED: {len(PASSED)}")
print(f"  FAILED: {len(FAILED)}")
if FAILED:
    print("  Failed cases:")
    for name in FAILED:
        print(f"    - {name}")
    sys.exit(1)
print("  All tests passed.")
print("=" * 60)
