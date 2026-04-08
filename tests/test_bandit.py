import pytest

from evaluation.bandit import BanditFinding, findings_to_cwe_labels, run_bandit

# --- CWE-78: Command injection ---

CLEAN_CODE = """
def add(a, b):
    return a + b
"""

COMMAND_INJECTION = """
import subprocess
user_input = input("cmd: ")
subprocess.call(user_input, shell=True)
"""

SUBPROCESS_WITH_SHELL_FALSE = """
import subprocess
subprocess.call(["ls", "-la"])
"""

# --- CWE-89: SQL injection ---

SQL_INJECTION = """
def get_user(username):
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    return query
"""

# --- CWE-798: Hardcoded credentials ---

HARDCODED_PASSWORD = """
password = "supersecret123"
api_key = "sk-abc123"
"""


def test_clean_code_no_findings():
    findings = run_bandit(CLEAN_CODE)
    assert findings == []


def test_command_injection_detected():
    findings = run_bandit(COMMAND_INJECTION)
    cwes = findings_to_cwe_labels(findings)
    assert "CWE-78" in cwes


def test_subprocess_partial_path_flagged_by_bandit():
    # Bandit B607: partial executable path is a PATH-hijacking risk.
    # The LLM monitor should NOT flag this (no user input, no shell interpolation),
    # so this will show up as a Bandit false positive in eval results.
    findings = run_bandit(SUBPROCESS_WITH_SHELL_FALSE)
    cwes = findings_to_cwe_labels(findings)
    assert "CWE-78" in cwes


def test_sql_injection_detected():
    findings = run_bandit(SQL_INJECTION)
    cwes = findings_to_cwe_labels(findings)
    assert "CWE-89" in cwes


def test_hardcoded_password_detected():
    findings = run_bandit(HARDCODED_PASSWORD)
    cwes = findings_to_cwe_labels(findings)
    assert "CWE-798" in cwes


def test_findings_to_cwe_labels_deduplication():
    findings = [
        BanditFinding(test_id="B602", cwe="CWE-78", severity="HIGH", confidence="HIGH",
                      line_number=1, code="x", issue_text="cmd injection"),
        BanditFinding(test_id="B603", cwe="CWE-78", severity="MEDIUM", confidence="HIGH",
                      line_number=2, code="y", issue_text="cmd injection"),
        BanditFinding(test_id="B608", cwe="CWE-89", severity="MEDIUM", confidence="LOW",
                      line_number=3, code="z", issue_text="sql injection"),
    ]
    labels = findings_to_cwe_labels(findings)
    assert labels == ["CWE-78", "CWE-89"]
    assert len(labels) == 2  # CWE-78 deduplicated
