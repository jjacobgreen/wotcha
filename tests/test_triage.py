from monitor.models import AgentEvent
from monitor.triage import triage_event


def write_event(content: str, file_path: str = "/project/app.py") -> AgentEvent:
    return AgentEvent(
        session_id="s1", tool_name="Write",
        tool_input={"file_path": file_path, "content": content},
        cwd="/project",
    )


def bash_event(command: str) -> AgentEvent:
    return AgentEvent(
        session_id="s1", tool_name="Bash",
        tool_input={"command": command},
        cwd="/project",
    )


# ── CWE-78 ────────────────────────────────────────────────────────────────────

def test_bash_shell_interpolation_escalates():
    r = triage_event(bash_event('echo "hello $USER"'))
    assert r.should_escalate
    assert "CWE-78" in r.cwe_candidates


def test_bash_subshell_escalates():
    r = triage_event(bash_event("result=$(cat /etc/passwd)"))
    assert r.should_escalate
    assert "CWE-78" in r.cwe_candidates


def test_bash_eval_escalates():
    r = triage_event(bash_event("eval $user_input"))
    assert r.should_escalate
    assert "CWE-78" in r.cwe_candidates


def test_bash_clean_command_no_escalation():
    r = triage_event(bash_event("ls -la /tmp"))
    assert not r.should_escalate


def test_python_os_system_escalates():
    r = triage_event(write_event("import os\nos.system(cmd)\n"))
    assert r.should_escalate
    assert "CWE-78" in r.cwe_candidates


def test_python_subprocess_escalates():
    r = triage_event(write_event("subprocess.call(args, shell=True)\n"))
    assert r.should_escalate
    assert "CWE-78" in r.cwe_candidates


def test_python_eval_escalates():
    r = triage_event(write_event("result = eval(user_input)\n"))
    assert r.should_escalate
    assert "CWE-78" in r.cwe_candidates


def test_python_clean_code_no_escalation():
    r = triage_event(write_event("def add(a, b):\n    return a + b\n"))
    assert not r.should_escalate


def test_non_python_file_ignored():
    r = triage_event(write_event("os.system(cmd)", file_path="/project/notes.txt"))
    assert not r.should_escalate


# ── CWE-89 ────────────────────────────────────────────────────────────────────

def test_sql_string_concat_escalates():
    code = 'query = "SELECT * FROM users WHERE name = \'" + name + "\'"\n'
    r = triage_event(write_event(code))
    assert r.should_escalate
    assert "CWE-89" in r.cwe_candidates


def test_sql_format_string_escalates():
    code = 'q = f"SELECT * FROM users WHERE id = {user_id}"\n'
    r = triage_event(write_event(code))
    assert r.should_escalate
    assert "CWE-89" in r.cwe_candidates


# ── CWE-798 ───────────────────────────────────────────────────────────────────

def test_hardcoded_password_escalates():
    r = triage_event(write_event('password = "hunter2"\n'))
    assert r.should_escalate
    assert "CWE-798" in r.cwe_candidates


def test_hardcoded_api_key_escalates():
    r = triage_event(write_event('api_key = "sk-abc123def456"\n'))
    assert r.should_escalate
    assert "CWE-798" in r.cwe_candidates


def test_password_variable_no_literal_no_escalation():
    # Assigning a variable, not a string literal
    r = triage_event(write_event("password = get_password_from_env()\n"))
    assert "CWE-798" not in r.cwe_candidates


# ── Multi-CWE ─────────────────────────────────────────────────────────────────

def test_multiple_cwes_in_one_file():
    code = (
        'password = "secret"\n'
        'query = "SELECT * FROM users WHERE id = " + uid\n'
    )
    r = triage_event(write_event(code))
    assert "CWE-89" in r.cwe_candidates
    assert "CWE-798" in r.cwe_candidates
