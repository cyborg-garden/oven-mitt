"""The v1 acceptance gate (DEVELOPMENT.md M8): AT-8, AT-11 via docker exec,
AT-13 across containers, AT-20, plus the brief's §9 end to end."""

from __future__ import annotations

import secrets

CLIENT = "from ovenmitt import VaultClient, OvenmittError; c = VaultClient('/run/ovenmitt/ovenmitt.sock'); "


def _sentinel() -> str:
    return "".join(chr(ord("a") + b % 26) for b in secrets.token_bytes(64))


def test_put_export_resolve_round_trip(stack):
    """Brief §9.1–9.2 through the real containers."""
    body = _sentinel()
    out = stack.agent_py(
        CLIENT
        + f"i = c.put({body!r}.encode(), 'private', name='hui.txt', mime='text/plain', labels=['e2e']); "
        + "print(i.handle, i.size, i.mime, i.name)"
    ).split()
    handle, size, mime, name = out
    assert handle.startswith("v_") and size == "64" and mime == "text/plain" and name == "hui.txt"

    # export inside the daemon container
    out = stack.agent_py(CLIENT + f"r = c.export({handle!r}, 'archive', 'out.txt'); print(r.size)")
    assert out.strip() == "64"
    assert stack.daemon("cat", "/var/lib/ovenmitt/export/archive/out.txt").stdout.decode() == body

    # resolve with a credential issued by the operator in the daemon container
    r = stack.daemon("ovenmitt", "credential", "issue", "--name", "vault_send", "--vault", "private")
    token = r.stdout.decode().strip()
    assert token.startswith("ovm_")
    target = f"chat:group/{stack.pattern_marker}"
    out = stack.agent_py(
        CLIENT
        + f"r = c.resolve({handle!r}, 'team-chat', {target!r}, {token!r}); print(r.read().decode())"
    )
    assert out.strip() == body

    stack._handle = handle  # noqa: SLF001 - shared with later tests
    stack._body = body
    stack._token = token


def test_leak_attempts_fail_safely_and_are_audited(stack):
    """Brief §9.3: no read path, store absent, refusals audited."""
    handle = stack._handle
    body = stack._body
    token = stack._token
    before = int(stack.daemon("sh", "-c", "wc -l < /var/lib/ovenmitt/audit/audit.jsonl").stdout.decode().strip())

    checks = [
        # resolve without credential
        (f"c.resolve({handle!r}, 'team-chat', 'chat:group/x', 'ovm_00000000_x')", "CREDENTIAL_INVALID"),
        # resolve to an undeclared destination
        (f"c.resolve({handle!r}, 'nope', 'chat:group/x', {token!r})", "DESTINATION_NOT_FOUND"),
        # export outside the root
        (f"c.export({handle!r}, 'archive', '../escape.txt')", "FILENAME_INVALID"),
        # export to a send destination
        (f"c.export({handle!r}, 'team-chat', 'x.txt')", "DESTINATION_KIND_MISMATCH"),
    ]
    for expr, code in checks:
        out = stack.agent_py(
            CLIENT + f"\ntry:\n    {expr}\n    print('OK')\nexcept OvenmittError as e:\n    print(e.code)\n"
        )
        assert out.strip() == code, (expr, out)

    # no read route: every metadata route is free of the content
    out = stack.agent_py(
        CLIENT
        + f"import json; print(json.dumps([c.stat({handle!r}).to_dict(), [o.to_dict() for o in c.list()], [v.__dict__ for v in c.vaults()], [d.__dict__ for d in c.destinations('private')]]))"
    )
    assert body not in out
    assert stack.root_marker not in out and stack.pattern_marker not in out

    after = int(stack.daemon("sh", "-c", "wc -l < /var/lib/ovenmitt/audit/audit.jsonl").stdout.decode().strip())
    assert after - before == len(checks), "exactly one audit entry per refusal"


def test_store_is_not_in_the_agent_container(stack):
    """AT-8 / SI-3."""
    body = stack._body
    # compose: the agent services mount only the socket volume
    cfg = stack.config_json()
    for svc in ("agent", "test-agent"):
        mounts = cfg["services"][svc].get("volumes", [])
        assert len(mounts) == 1, mounts
        assert mounts[0]["source"] in ("ovenmitt-sock", "oven-mitt_ovenmitt-sock", "docker_ovenmitt-sock") or mounts[0]["target"] == "/run/ovenmitt"
        assert mounts[0]["target"] == "/run/ovenmitt"
    # runtime: no key files, audit log, config, or object directories anywhere
    r = stack.agent(
        "sh",
        "-c",
        "find / -xdev \\( -name '*.key' -o -name 'audit.jsonl' -o -name 'ovenmitt.toml' -o -name 'dek.wrap' -o -name 'body.enc' \\) 2>/dev/null | grep -v '^/proc' ; true",
    )
    assert r.stdout.decode().strip() == "", r.stdout.decode()
    # and the sentinel content is nowhere on its filesystem
    r = stack.agent("sh", "-c", f"grep -rIl --exclude-dir=proc --exclude-dir=sys --exclude-dir=dev {body} / 2>/dev/null; true")
    assert r.stdout.decode().strip() == "", r.stdout.decode()
    # the socket is the only thing under /run/ovenmitt
    r = stack.agent("sh", "-c", "ls -A /run/ovenmitt")
    assert r.stdout.decode().split() == ["ovenmitt.sock"]


def test_daemon_has_no_tcp_listener(stack):
    """AT-20 / SI-2: nothing in LISTEN state in /proc/net/tcp{,6}."""
    for f in ("/proc/net/tcp", "/proc/net/tcp6"):
        r = stack.daemon("cat", f, check=False)
        if r.returncode != 0:
            continue
        lines = r.stdout.decode().splitlines()[1:]
        listening = [l for l in lines if l.split()[3] == "0A"]
        assert listening == [], listening


def test_topology_never_leaks_into_the_audit_log(stack):
    """AT-13 / SI-8 across containers."""
    log = stack.daemon("cat", "/var/lib/ovenmitt/audit/audit.jsonl").stdout.decode()
    assert stack.root_marker not in log
    assert stack.pattern_marker in log, "the pattern marker appears only because the *target* is logged"
    assert "/var/lib/ovenmitt/export" not in log
    assert stack._body not in log
    assert stack._token.rsplit("_", 1)[1] not in log


def test_audit_verify_and_review_via_docker_exec(stack):
    """AT-11 / brief §9.4."""
    r = stack.daemon("ovenmitt", "audit", "verify")
    assert r.stdout.decode().startswith("ok:")
    r = stack.daemon("ovenmitt", "audit", "review", check=False)
    assert r.returncode == 1, r.stderr.decode()
    err = r.stderr.decode()
    for reason in ("CREDENTIAL_INVALID", "DESTINATION_NOT_FOUND", "FILENAME_INVALID", "DESTINATION_KIND_MISMATCH"):
        assert f"reason={reason}" in err, err
    r = stack.daemon("ovenmitt", "audit", "review", "--threshold", "critical", check=False)
    assert r.returncode == 0
    r = stack.daemon("ovenmitt", "audit", "head")
    assert len(r.stdout.decode().strip()) == 64


def test_operator_sees_hidden_names_the_agent_does_not(stack):
    out = stack.agent_py(CLIENT + "i = c.put(b'x', 'hidden', name='secret-name.txt'); print(i.handle, i.name)")
    handle, name = out.split()
    assert name == "None"
    r = stack.daemon("ovenmitt", "object", "stat", handle)
    assert "name:       secret-name.txt" in r.stdout.decode()


def test_mcp_tool_list_in_the_agent_image(stack):
    """SI-13 inside the shipped image."""
    out = stack.agent_py(
        "import asyncio; from ovenmitt.mcp import build_server, TOOL_NAMES; "
        "s = build_server('/run/ovenmitt/ovenmitt.sock'); "
        "print(sorted(t.name for t in asyncio.run(s.list_tools())) == sorted(TOOL_NAMES), len(TOOL_NAMES))"
    )
    assert out.split() == ["True", "8"]
