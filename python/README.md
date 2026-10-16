# ovenmitt (Python)

<!-- FIXME: move this utunga/ URL to cyborg-garden/oven-mitt as soon as that is fixed (DEVELOPMENT.md §13) -->
Client library and MCP server for the [ovenmitt](https://github.com/utunga/oven-mitt) write-only vault daemon. Installed in the agent container; the daemon never has it.

```python
from ovenmitt import VaultClient

c = VaultClient("/run/ovenmitt/ovenmitt.sock")
info = c.put(stream, "private", mime="text/plain")      # → handle + metadata, never content
c.export(info.handle, "archive", "out.txt")
with c.resolve(info.handle, "team-chat", "chat:group/team", credential) as r:
    for chunk in r.stream:                                # consumer tool code only
        ...
with c.resolve_path(info.handle, "team-chat", "chat:group/team", credential, "out.txt") as path:
    send_file(path)                                       # one-shot memfd path, Linux only
```

`pip install ovenmitt` installs the client, which depends only on `httpx`. `pip install 'ovenmitt[mcp]'` adds the MCP server.

`ovenmitt mcp --socket /run/ovenmitt/ovenmitt.sock` serves the eight metadata-only tools over stdio.

Every daemon refusal raises `OvenmittError` with `.code` from the closed set in the PRD (§7).
