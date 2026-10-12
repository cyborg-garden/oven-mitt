# ovenmitt (Python)

Client library and MCP server for the [ovenmitt](https://github.com/utunga/oven-mitt) write-only vault daemon. Installed in the agent container; the daemon never has it.

```python
from ovenmitt import VaultClient

c = VaultClient("/run/ovenmitt/ovenmitt.sock")
info = c.put(stream, "private", mime="text/plain")      # → handle + metadata, never content
c.export(info.handle, "archive", "out.txt")
with c.resolve(info.handle, "team-chat", "chat:group/team", credential) as r:
    for chunk in r.stream:                                # consumer tool code only
        ...
```

`ovenmitt mcp --socket /run/ovenmitt/ovenmitt.sock` serves the eight metadata-only tools over stdio.

Every daemon refusal raises `OvenmittError` with `.code` from the closed set in the PRD (§7).
