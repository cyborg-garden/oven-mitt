# ovenmitt (Python)

Client library and MCP server for the [ovenmitt](https://github.com/cyborg-garden/oven-mitt) write-only vault daemon.
Install it in the agent container.
The daemon container never has it.

```sh
pip install ovenmitt            # the client; depends only on httpx
pip install 'ovenmitt[mcp]'     # adds the MCP server
```

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

`ovenmitt mcp --socket /run/ovenmitt/ovenmitt.sock` serves the eight metadata-only tools over stdio.
Without the `mcp` extra it exits with an install hint.

Every daemon refusal raises `OvenmittError`.
Its `.code` comes from the closed set in [PRD §7](https://github.com/cyborg-garden/oven-mitt/blob/tumu/PRD.md#7-error-model).
The full method list is in [PRD §10.2](https://github.com/cyborg-garden/oven-mitt/blob/tumu/PRD.md#102-library-contract-ovenmitt-python-package-protocol-1).
