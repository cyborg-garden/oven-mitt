---
name: ovenmitt
description: How to handle protected outputs with the ovenmitt_vault_* tools - what a handle is, how to send one to the person you're talking to, and why you never read it. Read whenever a tool gives you a handle (v_...) instead of content, or someone asks for a file you only hold by handle.
---

# ovenmitt: protected outputs

Some outputs must never pass through your context, because the model provider could keep or learn from what you read. Those outputs live in an **ovenmitt vault**. You hold them by **handle** (`v_` and 12 hex characters), never by content. Think oven mitt: you can pick the thing up and move it; you can't feel it.

## What you can do

| Tool | What it does |
|---|---|
| `ovenmitt_vault_send` | sends an object to the person you're talking to, as a file in this chat |
| `ovenmitt_vault_list` | lists objects in a vault: handles, sizes, types, labels, expiry |
| `ovenmitt_vault_stat` | the same, for one handle |
| `ovenmitt_vault_label` | sets labels, which you can see |
| `ovenmitt_vault_put` | puts a file you have into a vault, if you are asked to protect it |
| `ovenmitt_vault_delete` | deletes an object for good |
| `ovenmitt_vault_list_destinations` | shows which platforms the operator allows sends to |

Nothing returns content. That is the point, not a gap.

**Vault names.** Never guess one. Usually there is only one vault, and then you can leave `vault` out of every call. `ovenmitt_vault_list` with no `vault` returns every vault's name along with its objects.

**Putting a file.** Write it somewhere you are allowed to write, such as your working directory or home directory. A shared temp directory like `/tmp` may be off-limits for writes. Then call `ovenmitt_vault_put` with its path and `remove_source: true`, so no copy is left behind.

## Rules

1. **A handle is the deliverable.** When a tool hands you one, the job is to get it to the person, not to know what's in it. Send it, and say you've sent it. Don't summarise, quote or guess at it.
2. **Never try to read an object.** Don't look for its bytes on disk, in the socket, or anywhere else, and don't ask the user to paste it back to you. If someone asks what it says, explain that it's protected, so you deliver it without reading it.
3. **Sends only go to this chat.** `ovenmitt_vault_send` has no way to name another chat or person. If someone wants it elsewhere, they can forward it themselves.
4. **Refusals are expected, and audited.** If a send is refused (for example, the operator hasn't allowed this platform), tell the user plainly and stop. Don't retry in another way, export it, or convert it.
5. **Labels and filenames are visible to you.** Never put content in them. A filename label is fine to reuse when you resend.
6. **API keys and passwords never go in an ovenmitt vault.** The vault protects outputs. Keys live in the operator's key store.

## Resending

Objects stay in the vault until they expire (`expires_at` in `ovenmitt_vault_list`). If someone asks for a file again, call `ovenmitt_vault_list` with no vault, find the object by its labels or time, and send it again with `ovenmitt_vault_send`. Pass a filename label as `filename` so it arrives under the same name.
