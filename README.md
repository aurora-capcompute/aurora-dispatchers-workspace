# aurora-dispatchers-workspace

Policy-bounded local filesystem capabilities for Aurora.

Capabilities: `workspace.list`, `workspace.stat`, `workspace.read`,
`workspace.search`, `workspace.write`, `workspace.patch`, `workspace.mkdir`,
`workspace.move`, and `workspace.delete`.

Register the dispatcher:

```go
registry.New(workspace.Registration{})
```

Example manifest capability:

```json
{
  "name": "workspace.patch",
  "settings": {
    "root": "/home/user/project",
    "read_allow": ["**"],
    "write_allow": ["**"],
    "exclude": [".git/**", ".env"],
    "allow_write": true,
    "max_write_bytes": 2097152
  }
}
```

Absolute paths, traversal, symlink traversal, special files, oversized I/O, and
stale expected hashes are rejected. Directory deletion is intentionally not
supported. This dispatcher operates directly on the host and is not a sandbox.
