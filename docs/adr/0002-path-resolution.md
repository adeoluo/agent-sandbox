# ADR 0002: Resolve paths component by component, following symlinks before `..`

- Status: accepted
- Date: 2026-11-01

## Context

Path checks are only as good as the path they check. Common mistakes:

- Lexical normalization (`a/link/..` becomes `a`) applies `..` before following `link`,
  which is not what the kernel does.
- `std::fs::canonicalize` fails for paths that do not exist yet, and a write usually
  targets a path that does not exist yet.
- A dangling symlink in a writable directory (`scratch/out -> /etc/cron.d/job`) redirects
  a write that "looks" inside scratch.

## Decision

`paths::resolve` walks the path one component at a time from `/`:

- For an existing symlink, read its target and splice the target's components in front
  of the remaining ones (absolute targets restart at `/`). At most 40 links are followed,
  matching Linux `MAXSYMLINKS`; more is an error and the request is denied.
- `..` pops the already-resolved prefix, so it is applied after symlink resolution.
- Components that do not exist are appended as-is, so the result names the location a
  write would create.

The resolved path is compared against resolved roots with component-wise `starts_with`
(so `/a/bc` is not inside `/a/b`). Text is checked before resolution: NUL, control
characters, bidi and zero-width characters, and separator lookalikes such as U+2215 and
U+FF0F are rejected. They are not escapes on Unix by themselves, but they make a path
display differently from what the kernel sees, and other layers may normalize them.

A property test checks that `resolve` equals `realpath(3)` for every generated path that
exists, and another that no allowed write resolves outside the writable roots.

## Consequences

- Escapes through `..`, absolute paths, symlinked directories, dangling links, and link
  loops are denied by construction, and the tests cover each.
- There is an unavoidable time-of-check/time-of-use window between the check and the
  child's own `open`. The file API narrows it with `O_NOFOLLOW` on the final component; the
  OS backend closes it for writes on both platforms because the kernel checks again.
