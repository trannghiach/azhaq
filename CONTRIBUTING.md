# Contributing

## Commit messages

Commits follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/):

```
type(scope): what changed, in 72 characters or fewer

Why, and what it did before. Wrap at 100 characters.
```

- **type**: `feat`, `fix`, `perf`, `refactor`, `docs`, `test`, `bench`, `ci`, `build`, `chore` or `revert`.
- **scope** (optional): the command (`fuzz`, `roles`, `mcp`) or the package (`portscan`, `webextract`). Omit it when a change spans the tool.
- **subject**: lower case, no period, says what the tool now does.
- **body**: for anything that is not obvious from the subject: the behaviour before, the reason, the evidence. The CHANGELOG line is written separately, under `## Unreleased`.
- A breaking change to output or flags gets `!` after the type or scope and a `BREAKING CHANGE:` paragraph.

Examples:

```
fix(fuzz): hold host headers to the scope

-H 'Host: secret.lab' with -deny secret.lab sent both requests. Every
command that sends headers now refuses a host outside the scope before
anything goes out.
```

```
perf(ports): identify open ports while the scan goes on
docs(output): split the command fields into one page per command
ci: run commitlint on every push
```

The check runs twice: as a `commit-msg` hook, and on CI for every pushed commit. Enable the hook once per clone:

```
git config core.hooksPath .githooks
```

It needs commitlint, installed once: `npm i -g @commitlint/cli@19.8.1`. Merge, `fixup!` and `squash!` commits are not checked.

## Code

- `gofmt`, `go vet ./...` and `go test -race ./...` pass on CI for every push.
- Nothing outside `internal/egress` builds an `http.Client`, a `net.Dialer`, a `dns.Client` or a Chrome allocator, or calls `net.Dial`, `http.Get` and the like: ask egress for the client, so scope, budget, pace, proxy, kill file and ledger apply. The `lint` job and `go test ./internal/egress` check it; [Architecture: Egress](docs/ARCHITECTURE.md#egress) says how to add one.
- A fix comes with a test that fails before it.
- Comments are short and say why, not what. An exported name's comment starts with the name.
- Flags and output fields are documented in `docs/`; tests in `cmd/azhaq` check the docs against the flags.

## Docs

Every command has a page, `docs/commands/NAME.md`. The table of its flags sits between `<!-- flags:begin NAME -->` and `<!-- flags:end -->` and is made from the binary, so it is never edited by hand. After a flag is added, changed or removed, rewrite the tables and commit them:

```
go generate ./docs      # or: go run ./cmd/azhaq docs -flags-into docs/commands
azhaq docs -flags NAME  # prints one table, to look at it
```

A test in `cmd/azhaq` fails when a table differs from what the binary makes, when a command has no page, and when a link in the docs leads to a heading that is not there.
