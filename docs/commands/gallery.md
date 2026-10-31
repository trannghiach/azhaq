# azhaq gallery

Browse a workspace's screenshots in a browser: a grid with filters, search, look-alike groups and a page per shot.

## Synopsis

```
azhaq gallery [-db FILE ...] [-workspace DIR] [-listen 127.0.0.1:7180]
```

## Examples

```
azhaq gallery -db app.db
azhaq gallery -workspace ./recon -listen 127.0.0.1:8000
curl -s 'http://127.0.0.1:7180/api/shots?status=200&tech=nginx&collapse=1&limit=20'
```

## Output

The address of a local web page on stderr; the page and its JSON API (/api/) read the workspace and send nothing to any target; exit 3 when a workspace or picture file could not be read.

## Summary and exit codes

The summary and the exit codes are the shared ones: see [OUTPUT.md](../OUTPUT.md#exit-codes).

## Flags

<!-- flags:begin gallery -->
| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-db` | string, repeatable |  | a workspace to show (repeatable; default: the last run's) |
| `-listen` | string | `127.0.0.1:7180` | address to serve on; a loopback address answers only this machine (127.0.0.1:0 takes any free port) |
| `-workspace` | string |  | show every workspace (*.db) of this directory and of the directories directly in it, merged in one view |
<!-- flags:end -->
