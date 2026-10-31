# azhaq gallery

Browse a workspace's screenshots in a browser: a grid with filters, search, look-alike groups and a page per shot.

## Synopsis

```
azhaq gallery [-db FILE ...] [-workspace DIR] [-listen 127.0.0.1:7180]
```

## Examples

```
# Open one workspace, then browse to http://127.0.0.1:7180/
azhaq gallery -db app.db

# Merge every workspace of a directory, on another port
azhaq gallery -workspace ./recon -listen 127.0.0.1:8000

# Ask the JSON API from a script: 200s running nginx, one per look-alike group
curl -s 'http://127.0.0.1:7180/api/shots?status=200&tech=nginx&collapse=1&limit=20'
```

## What it does

1. Reads the screenshots of a workspace (from `shots` or `run -screenshots`).
2. Serves them to a browser on this machine at `http://127.0.0.1:7180/`. The address is printed on stderr.
3. Serves the same data as a JSON API under `/api/`.

It is made to go through thousands of pictures. The gallery reads the workspace and the picture files. It sends nothing to any target.

- The page is embedded in the binary and works offline: no CDN, no external font, and no request to anything but the gallery's own address.
- The page's `Content-Security-Policy` lets the browser load only its own script and style.
- Pictures, headers, TLS, console and network log all come from the workspace and the picture files.

## Output

The gallery prints the address of its local web page on stderr. Stop it with Ctrl-C.

The page has six views:

| View | What it shows |
| --- | --- |
| Pages | A grid or a table of thumbnails. See [Pages](#pages). |
| Search | The box at the top. See [Search](#search). |
| A page | One shot with everything known of it. See [A page](#a-page). |
| Look-alikes | Groups of 2 or more pages whose perceptual hashes are at most 10 bits apart (as in `export -format html`), largest first. |
| Not taken | Pages that gave no picture, with the run's reason: errors, and notes for pages left out on purpose (`-shot-codes`, the budget). |
| Statistics | Pages, status codes, technologies, groups, headers, requests and console lines, and what could not be shown. |

What the gallery cannot show, it says. A banner and `/api/stats` count the pages that fall into three groups:

- the picture file is gone from disk (partial: exit 3)
- the workspace holds no perceptual hash or status (taken by an older azhaq)
- the text was not kept

## Summary and exit codes

| Exit | When |
| --- | --- |
| 0 | Stopped with Ctrl-C, and everything could be read. The gallery is a server: a signal is its normal end, not a stop by a limit (exit 4). |
| 1 | No workspace could be read, or it holds no screenshot. |
| 3 | A workspace was skipped, or picture files are missing. Said on stderr and on the page. |

The summary and the other exit codes are the shared ones: see [the summary](../OUTPUT.md#the-summary) and [exit codes](../OUTPUT.md#exit-codes).

## Details

### Choosing what to show

- `-db` may be given more than once.
- `-workspace DIR` takes every `*.db` file of a directory and of the directories directly in it.
- The pages are merged in one view, each labelled with its workspace.
- A page shot in more than one run is listed once, with its newest picture.
- The workspace is opened read-only and read once at start. Start the gallery again to see pages taken since.
- A database that is not a workspace is skipped with a note. One that cannot be read is skipped and the exit code is 3.

### Pages

- Each thumbnail shows its URL, title, status and technologies.
- The grid is paged (48, 96 or 200 at a time). Sort it by URL, host, title, status, look-alike group or newest.
- The side panel filters by status, technology, host, title text, partial or complete, and workspace. Each value shows its count under the other filters.
- *One per look-alike group* shows one page for each group, with how many pages of it match.

### Search

- Words and `"phrases"` match the URL, the title and the page text.
- `url:`, `title:`, `host:`, `body:`, `header:`, `tech:`, `status:` and `p:` match one field.
  - `status:` takes `200`, `4xx` or `none`.
  - `p:` takes the start of a perceptual hash.
- A term with a `-` before it leaves out the pages that match.
- `body:` and free words read the text of the pages whose HTML was kept (`shots -shot-html`). The page says for how many that is.
- An example: `title:login tech:nginx body:"sign in"`.

### A page

A page shows:

- the full picture
- response headers and cookies (from `Set-Cookie`)
- TLS, the network log and console messages
- the page text and its HTML source, when kept
- the pages that look like it
- what the workspace holds of its URL (entity, links, observations), with the `azhaq show -db … URL` command that prints it all

### Binding to an address

- `-listen ADDR` changes the address. `127.0.0.1:0` takes any free port.
- A gallery bound to a loopback address answers only requests that name a loopback host.
- Bound elsewhere (`-listen 0.0.0.0:7180`), it shows every page in the workspace to anyone who can reach it. It says so on stderr.

### The JSON API

The page uses this API, which is open to scripts on the same address. Every response is JSON except the pictures. Errors are `{"error": "…"}` with status 400 (a bad parameter) or 404.

| Path | Answers |
| --- | --- |
| `GET /api/` | The list of these endpoints. |
| `GET /api/shots` | A page of shots: `{total, offset, limit, shots, took_ms}`. See [Shots](#shots). |
| `GET /api/shots/{id}` | One shot, with more fields. See [One shot](#one-shot). |
| `GET /api/shots/{id}/show` | `command`, `entity` (type, key, first and last seen), `links` and `observations` of the page's URL. |
| `GET /api/facets` | Counts for `status`, `technologies`, `hosts`, `partial` (and `workspaces`) under the same query parameters. Each facet is counted under the filters other than its own. |
| `GET /api/groups` | `{total, groups}`, each `{group, size, sample, title, hosts}`, largest first. Takes `min` (default 2) and `limit`. |
| `GET /api/failed` | `{total, offset, limit, failed}`, each `{url, kind, reason, at}`. Takes `q`, `kind` (`error` or `note`), `offset` and `limit`. |
| `GET /api/stats` | See [Statistics](#statistics-endpoint). |
| `GET /img/{id}/thumb` | The picture as a 360 pixel wide JPEG. |
| `GET /img/{id}/full` | The picture file as taken. Only a PNG or JPEG is ever served. |

A page's `id` is stable for a workspace file and URL. The first page of 2,000 pictures answers in about a millisecond, and a filter in a few. Thumbnails are made when first asked and kept in memory.

#### Shots

Each shot has:

| Field | Meaning |
| --- | --- |
| `id`, `url`, `final_url`, `host`, `title`, `technologies` | The page and what was read from it. |
| `workspace` | Present when several workspaces are shown. |
| `status` | The status. 0 means none recorded. |
| `partial` | With `partial_why`: `3 off-scope assets blocked: cdn.jsdelivr.net`, or how many images and styles did not load. |
| `hash`, `group`, `group_size` | The perceptual hash, the look-alike group and its size. |
| `taken_at`, `has_file`, `body_kept` | When it was taken, whether the picture file is there, and whether the page text was kept. |
| `group_matches` | With `collapse=1` only. |

The query parameters:

| Parameter | Meaning |
| --- | --- |
| `q` | The search above. |
| `status` | Repeatable or comma-separated: `200`, `4xx`, `none`. |
| `tech` | Repeatable, and all must hold. A name such as `nginx` matches `Nginx:1.25.3`. |
| `title`, `host` | Text the title or host contains. |
| `workspace` | A workspace. |
| `partial` | `yes` or `no`. |
| `group` | A group number. |
| `sort` | `url`, `host`, `title`, `status`, `group` or `time`. |
| `order=desc` | Reverse the order. |
| `collapse=1` | One shot for each look-alike group. |
| `offset`, `limit` | `limit` is 1 to 500, default 48. |

#### One shot

`GET /api/shots/{id}` returns the shot above, plus:

- `group_members`: up to 24 other pages of its group
- `show_command`: the `azhaq show` command for its URL
- `record`: the stored row (`headers`, `tls`, `network`, `console`, `response_code`, … as in the `shots` row)
- `body_text` and `body_html`, when kept. They are cut at 20 KB and 64 KB, and `body_cut` says so.

#### Statistics endpoint

`GET /api/stats` returns:

- `pages`, `pages_in_groups` and `workspaces` with their sizes
- `statuses`, `technologies`, `groups` and `largest_groups`
- `partial`, `headers`, `network_requests` and `console_lines`
- `not_taken` and `files_missing`
- `body_text`, with `kept`, `indexed` and `ready`
- `warnings`, each with `message` and `partial`
- `loaded_at`, when the gallery read the workspaces

## Flags

<!-- flags:begin gallery -->
| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-db` | string, repeatable |  | a workspace to show (repeatable; default: the last run's) |
| `-workspace` | string |  | show every workspace (*.db) of this directory and of the directories directly in it, merged in one view |
| `-listen` | string | `127.0.0.1:7180` | address to serve on; a loopback address answers only this machine (127.0.0.1:0 takes any free port) |
<!-- flags:end -->
