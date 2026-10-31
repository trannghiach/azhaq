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

`azhaq gallery -db FILE` serves the screenshots of a workspace (`shots`, `run -screenshots`) to a browser on this machine, at `http://127.0.0.1:7180/` (`-listen ADDR` changes it; `127.0.0.1:0` takes any free port). `-db` may be given more than once, and `-workspace DIR` takes every `*.db` file of a directory and of the directories directly in it; the pages are merged in one view, each labelled with its workspace. A database that is not a workspace is skipped with a note; one that cannot be read is skipped and the exit code is 3. The workspace is opened read-only and read once at start (start it again to see pages taken since). A page shot in more than one run is listed once, with its newest picture.

The page is embedded in the binary: no CDN, no external font, no request to anything but the gallery's own address. The server sends nothing to any target: pictures, headers, TLS, console and network log are read from the workspace and the picture files, and the page's policy (`Content-Security-Policy`) lets the browser load only its own script and style. A gallery bound to a loopback address answers only requests that name a loopback host; bound elsewhere (`-listen 0.0.0.0:7180`) it shows every page in the workspace to anyone who can reach it, and says so on stderr.

The views:

- **Pages**: a grid (or a table) of thumbnails, each with its URL, title, status and technologies, paged (48, 96 or 200 at a time) and sortable by URL, host, title, status, look-alike group or newest. The side panel filters by status, technology, host, title text, partial or complete, and workspace, with the count of each value under the other filters. *One per look-alike group* shows one page for each group, with how many pages of it match.
- **Search** (the box at the top): words and `"phrases"` match the URL, the title and the page text; `url:`, `title:`, `host:`, `body:`, `header:`, `tech:`, `status:` (`200`, `4xx`, `none`) and `p:` (the start of a perceptual hash) match one field; a term with a `-` before it leaves out the pages that match. `body:` and free words read the text of the pages whose HTML was kept (`shots -shot-html`); the page says for how many that is.
- **A page**: the full picture, response headers, cookies (from `Set-Cookie`), TLS, the network log, console messages, the page text and its HTML source (when kept), the pages that look like it, and what the workspace holds of its URL (entity, links, observations) with the `azhaq show -db … URL` command that prints it all.
- **Look-alikes**: the groups of 2 or more pages whose perceptual hashes are at most 10 bits apart (as in `export -format html`), largest first.
- **Not taken**: the pages that gave no picture, with the run's reason: errors, and notes for pages left out on purpose (`-shot-codes`, the budget).
- **Statistics**: pages, status codes, technologies, groups, headers, requests and console lines, and what could not be shown.

What the gallery cannot show it says: a banner and `/api/stats` count the pages whose picture file is gone from disk (partial: exit 3), whose workspace holds no perceptual hash or status (taken by an older azhaq), and whose text was not kept.

## Summary and exit codes

The summary and the exit codes are the shared ones: see [OUTPUT.md](../OUTPUT.md#exit-codes).

## Details

### The JSON API

The page uses this API, which is open to scripts on the same address. Every response is JSON except the pictures; errors are `{"error": "…"}` with status 400 (a bad parameter) or 404.

| Path | Answers |
|---|---|
| `GET /api/` | the list of these endpoints |
| `GET /api/shots` | `{total, offset, limit, shots, took_ms}`. Each shot: `id`, `workspace` (when several), `url`, `final_url`, `host`, `title`, `status` (0: none recorded), `technologies`, `partial` (with `partial_why`: `3 off-scope assets blocked: cdn.jsdelivr.net`, or how many images and styles did not load), `hash`, `group`, `group_size`, `taken_at`, `has_file`, `body_kept`; with `collapse=1` also `group_matches`. Query: `q` (the search above), `status` (repeatable, comma-separated; `200`, `4xx`, `none`), `tech` (repeatable, all must hold; a name such as `nginx` matches `Nginx:1.25.3`), `title`, `host` (contains), `workspace`, `partial` (`yes`/`no`), `group` (a group number), `sort` (`url`, `host`, `title`, `status`, `group`, `time`), `order=desc`, `collapse=1`, `offset`, `limit` (1 to 500, default 48) |
| `GET /api/shots/{id}` | one shot as above, plus `group_members` (up to 24 other pages of its group), `show_command`, `record` (the stored row: `headers`, `tls`, `network`, `console`, `response_code`, … as in the `shots` row), `body_text` and `body_html` (when kept; cut at 20 and 64 KB, `body_cut`) |
| `GET /api/shots/{id}/show` | `command`, `entity` (type, key, first and last seen), `links` and `observations` of the page's URL |
| `GET /api/facets` | counts for `status`, `technologies`, `hosts`, `partial` (and `workspaces`) under the same query parameters, each facet under the filters other than its own |
| `GET /api/groups` | `{total, groups}`, each `{group, size, sample, title, hosts}`, largest first; `min` (default 2), `limit` |
| `GET /api/failed` | `{total, offset, limit, failed}`, each `{url, kind, reason, at}`; `q`, `kind` (`error` or `note`), `offset`, `limit` |
| `GET /api/stats` | pages, workspaces (with sizes), `statuses`, `technologies`, `groups`, `largest_groups`, `partial`, `headers`, `network_requests`, `console_lines`, `not_taken`, `files_missing`, `body_text` (`kept`, `indexed`, `ready`) and `warnings` (`message`, `partial`) |
| `GET /img/{id}/thumb` | the picture as a 360 pixel wide JPEG |
| `GET /img/{id}/full` | the picture file as taken (only a PNG or JPEG is ever served) |

A page's `id` is stable for a workspace file and URL. The first page of 2,000 pictures answers in about a millisecond and a filter in a few; thumbnails are made when first asked and kept in memory.

Exit codes: 0 when stopped with Ctrl-C and everything could be read; 1 when no workspace could be read or it holds no screenshot; 3 when a workspace was skipped or picture files are missing, said on stderr and on the page.

**Screenshot gallery.** `azhaq gallery -db shots.db` (or `-workspace DIR` for a directory of workspaces) serves a local page, `http://127.0.0.1:7180/`, to go through thousands of pictures: a grid with each page's URL, title, status and technologies, filters (status, technology, host, title, partial, look-alike group), one tile for each group of look-alikes, search of URL, title and kept page text (`title:login tech:nginx body:"sign in"`), and a page per shot with its picture, headers, cookies, TLS, network log, console and the `azhaq show` command. It is embedded in the binary, works offline, reads only the workspace and sends nothing to any target; the same data is a JSON API under `/api/` ([The JSON API](#the-json-api)).

## Flags

<!-- flags:begin gallery -->
| Flag | Type | Default | Meaning |
| --- | --- | --- | --- |
| `-db` | string, repeatable |  | a workspace to show (repeatable; default: the last run's) |
| `-listen` | string | `127.0.0.1:7180` | address to serve on; a loopback address answers only this machine (127.0.0.1:0 takes any free port) |
| `-workspace` | string |  | show every workspace (*.db) of this directory and of the directories directly in it, merged in one view |
<!-- flags:end -->
