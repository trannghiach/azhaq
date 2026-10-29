# U3a: roles from proxy history, and the write that cannot be read back (proposed text)

Proposed text, by document. Nothing here is applied.

## README.md

In the paragraph on `azhaq roles`, after the command with `-role`:

> No headers to copy and no crawl: give each account's browsing as it was saved, one file per account.
>
>     azhaq roles -har alice=alice.har -har bob=bob.har
>     azhaq roles -burp alice=alice.xml -burp bob=bob.xml -replay-writes put,patch
>
> A HAR (browser devtools, Caido, Burp's HAR export) or a Burp "Save items" XML file. Every GET the account sent is a page it reached; its session is the Authorization and Cookie header of its latest request to the app; an anonymous role is added (`-no-anon` to leave it out). The origins most of an account's requests go to are the target; analytics and CDN calls in the file are left out and named in a note (`-allow HOST` keeps one). Without `--` run options nothing is crawled; with them the crawl's pages are added to the history's.

## docs/OUTPUT.md

Under "Writes (`-replay-writes`)", a new row in the verdict table:

| `writes another role's object: accepted; the change cannot be read back to confirm` | default | another role's write on the owner's object was answered 2xx (the text says which, `accepted (204)`), and no GET of the owner's object shows the field it sets (VAmPI's `PUT /users/v1/{username}/password`: `/users/v1/alice` has no password), or no GET of the object can be read at all. Neither proved nor disproved: check by hand. Never reported as "changed nothing". |

And in the paragraph on proof: "A write is proved in the field it sets: `{"quantity":2}` is not seen in an object that held a ProductId of 2. Two writes of the owner's on one object are each judged against the object as the last write left it. A write that sets what the object holds already says so (`already held what the write sets: no change could show`) instead of `unchanged`. When the history did not read the owner's object, the write's own URL and then its parents (down to two segments, never a `/v1` collection) are read as the owner. A short 2xx answer that says no (`Only Admins may delete users!`, `forbidden`, `access denied`) is a refusal, like a 401."

New section "History":

- `-har NAME=FILE`, `-burp NAME=FILE` (repeatable; the same NAME adds files): the requests account NAME sent. `NAME` is a `-role` of that name or a new role.
- Session: a role with no `-role` headers (and no `-role-cmd` or `-role-login`) takes the Authorization and the Cookie header of its most recent request to the target (by time when the file has one, else file order; from the origin most of its requests go to first). `Bearer null` and `Bearer undefined` are no session. A role whose history carries none is anonymous.
- Target origins: for each account, the origin most of its requests go to and any other with a quarter of them; `-allow HOST` adds a host (also read from the run options). Requests to other origins are neither sent nor read from; a note names them with their counts.
- Pages: each GET on the target a name does not say changes something (no logout, scripts, files) is asked once, as the account, and its answer is the account's own, as if its run had found it. `/rest/basket/6` and `/rest/basket/7` in two histories are the route `/rest/basket/{id}`; two words that differ in one place and one an answer held as an identifier (`/books/v1/a`, `/books/v1/b`) are `/books/v1/{book_title}`. Replay, identity, controls, evidence and `roles show` work as after a crawl.
- Without `--` run options: no crawl, and the target is the history's origins. With them, the crawl's pages are added.
- `-no-anon`: no anonymous role. `-rate N`: requests a second for the history reads and the replay (the run's `-rate` when there is a run).
- The history reads count against `-replay-max`.
- Writes: `-replay-writes` sends the history's writes of the methods named, to the target's origins only, never a logout; DELETE only when named.

## docs/RECIPES.md

> **From what you browsed.** Sign in to the app as each account in a browser (or through Burp or Caido), do what the account does, save the history of each (HAR, or Burp "Save items") and run `azhaq roles -har alice=alice.har -har bob=bob.har`. Add `-replay-writes put,patch` to replay the writes each account sent with the other accounts' sessions (they change data on the app: use accounts of your own).

## docs/CONCEPTS.md

Verdict list: add `writes another role's object: accepted; the change cannot be read back to confirm` after `writes another role's object`.

## Code note for the integrator

`verdictWriteUnread` is not in `verdictOrder` (TestDocsListTheCodesValues needs every key listed in OUTPUT.md); it sorts with rank 0, with the anyone-reads-secrets rows. When OUTPUT.md lists it, register it in `roles_writes.go`' init: `verdictOrder[verdictWriteUnread] = 0`. `azhaq report` (`classOf`) and `hunt` do not know the verdict yet; they ignore it.

## CHANGELOG.md

- `roles -har NAME=FILE` and the new `-burp NAME=FILE` take an account's browsing history as the whole input: its GETs are the pages it reached, its latest Authorization and Cookie headers its session, the origins most of its requests go to the target, an anonymous role is added (`-no-anon`), and no crawl runs without `--` run options.
- A cross-role write accepted with 2xx whose change no GET of the owner's object can show (VAmPI's password change) is listed as `writes another role's object: accepted; the change cannot be read back to confirm`, no longer hidden as "changed nothing".
- A write is proved in the field it sets, and against the object as the last write left it; a short 2xx answer saying "Only Admins…" is a refusal.
