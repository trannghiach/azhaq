# W5b: fewer requests for the same map, and screenshots that say what they need (proposed text)

## README / how a run spends requests

**Path checks stop at their answer.** The built-in path checks guess where an
API description sits (`openapi.json`, `swagger.json`, `api-docs`, `v3/api-docs`,
`v2/api-docs`, `swagger/v1/swagger.json`, the YAML names, `swagger`) and, under
each API base the run found (`/rest/`, `/v3/`), the same names again. They ask
these one at a time, likeliest first, and stop at the first that is an OpenAPI
or Swagger document with paths, or the Swagger UI or ReDoc page that loads one.
Once an origin has served a description (here or through `azhaq-openapi`), the
other locations on that origin are not asked, and the summary says so:

    note: path checks: 28 skipped (an API description was already found)

Every other check (`robots.txt`, `login`, `admin`, `graphql`, `.git/HEAD`, …)
is still asked: only a check whose answer is already known is skipped. A
Swagger UI whose script carries the document (Juice Shop's `/api-docs/`) is
read from that script; the names next to it are not guessed.

**One baseline for a shell.** A page that is byte for byte what the site root
answers for a made-up path (a single-page app's shell) is the catch-all answer
in a directory whose own baseline has not been asked, so that baseline is not
requested. A directory with answers of its own is still asked.

On Juice Shop a default `azhaq run` sends 148 requests where it sent 190, with
the same 70 of 77 known routes.

## README / screenshots

**Budget.** The page's images, scripts and styles each count against
`-max-requests`. When too few are left, Chrome is refused them and no image is
saved; `shots` and `run -screenshots` say it instead of going quiet:

    note: screenshot of http://127.0.0.1:3001/ not taken: the page needs about 26 requests and 8 were left (raise -max-requests)

The figure is how many requests the page made when it was cut short.

**One Chrome.** A run starts one Chrome and opens up to 4 tabs in it at once
(`-tabs N` changes it); each page is a tab, not a browser.
