# Known access-control flaws per lab, for `azhaq roles`

Each file lists flaws that the app's own source says exist (positives) and protected routes that must not be reported (negative controls), with the source that says so.

Before measuring azhaq, reproduce every line with curl, using two accounts you register yourself. A positive that does not reproduce on this instance is reported as such and leaves the bar. A negative that turns out readable is reported too.

The bar for `azhaq roles`:
- every reproduced positive is listed with the verdict class given;
- no negative is listed as a cross-role read or write.

Do not edit these files to make the bar pass.
