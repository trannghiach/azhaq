## Your area: fuzz (folder AREA = fuzz)

Commands: `dirs` and `fuzz` (vs ffuf), `params` (vs arjun), `urls` (vs gau). CHANGELOG sections: `dirs`, `fuzz`, `params`, `urls`; MIGRATING: ffuf, arjun, gau.

- dirs/fuzz: Juice Shop, DVWA, VAmPI, DVNA with the same wordlist as ffuf (the built-in common.txt is SecLists' common.txt; write your own too). Compare hits, counts (`-fs -fw -fl` must match ffuf's numbers on the same answer), and time at default and `-rate 5` vs ffuf `-rate 5`. Take real ffuf command lines from MIGRATING and run them through `azhaq fuzz`; `-o -of all`, `-request`, `-x` through countproxy, `-mode clusterbomb`, recursion, `-ac`.
- params: VAmPI, DVWA (signed in), DVNA, Juice Shop API routes, a reachable test site (low rate); vs arjun with the same list. Verify each found name by curl (does the answer actually change?). GET and `-X POST|JSON`, and `-proxy` through countproxy.
- urls: hackerone.com and vulnweb.com, at most two runs each per tool; vs gau with the same providers and filters (`-mc`, `-ft`, `-blacklist`, `-subs`). Same URL set? Duplicates? Time? Are dropped junk URLs counted?
