## Your area: web (folder AREA = web)

Commands: `crawl` (vs katana), `shots` and `gallery` (vs gowitness), `probe` (vs httpx). CHANGELOG sections: `crawl`, Screenshots and `gallery`, `probe`; MIGRATING: katana, gowitness, httpx.

- crawl: Juice Shop, DVNA, ginandjuice.shop (low rate). Compare URL sets with katana at default and `-rate 5` / katana `-rl 5`, including JS routes (`-jc`) and headless if you can. Every azhaq URL must be real (curl it); every katana URL azhaq lacks must be explained (junk string vs real page). Check `-jsonl`, `-f`, `-fs`, `-kf`, `-submit-forms` (writes only with it).
- shots: the five lab apps and the reachable test sites, default and `-rate 2`; vs gowitness. Pictures blank or partial? `partial` honest? Summary requests = ledger = proxy log. Then `gallery -db` on the result: every endpoint works, the Host guard holds (`curl -H 'Host: evil.example'`), and it sends nothing.
- probe: the lab apps, the services lab ports, the reachable test sites, plus a list mixing dead names, closed ports, redirects, `host:port` and full URLs with a scheme and port; vs httpx with the same flags (`-sc -title -td -fr -json`, matchers and filters, `-p`, `-path`, `-rl`). Every input must end as exactly one row or a counted failure, and a full URL must be asked exactly as given (count at countproxy).
