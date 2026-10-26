# Writes juice-shop-v20.3.0-routes.txt: python3 juice_routes.py server.js main.js
# (docker cp azq-juice:/juice-shop/build/server.js .; curl -o main.js http://127.0.0.1:3001/main.js)
import re, sys
srv = open(sys.argv[1]).read()
main = open(sys.argv[2]).read()
routes = set(m.group(2) for m in re.finditer(r"app\.(get|post|put|patch|delete|use|all)\(['\"`](/[^'\"`]+)['\"`]", srv))

def written(static):
    # The text is in the bundle as it is, or as a prefix constant plus a
    # suffix ("/rest/admin" + "/application-configuration").
    if static in main:
        return True
    segs = static.strip("/").split("/")
    for k in range(1, len(segs)):
        if "/" + "/".join(segs[:k]) in main and "/" + "/".join(segs[k:]) in main:
            return True
    return False

keep = []
for r in sorted(routes):
    if r.startswith(("/assets", "/vendor", "/.well-known")) or "(?" in r:
        continue
    statics = [s for s in re.split(r"/:[A-Za-z_]+", r) if s]
    if all(written(s) for s in statics):
        keep.append(re.sub(r":([A-Za-z_]+)", r"{\1}", r))
print("\n".join(keep))
