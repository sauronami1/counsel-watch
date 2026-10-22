#!/usr/bin/env python3
"""Turn an ArtifactData dump of the "jobs" collection into the plain file that cw_crypto.py seals.

  python3 tools/build_plain.py <dump_dir>/jobs <meta.json or -> <out_plain.json>

<dump_dir>/jobs holds one JSON file per job as written by ArtifactData (out_dir), each either
the job object itself or {"id":..., "data": {...job...}}. meta.json is the meta/status document
(either shape too); pass - to skip it. Keep every file here OUTSIDE the repo folder.
"""
import glob, json, os, sys

def body(d):
    return d["data"] if isinstance(d, dict) and isinstance(d.get("data"), dict) else d

if len(sys.argv) != 4:
    sys.exit(__doc__)
jobs = []
for f in sorted(glob.glob(os.path.join(sys.argv[1], "*.json"))):
    j = body(json.load(open(f)))
    if j.get("id") and j.get("title") and j.get("url"):
        jobs.append(j)
meta = body(json.load(open(sys.argv[2]))) if sys.argv[2] != "-" else {}
meta["open_count"] = sum(j.get("status", "open") == "open" for j in jobs)
assert jobs, "no jobs found in dump"
json.dump({"meta": meta, "jobs": jobs}, open(sys.argv[3], "w"), ensure_ascii=False)
print(f"{len(jobs)} jobs ({meta['open_count']} open) -> {sys.argv[3]}")
