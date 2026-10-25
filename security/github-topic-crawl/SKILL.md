---
name: github-topic-crawl
description: "Use when crawling a GitHub topic past the 1,000-result cap."
version: 1.0.0
author: serigalamalem + user
license: MIT
sources: operator_experience
metadata:
  hermes:
    tags: [github, search-api, crawling, pagination, rate-limit, data-collection]
    related_skills: [pentest-ref-corpus, osint-methodology, offensive-osint]
---

# GitHub Topic / Search Crawl Beyond the 1,000 Cap

GitHub's Search API returns **at most 1,000 results per query**. Requesting
`page=11` fails with `HTTP 422 Unprocessable Entity`. Any crawl that just
increments `page` dies at 1,000 and silently loses the rest.

The fix is query partitioning: split the search space so each partition stays
under 1,000, then union and dedupe.

> Verified 25 Okt 2026: `topic:pentesting` reports `total_count=8700` but caps at
> 1,000. Partitioned by star-range + language + created-year, 7,384 unique repos
> were recovered across 136 queries.

---

## When to Use

- Enumerating a GitHub topic, or any search expected to exceed 1,000 hits
- Building a corpus of repos/tools for a domain
- Any `page` loop that must survive past page 10

Do **not** use it for a search already under 1,000 results — a plain page loop is
simpler and cheaper.

---

## Rate Limits (unauthenticated)

| Endpoint | Limit |
| --- | --- |
| `search/repositories` | **10 requests / minute** |
| `rate_limit`, `repos/*` | 60 requests / hour |

Search and core share nothing — they are separate buckets. Budget the crawl as
`ceil(total/100)` requests minimum, so 8,700 repos = 87 requests = ~9 minutes.

Check before starting:

```bash
curl -s https://api.github.com/rate_limit | python -c "import sys,json;d=json.load(sys.stdin);print(d['resources']['search'])"
```

---

## Partition Strategy

Split in this order, re-splitting any partition that still reports
`total_count > 1000`:

1. **Star range** — `stars:>=250`, `stars:150..249`, `stars:100..149`, … down to
   `stars:0`. Cheapest split, and it naturally puts the valuable repos first.
2. **Language** — `language:python`, `language:go`, … (~35 common values).
3. **Created year** — `created:2016-01-01..2016-12-31`.
4. **Pushed year** — last resort, weakest signal.

Stop splitting at depth 3. A partition still >1,000 at depth 3 is low-signal by
definition — accept the cap and move on.

GitHub search qualifier syntax that works:

```
topic:pentesting stars:150..249 language:python created:2024-01-01..2024-12-31
```

---

## Working Crawler

Reference implementation:
`C:\Users\ROG G532 LV\Downloads\bountyforge-hunt\references\github-pentesting-topic\crawl2.py`

Structure:

```python
queue = deque([(query, depth)])   # BFS over partitions
while queue:
    q, depth = queue.popleft()
    total = harvest(q)            # paginate up to 10 pages, dedupe on write
    if total > 1000 and depth < 3:
        queue.extend((sub, depth+1) for sub in split(q, depth))
```

Key details that make it survive:

- **Dedupe on `full_name` at write time**, not after. Overlapping partitions
  (e.g. `stars:>=250` and `stars:150..249`) re-emit repos.
- **Resume from disk.** Load the existing output file's keys into `SEEN` before
  starting, so a restart does not re-fetch.
- **Sleep ~6.2 s between requests** — just under the 6 s the 10/min limit needs.
- **Read `X-RateLimit-Remaining`.** When it hits 0, sleep until
  `X-RateLimit-Reset` rather than guessing.
- **Treat `422` as a signal, not an error** — it means the partition is
  unsplittable at this depth. Log and skip.
- **Backoff on 403/429** using the `X-RateLimit-Reset` header, not a fixed delay.

---

## Output Schema

One JSON object per line, appended as the crawl runs so a crash loses nothing:

```json
{"full_name":"...","url":"...","desc":"...","stars":0,"forks":0,
 "lang":"...","topics":["..."],"pushed_at":"...","created_at":"...",
 "archived":false,"license":"MIT","open_issues":0,"size_kb":0,"homepage":"..."}
```

Truncate `desc` to ~400 chars — full descriptions bloat the file without adding
signal.

---

## Quality Gate (applied after the crawl)

Raw counts are misleading. On `topic:pentesting`, 7,384 raw repos reduced to
2,115 useful ones:

| Rule | Effect |
| --- | --- |
| Drop `archived` | removes dead projects |
| Drop `pushed_at` older than 2 years | removes abandoned tools |
| Drop empty `desc` | removes placeholder repos |
| Require stars by recency | `>=50` any age; `>=20` within 2y; `>=10` within 2y; `>=5` within 1y; `>=2` within 6mo |

The star floor is the highest-leverage filter: 4,950 of 7,384 repos had fewer
than 10 stars and were almost all noise.

---

## Pitfalls

- **`page=11` is not a bug in your loop.** It is the API cap. Partition instead.
- **A `git restore --source=HEAD :/` message is not a clone failure.** On
  Windows, shallow clones of repos with odd file permissions emit this warning
  after a successful checkout. Confirm with `git -C <dest> rev-parse HEAD`
  before declaring a clone failed or retrying it — retrying wastes the
  bandwidth and can mask a genuinely good clone.
- **`du -sh` is unusable on a directory holding 100+ repos.** It walks every
  file and can hang for minutes. Compute size in Python with `os. walk` and
  `os. path. getsize`, skipping `.git`.
- **A background job whose last command is slow reports `running` after the
  work is done.** A trailing `du -sh` or a final summary step keeps the process
  alive long past the useful output. Poll the artifact on disk (line count,
  directory listing) rather than waiting on the process to exit.
- **Forks are included by default.** `fork:true` means *only* forks; omitting it
  includes both. Dedupe handles the overlap, but expect inflated `total_count`.
- **`total_count` is approximate** for large result sets. Do not use it to decide
  when to stop — stop when a page returns fewer than `per_page` items.
- **Unauthenticated crawling is slow by design.** If a topic needs >500 requests,
  get a token rather than extending the runtime.
- **Do not parallelize requests** against the search bucket — it converts a
  9-minute crawl into a 403 loop.

---

## Cloning the Results

A crawl only collects metadata. To actually hold the repos:

```bash
git clone --depth 1 --single-branch --quiet https://github.com/<owner>/<repo>.git <dest>
```

- Set `GIT_LFS_SKIP_SMUDGE=1` in the env — LFS blobs are large and rarely
  needed for reading source.
- Set `GIT_TERMINAL_PROMPT=0` so a private or renamed repo fails fast instead
  of hanging on a credential prompt.
- Flatten `owner/repo` to `owner__repo` for the destination directory name;
  nested paths break tooling that iterates the folder.
- Budget roughly 30–60 MB per repo for shallow clones; wordlist and template
  repos run far larger (`OneListForAll` alone is >1 GB).

Verify a batch with `scripts/verify_clones.py` rather than eyeballing exit
codes — see the pitfall below about false failures.

---

## Stopping and Resuming

A multi-topic crawl can run for hours. When it is stopped partway — by the
user, by a timeout, or because the value of the remaining topics is unclear —
make the restart cheap instead of starting over.

**Persist the completed-query set to disk.** An in-memory `done` set means a
restart re-fetches every partition, burning the whole rate-limit budget again
for data already on disk:

```python
DONE_FILE = os.path.join(OUTDIR, "topics_done.txt")
done = set(l.strip() for l in open(DONE_FILE)) if os.path.exists(DONE_FILE) else set()
# ... after processing a query:
with open(DONE_FILE, "a", encoding="utf-8") as f: f.write(q + "\n")
```

**Write a `RESUME.md` next to the output** recording: which topics are done,
which remain, the resume command, and the patch needed to make the resume
cheap. Without it the next session cannot tell a deliberate stop from a crash.

**When the user redirects to what already exists** ("focus on what's done",
"stop the crawl"), stop the job, record the resume state, and process the data
already collected. Do not keep the crawl running in the background while
answering — the partial corpus is usually enough to be useful, and the
remaining topics are cheap to finish later.

---

## Reusing for Another Topic

Change one line:

```python
BASE = "topic:pentesting"   # -> "topic:bugbounty", "topic:osint", …
```

For non-topic searches, replace `BASE` with any qualifier string, e.g.
`"org:projectdiscovery"` or `"filename:.env"`.

---

## Out of Scope

- Does not authenticate. For private repos or heavy crawling, supply a token via
  the `Authorization` header and re-check the limits.
- Does not decide which repos are worth cloning — apply a quality gate first
  (see the Quality Gate section), then clone only what survives.

## Support Files

- `scripts/verify_clones.py` — verify every clone in a directory resolves a git
  HEAD and report the working-tree size. Run it after any batch clone instead of
  trusting exit codes.
