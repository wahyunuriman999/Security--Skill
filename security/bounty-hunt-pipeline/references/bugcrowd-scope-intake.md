# Bugcrowd Scope Intake

Applies when the engagement lives on Bugcrowd rather than HackerOne (no public
GraphQL scope query).

## The engagement page IS the scope document

`https://bugcrowd.com/engagements/<slug>` is server-rendered and public: extract
it with the plain page extractor (no auth, no browser). It carries the full target
table, a reward chart *per target*, per-target exclusions, the access notes, the
program rules, and the program-wide out-of-scope vulnerability list.

**Pitfall — the target table sits in the truncated middle.** A populated
engagement page runs well past the inline extraction budget, so the result comes
back as head+tail and the TARGETS block — the only part you actually need — is in
the omitted middle. Read the saved cache file the footer points at, with offsets,
before concluding a target is absent. `grep -n 'Targets\|In scope\|Exclusions'`
on that file gives the section boundaries immediately.

## Build the target list mechanically

Do not transcribe hosts and addresses by hand — pull them out of the saved markdown:

```bash
f=<cached-engagement-md>
grep -oE '0x[0-9a-fA-F]{40}' "$f" | sort -u                          # contract assets
grep -oE 'github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+' "$f" | sort -u # source repos
grep -oE 'https?://[a-zA-Z0-9.-]+' "$f" | sort -u                   # hosts
```

The github/host hits are noisy (they include unrelated links such as app-store
pages and Bugcrowd's own domains); the contract-address list is clean and is
usually the fastest read on which chains and primitives are in scope.

## Per-target shape to record in the ledger

Each target block gives: display name, in-scope flag, **its own P1–P4 chart**, its
own exclusions, and a Name/Location table holding the canonical asset string
(the address, repo URL, or `host` + `https://host/` pair that the submission must
name).

**The reward scale differs per target, so rank by target P1, not by P1 in the
generic sense.** A flagship contract can carry a P1 worth orders of magnitude
more than a mobile app or SDK target whose P1 is a rounding error on the same
program. Read the charts before choosing where to spend the session.

## The blanket subdomain rule — obey it literally

The scope section closes with a statement that testing is authorized only on the
targets listed and that any domain/property not listed, **explicitly including
unlisted subdomains**, is out of scope.

Therefore hosts you discover from an in-scope service's own metadata are NOT new
scope. An OIDC discovery document, a `.mcp.json`, a JS bundle, or an error page
that names an authorization server, an API host, or an internal hostname has
taught you about the architecture — nothing more. Record such hosts in the
ledger as "exists, not listed, do not test" and keep testing only the hosts that
appear in the target tables. A finding on an unlisted host is unrewardable by
construction, and probing it is the kind of unauthorized action that ends a
program relationship.

## Access notes gate authenticated hunting

Read the access section before planning any authenticated test. Self-provisioning
is typical, but it is usually tied to a program-issued alias domain
(`@bugcrowdninja.com`). If authenticated surface testing is the plan, confirm an
account on that alias actually exists before designing the hunt around it —
otherwise the working surfaces are the unauthenticated ones (public API, on-chain
contracts, published source).

## Copy the program-wide out-of-scope list into the ledger verbatim

Every program repeats a generic exclusion list, and each entry is a pre-answered
rejection you must not spend a session rediscovering: denial of service, version
or banner disclosure, descriptive errors and stack traces, rate limiting on
non-authentication endpoints, previously-known vulnerable libraries without a
working PoC, client-side JS manipulation without a remote path, gas
optimizations in contracts, and issues the vendor already knows about.

Two more that appear on Bugcrowd and are easy to miss:

- **Access-chart/modifier wording on contracts**: many contract targets state the
  asset covers only vulnerabilities *purely executed on chain* against the listed
  address, and exclude anything requiring user interaction or an
  attacker-controlled website. A wallet-popup or signing-flow attack is out even
  when the on-chain code is the thing being abused.
- **"Findings without demonstrable security impact", "SDK misuse or unsupported
  usage", and "issues requiring control of the client environment"** are standard
  on SDK/library assets. They kill anything that only manifests under a
  developer's misconfiguration or in a already-compromised integration; the claim
  has to survive the library being used *correctly*.

## Same-issue-once rule

Programs commonly pay one bounty per underlying issue even when it reproduces on
several in-scope assets or on the same contract deployed across multiple chains,
and one report per vulnerability. This kills the "report the same root cause
against every address" strategy — pick the highest-paying affected asset and write
one report.
