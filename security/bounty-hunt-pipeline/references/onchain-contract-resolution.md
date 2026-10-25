# Resolving a deployed EVM contract (no Etherscan key)

When a program lists an on-chain address (contract asset) and you must answer
"is this a proxy, what is its implementation, is the source verified, does the
bytecode match what it claims to be" — resolve it in one call set, then decide
whether to audit at all. This is recon work that precedes a line-by-line audit
and routinely kills dead theories (a drained/multisig-guarded/standard contract)
before they cost a session.

## One-call resolution: Blockscout v2 API

`https://eth.blockscout.com/api/v2/smart-contracts/{addr}` (other chains:
`<chain>.blockscout.com/api/v2/...`). No API key. Returns everything in one JSON:

- `name` — the on-chain identity. `PayableProxy`, `GnosisSafeProxy`, `SeaDrop`,
  `TransparentUpgradeableProxy` instantly tell you what you are looking at.
- `is_verified` + `source_code` / `additional_sources` — full verified Solidity
  when true; pull `source_code` into a `.sol` and the `additional_sources` list
  into their own files (they are `{file_path, source_code}` objects).
- `proxy_type` — `eip1967` / `master_copy` (Gnosis Safe) / `None`. Coupled with
  `implementations: [ {address, name} ]` this resolves "what contract do
  delegatecalls actually land in" without reading bytecode.
- `is_changed_bytecode` — `true` means the deployed code DIVERGES from the
  verified source (unverified upstream change = the interesting kind).
- `verified_at` — an old date on a well-known name means you are looking at the
  ORIGINAL production contract, not the program's fork; a `name` that does not
  match the program's description is itself a scope-mapping signal.
- `abi` — function + event names when source/ABI present.

Sourcify v2 (`sourcify.dev/server/v2/contract/1/{addr}?fields=match`) returns
`match: None` for many real-world deployments; Blockscout is more reliable and
richer. Prefer Blockscout, keep Sourcify as a cross-check.

## Identifying an UNVERIFIED contract with eth_call selector probes

When Blockscout has no source, identify the surface with read-only `eth_call` on
a public RPC (`https://ethereum-rpc.publicnode.com`), `from` = zero address:

| selector | fn | tells you |
|---|---|---|
| `0x8da5cb5b` | `owner()` | who controls it (often a proxy/multisig address) |
| `0x5c60da1b` | `implementation()` | resolver pattern (beacon/static proxy) |
| `0x06fdde03` | `name()` | identity string; ABI-decode the ABI-word (offset+len) |
| `0x95d89b41` | `symbol()` | token symbol |
| `0x18160ddd` | `totalSupply()` | token vs plain contract |
| `0x54fd4d50` | `version()` | version string |
| `0x715018a6` / `0xf2fde38b` | renounce/transferOwnership | ownership is proxied/guarded? |

`name()` decodes to ABI string: word0 = `0x20` (offset), word1 = length, then the
UTF-8 bytes. `name()` = `ethereum-fee-collector` + `proxy_type: master_copy` +
implementation `GnosisSafe` means the owner is a **multisig** — retire
`transferOwnership`/`withdraw`-as-attacker theories immediately.

## Bytecode + storage triage

- `eth_getCode` length: 0 = EOA/no code; ~45 bytes = minimal proxy; ~1–2 KB =
  small custom (often the real logic, worth disassembling); >15 KB = compiled
  implementation.
- `eth_getBalance` first: a contract sitting on meaningful ETH is the only
  version worth a drain theory. Record the balance in the ledger.
- EIP-1967 slots via `eth_getStorageAt` on `0x360894…b` (impl) and `0xb5312…03`
  (admin) distinguish a standard proxy from a custom/beacon one (where both read
  `0x0` but the impl is resolved through a beacon call).

## Pure-python disassembler for small unverified proxies

A tiny EVM disassembler (opcode table + PUSH1..PUSH32 decoding, printing
`PUSH20#addr` / `PUSH4#selector` / `PUSH32 hex`) is enough to decode a 1–2 KB
proxy's dispatch: which selector is special-cased, the `tx.origin` whitelist
addresses, the `STATICCALL`/`DELEGATECALL` targets, and the revert strings. ~80
lines, no deps. Read the DELEGATECALL target address to find the real
implementation.

**Pitfall — mask a PUSH32 address to 20 bytes before `eth_getCode`/`eth_call`.**
A `STATICCALL` target pushed as a 32-byte value (24 zero bytes + 20 real bytes,
e.g. `0x00000000000000000000000000…a967884f`) passed as-is to `eth_getCode`
normalizes to "no code" and reads as an EOA — but the contract the code actually
calls is the last 20 bytes. AND the word with `0xffff…ffff`(20 bytes), then
query THAT address. Mistaking the impl-resolver for empty code sends the whole
resolution down a wrong path.

## Standard-pattern short-circuit

OpenSea's PayableProxy/beacon primitives are `tx.origin`-gated on a fixed
allowlist and `_beacon`-immutable, with the fee withdrawal in a separately-owned
implementation. When `name`/`proxy_type`/the source show you are on one of the
vendor's own audited primitives, state that in the ledger and move on — the
novelty is in the *program-specific fork code*, not the shared infra.
