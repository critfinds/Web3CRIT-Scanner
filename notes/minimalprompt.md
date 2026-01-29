Audit: `modules/web3/tools/Web3CRIT-Scanner` as a hostile reviewer.

Decide if it is **production‑grade for $5M+ TVL DeFi** and **Immunefi High/Critical** discovery.

Rules:
- Only count exploit chains ending in **theft / unauthorized transfer / governance or proxy takeover / insolvency**.
- Every accepted finding must include a **Foundry PoC that compiles + passes** (no placeholders, no `address(0)`, no `0x...`, no TODOs).
- You may only reference **functions, storage variables, and events** by name.

Check:
1) In `src/cli.js`, is exploit-driven gating actually enabled (e.g., `--immunefi-only`)? If not, fail it.
2) Can any detector output HIGH/CRITICAL from heuristics/keywords without real value/takeover path?
3) Scan `test/contracts/secure/SecurePatterns.sol`: must be **0 HIGH, 0 CRITICAL** (otherwise show which detector + why).
4) Give the single biggest architectural fix to become bounty-grade.

Output only:
Verdict: {Not production‑grade | Borderline | Production‑grade}
Failure modes: 3–6 bullets (file + function)
Biggest fix: 1 sentence
