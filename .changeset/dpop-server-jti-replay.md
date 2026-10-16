---
'@modelcontextprotocol/server': minor
'@modelcontextprotocol/express': minor
---

`DpopAuthOptions` takes an optional `replay` store with one method, `consume(key, ttlSeconds)`. When set, `verifyDpopToken` refuses a proof whose `jti` the store has seen (RFC 9449 §11.1), keyed by `"<jkt>.<jti>"` with a TTL of at most twice `iatSkewSeconds`. `requireDpopAuth` and the Express middleware pass it through. No store ships with the SDK.
