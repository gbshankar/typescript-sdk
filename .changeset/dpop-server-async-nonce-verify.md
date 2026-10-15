---
'@modelcontextprotocol/server': minor
---

`DpopNonceState.verify` may return `boolean | Promise<boolean>`, so a nonce store shared between server instances can be used; `verifyDpopProof` awaits it. A synchronous `verify` keeps working unchanged. `issue()` stays synchronous.
