---
'@modelcontextprotocol/server': minor
'@modelcontextprotocol/express': minor
---

With `options.nonce` set, `dpopAuthChallengeResponse` puts a `DPoP-Nonce` header on every `401`, not only on `use_dpop_nonce`, so a client's first, token-less request already learns the nonce (RFC 9449 §8.2). The Express `requireDpopAuth` middleware also sets it on accepted requests. A `fetch` host sets `DPoP-Nonce: nonce.issue()` on its own success response.
