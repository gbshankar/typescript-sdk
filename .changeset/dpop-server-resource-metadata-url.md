---
'@modelcontextprotocol/server': patch
---

`verifyDpopToken` stamps the gate's `resourceMetadataUrl` onto the returned `AuthInfo` when the verifier left it unset, as `verifyBearerToken` does, so a later scope challenge on a DPoP request advertises the same document. A verifier-set value still wins.
