---
'@modelcontextprotocol/server': minor
---

`requireDpopAuth` (fetch) takes an optional `requestUrl` function that derives the URL the proof's `htu` must match, for servers behind a reverse proxy or TLS termination where `request.url` is not the URL the client signed. It defaults to `request.url`. A function that throws answers `500`, like a throwing verifier.
