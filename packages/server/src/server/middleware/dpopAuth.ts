/**
 * DPoP (RFC 9449 / SEP-1932) authentication gate for MCP servers acting as an OAuth 2.0 Resource
 * Server. Mirrors the shape of `bearerAuth.ts`: {@linkcode verifyDpopToken} validates a request
 * end to end (token + proof, both required), {@linkcode dpopAuthChallengeResponse} maps a failure
 * to the matching HTTP response, and {@linkcode requireDpopAuth} composes both for web-standard
 * `fetch(request)` hosts. Framework adapters (e.g. `@modelcontextprotocol/express`) build on
 * {@linkcode verifyDpopToken} / {@linkcode dpopAuthChallengeResponse} directly.
 */

import type { AuthInfo } from '@modelcontextprotocol/core-internal';
import { OAuthError, OAuthErrorCode } from '@modelcontextprotocol/core-internal';

import { buildWwwAuthenticateHeader } from './authChallenge';
import type { VerifyBearerTokenOptions } from './bearerAuth';
import { assertExpectedResource } from './bearerAuth';
import type { DpopNonceState } from './dpop';
import { DEFAULT_IAT_SKEW_SECONDS, DPOP_SUPPORTED_ALGS, verifyDpopProof } from './dpop';

// Re-exported so a `requireDpopAuth` caller building `DpopAuthOptions` doesn't need a second
// import from `./bearerAuth` for the token-verifier type it shares with Bearer auth.
export type { OAuthTokenVerifier } from './bearerAuth';

/** RFC 9449 §5.1: the JWS algorithms this SDK's DPoP validator accepts, advertised in the `algs` challenge parameter. */
const ADVERTISED_ALGS = DPOP_SUPPORTED_ALGS.join(' ');

/**
 * Options for {@linkcode verifyDpopToken}, {@linkcode dpopAuthChallengeResponse}, and
 * {@linkcode requireDpopAuth}.
 */
export interface DpopAuthOptions extends VerifyBearerTokenOptions {
    /**
     * Acceptance window for the proof's `iat`, in seconds either side of the server's clock.
     * @default 300 (SEP-1932's recommended ±5 minutes)
     */
    iatSkewSeconds?: number;

    /**
     * Server-provided nonce support (RFC 9449 §9 — a SHOULD, not a MUST). Omit to never require
     * a nonce. When set, {@linkcode dpopAuthChallengeResponse} calls `issue()` for the `DPoP-Nonce`
     * header on every `401` (so a client's first, token-less request already learns the nonce), and
     * {@linkcode verifyDpopToken} calls `verify()` (via {@linkcode DpopNonceState}) to check a
     * presented proof's nonce. RFC 9449 §8.2 lets a fresh nonce ride on success responses too; the
     * Express middleware sets it there itself, a `fetch` host sets `DPoP-Nonce: nonce.issue()` on its
     * own response. When to rotate is the host's policy, expressed through what `issue()` returns.
     */
    nonce?: {
        /**
         * The nonce to send in a `DPoP-Nonce` response header: the one the next proof should carry.
         * Called on every `401`, so also for unauthenticated requests; return the current value and
         * keep no per-call state, or an anonymous caller can make the server mint nonces at will.
         */
        issue(): string;
    } & DpopNonceState;

    /**
     * `jti` replay protection (RFC 9449 §11.1 — a SHOULD). Omit to not track `jti` values. When
     * set, {@linkcode verifyDpopToken} calls `consume()` once per otherwise-valid request, after
     * every other check, with the key `"<jkt>.<jti>"` (proof key thumbprint and proof `jti`) and
     * the number of whole seconds the proof could at most still pass the `iat` window (twice
     * `iatSkewSeconds`, rounded up, at least 1). The store keeps the key for that long; `false`
     * (seen before) refuses the request with `401 invalid_dpop_proof`. Storage and atomicity are
     * the host's — an in-memory `Map`, Redis `SET NX EX`, etc.
     */
    replay?: {
        /**
         * Record `key` for `ttlSeconds` (a positive integer); return `false` if it was already
         * recorded. May return a `Promise`; {@linkcode verifyDpopToken} always `await`s the result.
         */
        consume(key: string, ttlSeconds: number): boolean | Promise<boolean>;
    };
}

/** A raw incoming request's fields relevant to DPoP validation, framework-neutral. */
export interface DpopRequest {
    /** Raw `Authorization` header value. */
    authorization: string | null | undefined;
    /**
     * Raw `DPoP` header value(s) — see {@linkcode server/middleware/dpop.VerifyDpopProofOptions.proof | VerifyDpopProofOptions.proof} in `dpop.ts` for
     * why this is `string | string[] | undefined` rather than always a single string.
     */
    dpop: string | string[] | undefined;
    /** HTTP method of the request. */
    method: string;
    /** Full URL the request arrived at — the value the proof's `htu` claim must match. */
    url: string | URL;
}

/**
 * Validate a DPoP-bound request — the `Authorization: DPoP <token>` header and the accompanying
 * `DPoP` proof header, together — and return the verified {@linkcode AuthInfo}.
 *
 * The runtime-neutral core of DPoP authentication, mirroring {@linkcode server/middleware/bearerAuth.verifyBearerToken | verifyBearerToken}: parses
 * the `Authorization` header (requiring the `DPoP` scheme, not `Bearer`), runs `options.verifier`,
 * verifies the proof against the request's method/URL via {@linkcode verifyDpopProof}, then checks
 * that the proof key's RFC 7638 thumbprint matches the verified token's `cnf.jkt` (RFC 9449 §4.3
 * step 12b — the actual sender-constraint check; everything upstream of it only confirms the
 * caller holds *some* valid token and *some* well-formed proof, not that they're bound together).
 * Then enforces `expectedResource`, `requiredScopes`, and token expiry exactly as `verifyBearerToken` does,
 * consumes the proof's `jti` through `options.replay` when set, and stamps `resourceMetadataUrl` onto
 * the returned {@linkcode AuthInfo} as `verifyBearerToken` does.
 *
 * On any failure throws an {@linkcode OAuthError} — pass that to
 * {@linkcode dpopAuthChallengeResponse} for the matching HTTP answer, or use
 * {@linkcode requireDpopAuth} to get both steps as one call.
 */
export async function verifyDpopToken(request: DpopRequest, options: DpopAuthOptions): Promise<AuthInfo> {
    const { verifier, requiredScopes = [], expectedResource, iatSkewSeconds = DEFAULT_IAT_SKEW_SECONDS, nonce, replay } = options;

    if (!request.authorization) {
        throw new OAuthError(OAuthErrorCode.InvalidToken, 'Missing Authorization header');
    }
    const [scheme, token] = request.authorization.split(' ');
    if (scheme?.toLowerCase() !== 'dpop' || !token) {
        throw new OAuthError(OAuthErrorCode.InvalidToken, "Invalid Authorization header format, expected 'DPoP TOKEN'");
    }

    const authInfo = await verifier.verifyAccessToken(token);

    // Same audience check as verifyBearerToken. A DPoP endpoint must not skip it.
    assertExpectedResource(authInfo, expectedResource);

    const { jkt, claims } = await verifyDpopProof({
        proof: request.dpop,
        method: request.method,
        url: request.url,
        accessToken: token,
        iatSkewSeconds,
        nonce
    });

    // RFC 9449 §4.3 step 12b: the proof's key must be the one this token is bound to. A verifier
    // that never populates `cnf.jkt` (does not support DPoP-bound tokens) cannot pass this gate —
    // every token it issues is rejected here rather than silently accepted as unbound.
    if (authInfo.cnf?.jkt !== jkt) {
        throw new OAuthError(OAuthErrorCode.InvalidToken, 'Access token is not bound to this proof key (cnf.jkt mismatch)');
    }

    if (requiredScopes.length > 0) {
        const hasAllScopes = requiredScopes.every(scope => authInfo.scopes.includes(scope));
        if (!hasAllScopes) {
            throw new OAuthError(OAuthErrorCode.InsufficientScope, 'Insufficient scope');
        }
    }

    if (typeof authInfo.expiresAt !== 'number' || Number.isNaN(authInfo.expiresAt)) {
        throw new OAuthError(OAuthErrorCode.InvalidToken, 'Token has no expiration time');
    } else if (authInfo.expiresAt < Date.now() / 1000) {
        throw new OAuthError(OAuthErrorCode.InvalidToken, 'Token has expired');
    }

    // Last, so a refused request never consumes its jti. TTL = the iat window (2 * skew), whole seconds, at least 1.
    if (replay && !(await replay.consume(`${jkt}.${claims.jti}`, Math.max(1, Math.ceil(2 * iatSkewSeconds))))) {
        throw new OAuthError(OAuthErrorCode.InvalidDpopProof, "DPoP proof 'jti' has already been used");
    }

    // Same hand-off as verifyBearerToken: a verifier-set value wins over the gate's configuration.
    if (options.resourceMetadataUrl !== undefined && authInfo.resourceMetadataUrl === undefined) {
        return { ...authInfo, resourceMetadataUrl: options.resourceMetadataUrl };
    }

    return authInfo;
}

/**
 * Build the HTTP answer for a DPoP authentication failure.
 *
 * Maps an {@linkcode OAuthError} to its status — `401` for `invalid_token`/`invalid_dpop_proof`
 * and `use_dpop_nonce` (all carrying a `WWW-Authenticate: DPoP …` challenge advertising the
 * accepted `algs`, plus `resource_metadata` when configured), `403` for `insufficient_scope`,
 * `500` for `server_error`, `400` for anything else. When `options.nonce` is set, every `401` also
 * carries a `DPoP-Nonce` response header (from `options.nonce.issue()`) for the client's next proof
 * — see RFC 9449 §8.2 / §9. A non-`OAuthError` value answers `500 server_error`. The body is the
 * OAuth error JSON.
 */
export function dpopAuthChallengeResponse(
    error: unknown,
    options?: Pick<DpopAuthOptions, 'requiredScopes' | 'resourceMetadataUrl' | 'nonce'>
): Response {
    const { requiredScopes = [], resourceMetadataUrl, nonce } = options ?? {};

    if (!(error instanceof OAuthError)) {
        const serverError = new OAuthError(OAuthErrorCode.ServerError, 'Internal Server Error');
        return Response.json(serverError.toResponseObject(), { status: 500 });
    }

    const challenge = (): string =>
        buildWwwAuthenticateHeader('DPoP', error.code, error.message, requiredScopes, resourceMetadataUrl, { algs: ADVERTISED_ALGS });

    switch (error.code) {
        case OAuthErrorCode.InvalidToken:
        case OAuthErrorCode.InvalidDpopProof:
        case OAuthErrorCode.UseDpopNonce: {
            // Every 401 carries the nonce, not only use_dpop_nonce: the first request has no proof yet to carry one.
            const headers: Record<string, string> = { 'WWW-Authenticate': challenge() };
            if (nonce) headers['DPoP-Nonce'] = nonce.issue();
            return Response.json(error.toResponseObject(), { status: 401, headers });
        }
        case OAuthErrorCode.InsufficientScope: {
            return Response.json(error.toResponseObject(), { status: 403, headers: { 'WWW-Authenticate': challenge() } });
        }
        case OAuthErrorCode.ServerError: {
            return Response.json(error.toResponseObject(), { status: 500 });
        }
        default: {
            return Response.json(error.toResponseObject(), { status: 400 });
        }
    }
}

/**
 * Require a valid DPoP-bound token on web-standard requests.
 *
 * The framework-free counterpart of `requireDpopAuth` from `@modelcontextprotocol/express`, for
 * hosts whose HTTP surface is a `fetch(request)` handler — edge/serverless runtimes, Deno, Bun,
 * Hono. The returned gate resolves to the verified {@linkcode AuthInfo}, or to the ready-to-return
 * challenge `Response` when the request must be refused.
 *
 * The proof's `htu` is compared with `request.url`. Behind a reverse proxy or TLS termination that
 * is the internal URL, not the one the client signed, so pass `requestUrl`, a function that derives
 * the external URL per request (for example from `Forwarded` headers you trust). It is a function,
 * not a fixed string, so one gate behind several routes never checks every path against one URL.
 * The Express middleware rebuilds the URL itself through Express's `trust proxy` setting instead
 * (https://expressjs.com/en/guide/behind-proxies.html); see RFC 9449 §4.3 for what `htu` must match.
 *
 * @example
 * ```ts source="./dpopAuth.examples.ts#requireDpopAuth_fetchGate"
 * const gate = requireDpopAuth({ verifier, requiredScopes: ['mcp'] });
 *
 * async function fetchHandler(request: Request): Promise<Response> {
 *     const auth: AuthInfo | Response = await gate(request);
 *     if (auth instanceof Response) return auth;
 *     return handler.fetch(request, { authInfo: auth });
 * }
 * ```
 */
export function requireDpopAuth(
    options: DpopAuthOptions & {
        /** Derives the URL the proof's `htu` must match, when it is not `request.url`. @default request.url */
        requestUrl?: (request: Request) => string;
    }
): (request: Request) => Promise<AuthInfo | Response> {
    // Destructure at creation so a plain-JS caller passing undefined or malformed options crashes
    // at startup, not on the first request.
    const { verifier, requiredScopes = [], resourceMetadataUrl, expectedResource, iatSkewSeconds, nonce, replay, requestUrl } = options;
    const resolved = { verifier, requiredScopes, resourceMetadataUrl, expectedResource, iatSkewSeconds, nonce, replay };
    return async request => {
        // Outside the try: a wrong-framework misuse (no web-standard Request) should throw
        // loudly, not surface as a 500 challenge.
        const [authorization] = (request.headers.get('authorization') ?? '').split(',');
        // Headers.get comma-joins repeated headers (fetch's Headers behavior, unlike Node's
        // `http` which keeps the first) — verifyDpopProof's own comma check catches a genuine
        // duplicate DPoP header this way; a single proof JWT never contains a comma.
        const dpop = request.headers.get('dpop') ?? undefined;
        try {
            // Inside the try: a host's requestUrl function that throws answers 500 like a throwing verifier.
            const url = requestUrl ? requestUrl(request) : request.url;
            return await verifyDpopToken({ authorization: authorization || undefined, dpop, method: request.method, url }, resolved);
        } catch (error) {
            return dpopAuthChallengeResponse(error, resolved);
        }
    };
}
