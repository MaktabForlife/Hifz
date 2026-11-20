# Hifz V111 native integration candidate

This source candidate is local and inactive. It does not change deployment,
Wrangler environment selectors, existing databases, migration history or build
selection. Set `UAA_V2_ENABLED=1` only through a separately approved configuration.
The current `config/v111-auth.json` remains activation-disabled.

The canonical V2 origin is `https://mahadarwa-hifz.ummabbadacademy.app`.
The owning Worker serves an exact public asset list and explicit native personal
link shells. Unknown/protected routes never use the current wildcard Pages SPA
fallback. Exact C19 auth/internal paths go to the common runtime, including its
strict callback POST relay and external relay module. Browser callback secrets
are never parsed from query strings or fragments by the native integration.

`createHifzV2Handler` accepts trusted runtime/native-dispatch constructor seams
for isolated tests. Default mode uses the actual app `runtimeFor`. Public SDK
modules must be mapped only to `/js/v111/browser-session.mjs` and
`/js/v111/browser-drafts.mjs`; no private server module directory is public.
The separate frontend/Static Assets package and actual resource setup still need
source/config/build acceptance and deployment approval.

V2 native business routes are `/api/...`. Their existing handlers receive a
branded common-runtime capability projected to the permanent Hifz student ID and
native role. Request subjects never select the authenticated native actor.
Warm ordinary reads use the verified app snapshot. No native identity SQL is
added before a pure business SELECT. Each actual native effect obtains the live
write guard and runs in the owning D1 batch with its guard before/after rows.
This fences each effect; it does not make the legacy compound save atomic or
create a business operation receipt. Existing business SQL, privacy, teacher and
row ownership checks remain in control.

The app-specific native factory resolves `academy_profile_links` to `students.id`
and checks the source credential epoch. Missing/incomplete/duplicate mappings
deny. No account is provisioned from browser input. Native bearer/PIN registration,
lookup and old v1 handoff are disabled in explicit V2 mode. Old code/files remain
for unchanged non-V2 operation. The v1 profile-delivery path accepts credentials
and is not enabled for V2; an accepted authenticated versioned Academy identity
intake without `pinHash` is an explicit integration dependency.

Draft resources are closed native selectors:

- `hifz:/sabaq:own` (similarly sabaq-dhor, dhor, reflections).
- Explicit native subject: `hifz:/sabaq:id.<encodeURIComponent(nativeID)>`.
- Existing row: append `:entry:<positive integer>`.
- Editor input: `hifz:/editor/{sabaq|sabaq-dhor|dhor|reflections}:{own|id.<encodedID>}`.

The key-release guard combines the current canonical/native mapping, role,
active native subject and actual journal-row ownership where a row is named.
Unknown paths/encodings/resources deny. `own` and a native ID literally `own`
are distinct. Encrypted input checkpoints are demanded on first editor use;
input is held until storage/key preflight succeeds. No draft key is written to
browser storage by native code. The common SDK owns encryption, deadlines,
leadership, cookie operations, authority headers and immediate context clearing.

Before each mutation, the adapter awaits the encrypted in-flight marker. A lost,
failed or stale response marks `SAVE_OUTCOME_UNKNOWN`; it never retries the
original POST/PATCH/DELETE. Manual reconciliation freshly reads the authorised
journal, plans, comments (native row fields) and attendance. Read errors remain
unavailable, never `[]`. Matching text or apparent absence never proves completion.
Only a deliberate selected existing-row PATCH can proceed after fresh inspection;
its own marker is separate and the original outcome remains unknown. This is not
an operation-status API. Logout/switch synchronously masks/clears available native
views/caches and discards drafts through the common SDK; saved/partial server
business records remain. The existing service worker is not registered or cleaned
up by this candidate.

Validation uses only source parsing, injected transports and disposable in-memory
SQLite/encrypted stores. This document does not claim accounts, a browser, local
server, hosted APIs, databases, DNS/TLS or production acceptance were exercised.
AI remains off. No deletion, untracking, build exclusion, push or deployment.
