# V110 native browser hooks — undeployed feature work

This branch prepares opt-in browser integration only. The default browser config is disabled. It does not install/authenticate/issue a live V110 family, change database state or enable production. The current agreed DB hold remains.

Common browser control/display/entry/bootstrap code is copied byte-for-byte from the exact Studio integration feature source; the validation workflow must compare those common bytes across all three checkouts. Only per-app default config differs. UI control stores opaque non-authorizing browser metadata, not credentials, grants or private content. Exact configured origins and document/source nonces are required.

Native profile/bootstrap account IDs are compared against the app's actual verified V110 context before unmasking. Hifz's permanent student ID may differ from the Academy/Studio account ID; cross-app binding is shared parent/browser generation. Private fetch bodies and late responses are guarded. Known global clearing masks locally first and drops native identity/cache/request state. A previously revealed native document is reloaded on resumption/change, so old native globals/DOM/media cannot be unmasked; versioned public code may still be reused.

Hifz's ordinary journal/profile data reads remain live. No journal content is added to a display/control cache. Native server permissions, source guards, ownership, existing schema/IDs/copies and timing gates are unchanged. Studio's old completed private response/sessionStorage cache is bypassed only when this explicit feature mode is installed; unrelated legacy behavior remains.

The actual fresh V110 context producer must provide session/family/current credential/browser/security/unlock facts and real last qualifying same-app foreground time. No native verifiedAt or profile timestamp is substituted. Missing/unavailable context keeps UI masked. Academy's successful sign-in/handover callback must supply its real verified browserContext to complete the exact preceding browser-clear intent. Child PIN login is blocked by the feature adapter. This is not proof of implemented issuer/admission/refresh/PIN/CSRF, global server cancellation, late Set-Cookie handling or full application authorization.

Testing must distinguish native frontends with synthetic authoritative-response fixtures from actual JWT/native backend authorization. Same-site, different-origin browser clearing and storage partition failures require real Chromium checks. Current proposal tables are not installed, and no live login/DB/config changes are authorised.

The existing feature_worker shares live Core/Admin/coordinator/bucket bindings. Do not deploy a normal writable runtime or exercise auth there. Await the owner's separate isolation work or use a reviewed zero-binding-use read-only preview. GitHub fixtures are disposable; no Mac files/builds/tests.
