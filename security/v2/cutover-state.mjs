// This release gate closes ingress before any legacy or V111 writer is selected.
export function heldForV111Cutover(env) {
  const phase = env.UAA_V111_CUTOVER;
  if (phase === undefined) return env.UAA_V2_ENABLED === '1';
  return phase !== 'active' || env.UAA_V2_ENABLED !== '1';
}

// A request eligible to reach C19 still requires the fixed origin, signed body,
// configured peer key and fresh nonce in handleServiceHTTP.
export function offlineSecurityRequest(request, env, app) {
  if (env.UAA_V111_CUTOVER !== 'held' || env.UAA_V2_ENABLED !== '1') return false;
  if (request.method !== 'POST' || request.headers.has('Origin') || request.headers.has('Cookie')) return false;
  if (!request.headers.has('X-UAA-Service-Key')) return false;
  const url = new URL(request.url);
  if (url.search) return false;
  if (app === 'academy') return url.pathname === '/internal/auth/v2/reconcile';
  return ['studio', 'hifz'].includes(app) && url.pathname === '/internal/auth/v2/events';
}

export function cutoverUnavailable() {
  return Response.json({
    success: false,
    code: 'V111_CUTOVER_HOLD',
    error: 'The app is temporarily unavailable during an update.',
  }, {
    status: 503,
    headers: {'Cache-Control': 'no-store', 'Retry-After': '60'},
  });
}

export function requireV111CutoverOpen(env) {
  if (heldForV111Cutover(env)) {
    throw Object.assign(Error('The app is temporarily unavailable during an update.'), {
      status: 503, code: 'V111_CUTOVER_HOLD',
    });
  }
}
