// This release gate closes ingress before any legacy or V111 writer is selected.
export function heldForV111Cutover(env) {
  const phase = env.UAA_V111_CUTOVER;
  if (phase === undefined) return env.UAA_V2_ENABLED === '1';
  return phase !== 'active' || env.UAA_V2_ENABLED !== '1';
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
