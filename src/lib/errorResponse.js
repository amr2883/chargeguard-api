'use strict';

// Fails CLOSED: verbose error detail (message + stack) is only sent to the
// client when NODE_ENV is explicitly 'development', or the separate
// DEBUG_ERRORS escape hatch is explicitly set to 'true' — never as a side
// effect of NODE_ENV being unset or misconfigured in a deployment. This
// mirrors the fail-closed pattern already used elsewhere in this codebase
// (e.g. SECRET_SALT / IDENTITY_GRAPH_SECRET throwing on startup rather than
// silently falling back to an insecure default).
const DEBUG_ERRORS = process.env.NODE_ENV === 'development' || process.env.DEBUG_ERRORS === 'true';

/**
 * Builds the client-facing JSON body for a server-fault (5xx) response.
 * Never includes err.message/err.stack in production — every call site is
 * expected to have already logged the full error server-side via
 * logger.error() before calling this, so no debuggability is lost, only
 * hidden from the HTTP response.
 *
 * @param {Error} err
 * @param {string} [publicMessage] Generic message shown when not in debug mode.
 * @returns {{error: string, stack?: string}}
 */
function safeErrorPayload(err, publicMessage = 'Internal server error') {
  if (DEBUG_ERRORS) {
    return {
      error: (err && err.message) || publicMessage,
      stack: err && err.stack,
    };
  }
  return { error: publicMessage };
}

module.exports = { safeErrorPayload, DEBUG_ERRORS };