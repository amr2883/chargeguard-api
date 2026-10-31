'use strict';

// S4: crash and shutdown handlers.
//
// Node 20+ exits on unhandledRejection / uncaughtException by default (with
// an unstructured stack dump to stderr). That outcome is right — an unhandled
// rejection means an invariant is broken and the process state is unknown.
// But the dump is easy to lose in Render's log stream. These helpers log via
// the app logger first, then exit, so the reason is visible with the same
// shape as other errors.
//
// SIGTERM is Render's shutdown signal (30s budget, then SIGKILL). We close
// the HTTP server, await in-flight requests, then best-effort disconnect the
// Prisma clients. A 25s force-exit timer guarantees we exit before SIGKILL.

function installCrashHandlers({ logger, exitFn = process.exit } = {}) {
  const logFatal = (obj, msg) => {
    try { if (logger && typeof logger.error === 'function') logger.error(obj, msg); } catch (_) {}
    try { console.error(`[FATAL] ${msg}`, obj); } catch (_) {}
  };

  const onRejection = (reason) => {
    const msg = reason && reason.message ? reason.message : String(reason);
    const stack = reason && reason.stack ? reason.stack : undefined;
    logFatal({ module: 'lifecycle', event: 'unhandledRejection', error: msg, stack }, 'Unhandled promise rejection — exiting');
    exitFn(1);
  };

  const onException = (err) => {
    const msg = err && err.message ? err.message : String(err);
    const stack = err && err.stack ? err.stack : undefined;
    logFatal({ module: 'lifecycle', event: 'uncaughtException', error: msg, stack }, 'Uncaught exception — exiting');
    exitFn(1);
  };

  process.on('unhandledRejection', onRejection);
  process.on('uncaughtException', onException);

  return function cleanup() {
    try { process.removeListener('unhandledRejection', onRejection); } catch (_) {}
    try { process.removeListener('uncaughtException', onException); } catch (_) {}
  };
}

function installShutdownHandler({ server, clients = [], logger, exitFn = process.exit, timeoutMs = 25000, setTimeoutFn = setTimeout, clearTimeoutFn = clearTimeout } = {}) {
  let shuttingDown = false;

  return function shutdown(signal) {
    if (shuttingDown) return;
    shuttingDown = true;

    try { if (logger && typeof logger.info === 'function') logger.info({ module: 'lifecycle', event: 'shutdownStart', signal }, 'Shutdown initiated'); } catch (_) {}

    const timer = setTimeoutFn(() => {
      try { if (logger && typeof logger.error === 'function') logger.error({ module: 'lifecycle', event: 'shutdownTimeout', timeoutMs }, 'Forced shutdown after timeout'); } catch (_) {}
      exitFn(1);
    }, timeoutMs);
    if (timer && typeof timer.unref === 'function') timer.unref();

    server.close(async () => {
      const promises = [];
      for (const c of clients) {
        try {
          if (c && typeof c.$disconnect === 'function') promises.push(c.$disconnect());
          else promises.push(Promise.resolve());
        } catch (e) {
          promises.push(Promise.resolve());
        }
      }
      try { await Promise.allSettled(promises); } catch (_) {}
      try { clearTimeoutFn(timer); } catch (_) {}
      try { if (logger && typeof logger.info === 'function') logger.info({ module: 'lifecycle', event: 'shutdownComplete', signal }, 'Shutdown complete'); } catch (_) {}
      exitFn(0);
    });
  };
}

module.exports = { installCrashHandlers, installShutdownHandler };