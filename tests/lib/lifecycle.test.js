'use strict';

const { installCrashHandlers, installShutdownHandler } = require('../../src/lib/lifecycle');

function flushMicrotasks() { return new Promise((r) => setImmediate(r)); }

describe('lifecycle: installCrashHandlers', () => {
  let cleanup, exitFn, mockLogger;

  beforeEach(() => {
    exitFn = jest.fn();
    mockLogger = { info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() };
    cleanup = installCrashHandlers({ logger: mockLogger, exitFn });
  });

  afterEach(() => {
    if (cleanup) cleanup();
    cleanup = null;
  });

  it('exits with 1 on unhandledRejection', () => {
    process.emit('unhandledRejection', new Error('boom'));
    expect(exitFn).toHaveBeenCalledWith(1);
  });

  it('logs the error via logger.error on unhandledRejection', () => {
    process.emit('unhandledRejection', new Error('boom'));
    expect(mockLogger.error).toHaveBeenCalledWith(
      expect.objectContaining({ event: 'unhandledRejection', error: 'boom' }),
      expect.any(String)
    );
  });

  it('exits with 1 on uncaughtException', () => {
    process.emit('uncaughtException', new Error('kaboom'));
    expect(exitFn).toHaveBeenCalledWith(1);
  });

  it('does not throw when logger is missing (defensive)', () => {
    cleanup(); cleanup = null;
    const exit2 = jest.fn();
    const cleanup2 = installCrashHandlers({ exitFn: exit2 });
    expect(() => process.emit('uncaughtException', new Error('x'))).not.toThrow();
    expect(exit2).toHaveBeenCalledWith(1);
    cleanup2();
  });
});

describe('lifecycle: installShutdownHandler', () => {
  let server, client, exitFn, mockLogger, timerObj, setTimeoutFn, clearTimeoutFn;

  beforeEach(() => {
    server = { close: jest.fn((cb) => { if (cb) cb(); }) };
    client = { $disconnect: jest.fn(() => Promise.resolve()) };
    exitFn = jest.fn();
    mockLogger = { info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() };
    timerObj = { unref: jest.fn() };
    setTimeoutFn = jest.fn(() => timerObj);
    clearTimeoutFn = jest.fn();
  });

  it('calls server.close, disconnects clients, and exits 0', async () => {
    const shutdown = installShutdownHandler({
      server, clients: [client], logger: mockLogger, exitFn,
      timeoutMs: 25000, setTimeoutFn, clearTimeoutFn,
    });
    shutdown('SIGTERM');
    await flushMicrotasks();
    expect(server.close).toHaveBeenCalled();
    expect(client.$disconnect).toHaveBeenCalled();
    expect(exitFn).toHaveBeenCalledWith(0);
    expect(clearTimeoutFn).toHaveBeenCalledWith(timerObj);
  });

  it('unrefs the force-exit timer', () => {
    const shutdown = installShutdownHandler({
      server, clients: [client], logger: mockLogger, exitFn,
      timeoutMs: 25000, setTimeoutFn, clearTimeoutFn,
    });
    shutdown('SIGTERM');
    expect(timerObj.unref).toHaveBeenCalled();
  });

  it('does not exit twice on duplicate signal', async () => {
    const shutdown = installShutdownHandler({
      server, clients: [client], logger: mockLogger, exitFn,
      timeoutMs: 25000, setTimeoutFn, clearTimeoutFn,
    });
    shutdown('SIGTERM');
    shutdown('SIGINT');
    await flushMicrotasks();
    expect(exitFn).toHaveBeenCalledTimes(1);
  });

  it('logs shutdownStart and shutdownComplete with the signal', async () => {
    const shutdown = installShutdownHandler({
      server, clients: [client], logger: mockLogger, exitFn,
      timeoutMs: 25000, setTimeoutFn, clearTimeoutFn,
    });
    shutdown('SIGTERM');
    await flushMicrotasks();
    const events = mockLogger.info.mock.calls.map((c) => (c[0] && c[0].event) || null);
    expect(events).toContain('shutdownStart');
    expect(events).toContain('shutdownComplete');
  });

  it('force-exits with 1 when the timer fires (hung server.close)', () => {
    let timerCb;
    const hangTimer = jest.fn((cb) => { timerCb = cb; return { unref: jest.fn() }; });
    const hung = { close: jest.fn(() => { /* never calls cb */ }) };
    const shutdown = installShutdownHandler({
      server: hung, clients: [client], logger: mockLogger, exitFn,
      timeoutMs: 25000, setTimeoutFn: hangTimer, clearTimeoutFn,
    });
    shutdown('SIGTERM');
    expect(typeof timerCb).toBe('function');
    timerCb();
    expect(exitFn).toHaveBeenCalledWith(1);
  });

  it('works with zero clients', async () => {
    const shutdown = installShutdownHandler({
      server, clients: [], logger: mockLogger, exitFn,
      timeoutMs: 25000, setTimeoutFn, clearTimeoutFn,
    });
    shutdown('SIGTERM');
    await flushMicrotasks();
    expect(server.close).toHaveBeenCalled();
    expect(exitFn).toHaveBeenCalledWith(0);
  });

  it('tolerates a client whose $disconnect throws synchronously', async () => {
    const thrower = { $disconnect: jest.fn(() => { throw new Error('nope'); }) };
    const shutdown = installShutdownHandler({
      server, clients: [thrower], logger: mockLogger, exitFn,
      timeoutMs: 25000, setTimeoutFn, clearTimeoutFn,
    });
    shutdown('SIGTERM');
    await flushMicrotasks();
    expect(exitFn).toHaveBeenCalledWith(0);
  });
});