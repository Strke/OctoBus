// 360 EPP service test: parameter validation, API mapping, error mapping, auth flow

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import { fork } from 'child_process';

import { rpcdef, _test } from '../src/360-epp.js';

const mockUrl = (port) => `http://127.0.0.1:${port}`;

function startMock() {
  return new Promise((resolve, reject) => {
    const child = fork(new URL('mock_upstream.js', import.meta.url), [], {
      stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
    });
    child.on('message', (msg) => {
      if (msg?.port) resolve({ child, port: msg.port });
    });
    child.on('error', reject);
    child.on('exit', (code) => {
      if (code !== 0 && code !== null) reject(new Error(`mock exited with ${code}`));
    });
    const timer = setTimeout(() => reject(new Error('mock start timeout')), 10000);
    timer.unref?.();
    child.on('message', (msg) => {
      if (msg?.port) {
        clearTimeout(timer);
        resolve({ child, port: msg.port });
      }
    });
    child.on('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });
    child.on('exit', (code) => {
      if (code !== 0 && code !== null) {
        clearTimeout(timer);
        reject(new Error(`mock exited with ${code}`));
      }
    const child = fork(new URL('mock_upstream.js', import.meta.url), [], {
      stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
    });
    const timer = setTimeout(() => reject(new Error('mock start timeout')), 10000);
    timer.unref?.();
    child.on('message', (msg) => {
      if (msg?.port) {
        clearTimeout(timer);
        resolve({ child, port: msg.port });
      }
    });
    child.on('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });
    child.on('exit', (code) => {
      if (code !== 0 && code !== null) {
        clearTimeout(timer);
        reject(new Error(`mock exited with ${code}`));
      }
    });
  });
}

describe('360 EPP Service', () => {
  let mockServer;
  let mockPort;

  before(async () => {
    const mock = await startMock();
    mockServer = mock.child;
    mockPort = mock.port;
  });

  after(() => {
    if (mockServer) mockServer.kill();
  });

  function makeCtx(overrides = {}, reqOverrides = {}) {
    return {
      req: { ...reqOverrides },
      config: {},
      secret: {},
      bindings: {
        endpoint: mockUrl(mockPort),
        username: 'eppadmin',
        password: 'Chaitin123..',
        skipTlsVerify: true,
        ...overrides,
      },
      meta: { instance_id: 'test-instance' },
      limits: {},
    };
  }

  describe('rpcdef', () => {
    it('should return handlers for all methods', () => {
      const ctx = makeCtx();
      const methods = rpcdef(ctx);
      const keys = Object.keys(methods);
      assert.ok(keys.length >= 7, `expected >=7 methods, got ${keys.length}`);
      assert.ok(keys.every((k) => typeof methods[k] === 'function'));
    });

    it('should throw for missing endpoint', async () => {
      const ctx = makeCtx({ endpoint: '' });
      try {
        await rpcdef(ctx)['Qihoo360_EPP.Qihoo360_EPP/GetDashboardInfo']();
        assert.fail('should have thrown');
      } catch (e) {
        assert.ok(e.message.includes('endpoint') || e.message.includes('baseUrl'));
      }
    });

    it('should throw for missing credentials', async () => {
      const ctx = makeCtx({ username: '', password: '' });
      try {
        await rpcdef(ctx)['Qihoo360_EPP.Qihoo360_EPP/GetDashboardInfo']();
        assert.fail('should have thrown');
      } catch (e) {
        assert.ok(e.message.includes('username') || e.message.includes('password'));
      }
    });
  });

  describe('toStructValue', () => {
    it('should encode numbers, booleans and null as native Struct values', () => {
      assert.deepEqual(
        _test.toStructValue({
          count: 3,
          rate: 1.5,
          enabled: true,
          disabled: false,
          missing: null,
          name: 'epp',
          items: [1, false, null, { level: 2 }],
        }),
        {
          structValue: {
            fields: {
              count: { numberValue: 3 },
              rate: { numberValue: 1.5 },
              enabled: { boolValue: true },
              disabled: { boolValue: false },
              missing: { nullValue: 'NULL_VALUE' },
              name: { stringValue: 'epp' },
              items: {
                listValue: {
                  values: [
                    { numberValue: 1 },
                    { boolValue: false },
                    { nullValue: 'NULL_VALUE' },
                    { structValue: { fields: { level: { numberValue: 2 } } } },
                  ],
                },
              },
            },
          },
        }
      );
    });

    it('should keep null fields instead of dropping them', () => {
      assert.deepEqual(_test.toStructValue({ statistics: { '0': 1, '-1': null } }), {
        structValue: {
          fields: {
            statistics: {
              structValue: {
                fields: {
                  '0': { numberValue: 1 },
                  '-1': { nullValue: 'NULL_VALUE' },
                },
              },
            },
          },
        },
      });
    });
  });

  describe('GetDashboardInfo', () => {
    it('should fetch dashboard info', async () => {
      const ctx = makeCtx();
      const result = await rpcdef(ctx)['Qihoo360_EPP.Qihoo360_EPP/GetDashboardInfo']();
      assert.ok(result.data);
      assert.deepEqual(result.data.structValue.fields.terminal_count, { numberValue: 100 });
      assert.deepEqual(result.data.structValue.fields.virus_count, { numberValue: 5 });
    });
  });

  describe('ListAlarms', () => {
    it('should fetch alarm list', async () => {
      const ctx = makeCtx();
      const result = await rpcdef(ctx)['Qihoo360_EPP.Qihoo360_EPP/ListAlarms']();
      assert.ok(result.alarms);
      assert.ok(Array.isArray(result.alarms));
      assert.ok(result.total >= 0);
      assert.deepEqual(result.statistics.structValue.fields['0'], { numberValue: 1 });
      assert.deepEqual(result.statistics.structValue.fields['1'], { numberValue: 0 });
    });
  });

  describe('GetVirusStats', () => {
    it('should fetch virus stats', async () => {
      const ctx = makeCtx();
      const result = await rpcdef(ctx)['Qihoo360_EPP.Qihoo360_EPP/GetVirusStats']();
      assert.ok(result.data);
    });
  });

  describe('GetLeakFixStats', () => {
    it('should fetch leakfix stats', async () => {
      const ctx = makeCtx();
      const result = await rpcdef(ctx)['Qihoo360_EPP.Qihoo360_EPP/GetLeakFixStats']();
      assert.ok(result.data);
    });
  });

  describe('Login flow', () => {
    it('should login and cache session', async () => {
      const ctx = makeCtx();
      const result1 = await rpcdef(ctx)['Qihoo360_EPP.Qihoo360_EPP/GetDashboardInfo']();
      assert.ok(result1.data);
      // Second call should use cached session
      const result2 = await rpcdef(ctx)['Qihoo360_EPP.Qihoo360_EPP/GetVirusStats']();
      assert.ok(result2.data);
    });
  });

  describe('Error handling', () => {
    it('should handle login failure', async () => {
      const ctx = makeCtx({ password: 'wrong_password' });
      try {
        await rpcdef(ctx)['Qihoo360_EPP.Qihoo360_EPP/GetDashboardInfo']();
        assert.fail('should have thrown');
      } catch (e) {
        assert.ok(e.message.includes('login') || e.message.includes('鉴权') || e.message.includes('auth'));
      }
    });
  });
});
