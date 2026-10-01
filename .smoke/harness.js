/* Smoke test: stub every outbound HTTP call, boot the bot, drive it via /webhook. */
const axios = require('axios');

const SCENARIO = process.argv[2] || 'healthy';
const STATS_DELAY_MS = SCENARIO === 'stats-timeout' ? 1500 : 0;

const sentToTelegram = [];
const calls = [];
let statsCallCount = 0;

const GUID_A = 'aaaaaaaa-0000-0000-0000-000000000001';
const GUID_B = 'bbbbbbbb-0000-0000-0000-000000000002';

const redis = Object.create(null);

function reply(config, data, status = 200) {
  return { data, status, statusText: 'OK', headers: {}, config, request: {} };
}

axios.defaults.adapter = async (config) => {
  const url = config.url || '';
  calls.push(url);

  if (url.includes('api.telegram.org')) {
    const body = typeof config.data === 'string' ? JSON.parse(config.data) : (config.data || {});
    sentToTelegram.push(body.text);
    return reply(config, { ok: true });
  }

  if (url.includes('auth.weeztix.com/tokens')) {
    return reply(config, {
      access_token: 'aaa.bbb.ccc',
      refresh_token: 'refresh-2',
      expires_in: 3600
    });
  }

  if (url.includes('auth.weeztix.com/users/me')) {
    return reply(config, { companies: [{ guid: 'company-guid-0000000000000000000000' }] });
  }

  // Upstash REST
  if (url.startsWith('http://redis.local')) {
    const rest = url.replace('http://redis.local/', '');
    const [op, rawKey] = rest.split('/');
    const key = decodeURIComponent(rawKey);
    if (op === 'get') return reply(config, { result: key in redis ? redis[key] : null });
    if (op === 'set') { redis[key] = config.data; return reply(config, { result: 'OK' }); }
  }

  if (url.includes('/statistics/dashboard/')) {
    statsCallCount++;
    if (STATS_DELAY_MS > Number(config.timeout || 0)) {
      // axios enforces config.timeout inside the real adapter; emulate that here.
      await new Promise(r => setTimeout(r, Number(config.timeout)));
      const err = new Error(`timeout of ${config.timeout}ms exceeded`);
      err.code = 'ECONNABORTED';
      throw err;
    }
    return reply(config, {
      'Maledetta Primavera': {
        aggregations: {
          ticketCount: {
            statistics: {
              buckets: [
                { key: GUID_A, doc_count: 10 },
                { key: GUID_B, doc_count: 5 }
              ]
            }
          },
          scanned: {
            statistics: {
              buckets: [
                { key: GUID_A, doc_count: 4 },
                { key: GUID_B, doc_count: 1 }
              ]
            }
          }
        }
      }
    });
  }

  if (url.includes('/event/') && url.includes('/ticket')) {
    return reply(config, [
      { guid: GUID_A, name: 'Wave 1', available_stock: 40, min_price: 1382 },
      { guid: GUID_B, name: 'Wave 2', available_stock: 25, min_price: 1674 }
    ]);
  }

  return reply(config, {}, 404);
};

process.env.BOT_TOKEN = 'test-token';
process.env.OAUTH_CLIENT_ID = 'cid';
process.env.OAUTH_CLIENT_SECRET = 'csecret';
process.env.WEEZTIX_EVENT_GUID = GUID_A;
process.env.WEEZTIX_EVENT_GUID_NIGHT = GUID_B;
process.env.WEEZTIX_REFRESH_TOKEN = 'refresh-1';
process.env.MP_CAPACITY = '100';
process.env.REDIS_URL = 'http://redis.local';
process.env.REDIS_TOKEN = 'rtoken';
process.env.PORT = SCENARIO === 'stats-timeout' ? '4557' : '4555';
if (SCENARIO === 'stats-timeout') process.env.STATS_TIMEOUT_MS = '150';

require('../index.js');

const wait = (ms) => new Promise(r => setTimeout(r, ms));
const nodeHttp = require('http');

function postWebhook(text) {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify({ message: { chat: { id: 999 }, text } });
    const req = nodeHttp.request({
      host: '127.0.0.1', port: Number(process.env.PORT), path: '/webhook', method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) }
    }, (res) => { res.resume(); res.on('end', resolve); });
    req.on('error', reject);
    req.end(payload);
  });
}

async function send(text, settleMs = 700) {
  sentToTelegram.length = 0;
  await postWebhook(text);
  await wait(settleMs);
  return sentToTelegram.slice();
}

(async () => {
  await wait(1200); // let the boot warm-up finish

  let failures = 0;
  const check = (name, ok, detail) => {
    console.log((ok ? 'PASS  ' : 'FAIL  ') + name + (detail ? '\n        ' + detail : ''));
    if (!ok) failures++;
  };

  if (SCENARIO === 'stats-timeout') {
    const msgs = await send('/biglietti', 4000);
    const text = msgs.filter(m => m.includes('BIGLIETTI')).join('\n');
    console.log('--- /biglietti (stats endpoint down) ---\n' + text + '\n--- end ---');
    check('/biglietti still replies', text.length > 0);
    check('does NOT report sold=0 as if it were real', !/sold=0\b/.test(text) && !/Totale sold: 0/.test(text),
          'zeros were presented as real data');
    check('says sales data is unavailable', /non disponibil/i.test(text));
    check('surfaces the underlying error', /Timeout/.test(text));
    check('still shows capacities', /cap=40/.test(text) && /cap=25/.test(text));
    console.log('\n' + (failures ? failures + ' FAILURE(S)' : 'ALL CHECKS PASSED'));
    process.exit(failures ? 1 : 0);
  }

  const biglietti = await send('/biglietti');
  console.log('--- /biglietti messages ---\n' + biglietti.join('\n===\n') + '\n--- end ---');
  check('/biglietti replies', biglietti.length > 0, 'got ' + biglietti.length + ' message(s)');
  const body = biglietti.join('\n');
  check('/biglietti shows sold counts', /sold=10/.test(body) && /sold=5/.test(body), body.slice(0, 300));
  check('/biglietti shows prices (TDZ bug fixed)', /€13\.82\/cad/.test(body), body.slice(0, 300));
  check('/biglietti shows remaining', /remaining=/.test(body), body.slice(0, 300));

  const statsBefore = statsCallCount;
  await send('/biglietti');
  check('warm /biglietti makes no extra stats call', statsCallCount === statsBefore,
        'stats calls: ' + statsBefore + ' -> ' + statsCallCount);

  const raw = await send('/debugweeztix_raw');
  check('/debugweeztix_raw now reachable', /WEEZTIX RAW/.test(raw.join('\n')), raw.join('\n').slice(0, 120));

  const trend = await send('/trend');
  check('/trend replies', trend.length > 0 && /TREND|serve qualche minuto/.test(trend.join('\n')),
        trend.join('\n').slice(0, 160));

  check('stats snapshot persisted to Redis', typeof redis['weeztix_stats_snapshot'] === 'string',
        Object.keys(redis).join(', '));
  check('access token cached to Redis', typeof redis['weeztix_access_token'] === 'string',
        Object.keys(redis).join(', '));

  const tokenCalls = calls.filter(u => u.includes('auth.weeztix.com/tokens')).length;
  check('OAuth token fetched once, not per call', tokenCalls === 1, 'token calls: ' + tokenCalls);

  console.log('\n' + (failures ? failures + ' FAILURE(S)' : 'ALL CHECKS PASSED'));
  process.exit(failures ? 1 : 0);
})();
