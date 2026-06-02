import http from 'k6/http';
import { check, sleep } from 'k6';
import { Trend, Rate } from 'k6/metrics';

// Custom trends to capture timing breakdowns from the server headers
const lockAcquireTrend = new Trend('lilith_lock_acquire_ms');
const stateLoadTrend = new Trend('lilith_state_load_ms');
const coreEvalTrend = new Trend('lilith_eval_ms');
const stateSaveTrend = new Trend('lilith_state_save_ms');
const serverTimeTrend = new Trend('lilith_server_time_ms');
const roundTripTrend = new Trend('round_trip_latency_ms');

const errorRate = new Rate('errors');

// Load shared JSON payloads
const allowedBase = JSON.parse(open('../shared_payloads/webhook_allowed.json'));
const deniedBase = JSON.parse(open('../shared_payloads/webhook_denied.json'));

export const options = {
  vus: __ENV.LILITH_VUS ? parseInt(__ENV.LILITH_VUS) : 10,
  duration: __ENV.LILITH_DURATION || '10s',
};

export default function () {
  const url = __ENV.LILITH_URL || 'http://localhost:8080/analyze-tool-execution';
  const agentId = __ENV.LILITH_AGENT_ID || 'test-agent';
  const bearerToken = __ENV.LILITH_BEARER_TOKEN || '';
  const useRandomConv = __ENV.LILITH_RANDOM_CONV === 'true' || __ENV.LILITH_RANDOM_CONV === '1';

  // Generate conversation ID (determines lock contention behavior)
  const convId = useRandomConv
    ? `conv-${Math.random().toString(36).substring(2, 15)}`
    : 'static-load-test-session';

  // Interleave allowed and denied tool request payloads
  const isAllowedRequest = Math.random() < 0.5;
  const payload = isAllowedRequest
    ? JSON.parse(JSON.stringify(allowedBase))
    : JSON.parse(JSON.stringify(deniedBase));

  payload.conversationMetadata.conversationId = convId;
  payload.conversationMetadata.agent.id = agentId;

  const headers = {
    'Content-Type': 'application/json',
  };
  if (bearerToken) {
    headers['Authorization'] = `Bearer ${bearerToken}`;
  }

  const start = Date.now();
  const res = http.post(url, JSON.stringify(payload), { headers });
  const roundTrip = Date.now() - start;

  roundTripTrend.add(roundTrip);

  const isOk = check(res, {
    'status is 200': (r) => r.status === 200,
  });

  if (!isOk) {
    errorRate.add(1);
    return;
  }

  errorRate.add(0);

  // Extract custom headers containing server-side latency breakdown
  const lockAcquire = res.headers['X-Lilith-Lock-Acquire-Ms'] || res.headers['x-lilith-lock-acquire-ms'];
  const stateLoad = res.headers['X-Lilith-State-Load-Ms'] || res.headers['x-lilith-state-load-ms'];
  const coreEval = res.headers['X-Lilith-Eval-Ms'] || res.headers['x-lilith-eval-ms'];
  const stateSave = res.headers['X-Lilith-State-Save-Ms'] || res.headers['x-lilith-state-save-ms'];
  const serverTime = res.headers['X-Lilith-Server-Time-Ms'] || res.headers['x-lilith-server-time-ms'];

  if (lockAcquire) lockAcquireTrend.add(parseFloat(lockAcquire));
  if (stateLoad) stateLoadTrend.add(parseFloat(stateLoad));
  if (coreEval) coreEvalTrend.add(parseFloat(coreEval));
  if (stateSave) stateSaveTrend.add(parseFloat(stateSave));
  if (serverTime) serverTimeTrend.add(parseFloat(serverTime));

  // Small pacing interval
  sleep(0.01);
}
