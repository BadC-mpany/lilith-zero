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

export function handleSummary(data) {
  const metrics = data.metrics;
  
  const getMetric = (metricName) => {
    if (metrics[metricName] && metrics[metricName].values) {
      const v = metrics[metricName].values;
      return {
        avg: v.avg || 0.0,
        min: v.min || 0.0,
        med: v.med || v['p(50)'] || 0.0,
        max: v.max || 0.0,
        p90: v['p(90)'] || 0.0,
        p95: v['p(95)'] || 0.0
      };
    }
    return { avg: 0.0, min: 0.0, med: 0.0, max: 0.0, p90: 0.0, p95: 0.0 };
  };

  const httpReqs = metrics.http_reqs ? metrics.http_reqs.values : { count: 0, rate: 0 };
  const errors = metrics.errors ? metrics.errors.values : { rate: 0.0 };
  
  const httpDuration = getMetric('http_req_duration');
  const lockAcquire = getMetric('lilith_lock_acquire_ms');
  const stateLoad = getMetric('lilith_state_load_ms');
  const coreEval = getMetric('lilith_eval_ms');
  const stateSave = getMetric('lilith_state_save_ms');
  const serverTime = getMetric('lilith_server_time_ms');
  
  const report_json = {
    summary: {
      total_requests: httpReqs.count,
      throughput_req_sec: httpReqs.rate,
      error_rate_pct: errors.rate * 100.0,
      duration_sec: data.state && data.state.testRunDurationMs ? (data.state.testRunDurationMs / 1000.0) : 0.0,
      status: errors.rate === 0 ? "PASS" : "FAIL"
    },
    metrics: {
      http_req_duration: httpDuration,
      lock_acquire: lockAcquire,
      state_load: stateLoad,
      core_eval: coreEval,
      state_save: stateSave,
      server_time: serverTime
    }
  };

  const md = `# Lilith Zero: Webhook Load Test Report

## Execution Summary
- **Total Requests**: ${httpReqs.count}
- **Throughput**: ${httpReqs.rate.toFixed(2)} req/s
- **Error Rate**: ${(errors.rate * 100.0).toFixed(2)}%
- **Status**: ${errors.rate === 0 ? '✓ PASS' : '✗ FAIL'}

## Latency Metrics Breakdown (ms)

### Client Round-Trip Latency
| Metric | Avg (ms) | Min (ms) | Med (ms) | Max (ms) | P(90) (ms) | P(95) (ms) |
|---|---|---|---|---|---|---|
| HTTP Request Duration | ${httpDuration.avg.toFixed(2)} | ${httpDuration.min.toFixed(2)} | ${httpDuration.med.toFixed(2)} | ${httpDuration.max.toFixed(2)} | ${httpDuration.p90.toFixed(2)} | ${httpDuration.p95.toFixed(2)} |

### Server-Side Latency Breakdown
| Phase | Avg (ms) | Med (ms) | P(95) (ms) | Max (ms) |
|---|---|---|---|---|
| Session Lock Acquire | ${lockAcquire.avg.toFixed(2)} | ${lockAcquire.med.toFixed(2)} | ${lockAcquire.p95.toFixed(2)} | ${lockAcquire.max.toFixed(2)} |
| Session State Load | ${stateLoad.avg.toFixed(2)} | ${stateLoad.med.toFixed(2)} | ${stateLoad.p95.toFixed(2)} | ${stateLoad.max.toFixed(2)} |
| Security Policy Eval | ${coreEval.avg.toFixed(2)} | ${coreEval.med.toFixed(2)} | ${coreEval.p95.toFixed(2)} | ${coreEval.max.toFixed(2)} |
| Session State Save | ${stateSave.avg.toFixed(2)} | ${stateSave.med.toFixed(2)} | ${stateSave.p95.toFixed(2)} | ${stateSave.max.toFixed(2)} |
| Total Server Time | ${serverTime.avg.toFixed(2)} | ${serverTime.med.toFixed(2)} | ${serverTime.p95.toFixed(2)} | ${serverTime.max.toFixed(2)} |
`;

  let consoleSummary = `
================================================================================
LILITH ZERO WEBHOOK LOAD TEST RESULTS
================================================================================
Total Requests:   ${httpReqs.count} (${httpReqs.rate.toFixed(2)} req/s)
Error Rate:       ${(errors.rate * 100.0).toFixed(2)}%
Client Duration:  Avg=${httpDuration.avg.toFixed(2)}ms, Med=${httpDuration.med.toFixed(2)}ms, P(95)=${httpDuration.p95.toFixed(2)}ms
Server Eval:      Avg=${coreEval.avg.toFixed(2)}ms, Med=${coreEval.med.toFixed(2)}ms, P(95)=${coreEval.p95.toFixed(2)}ms
--------------------------------------------------------------------------------
Summary: ${errors.rate === 0 ? '\033[32mPASS\033[0m' : '\033[31mFAIL\033[0m'} (${httpReqs.count} requests completed)
================================================================================
`;

  return {
    'stdout': consoleSummary,
    'results/webhook_load_test_report.json': JSON.stringify(report_json, null, 2),
    'results/webhook_load_test_report.md': md,
  };
}
