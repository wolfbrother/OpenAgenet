# Multi Node End-to-End Benchmark

- startedAt: 2026-05-31T07:52:03.723Z
- finishedAt: 2026-05-31T08:00:13.651Z

## Scales
- scale=200, concurrency=36, totalWallMs=110428.29, registrationThroughput=19.43/s, endToEndThroughput=5.43/s, missing=0
  - rootAccept: registrar.createDraft.8101:avg=44.45ms,p95=162.87ms | registrar.validateDraft.8101:avg=34.26ms,p95=142.09ms | registrar.controlChallenge.8101:avg=46.13ms,p95=181.82ms | registrar.proveControl.8101:avg=67.88ms,p95=134.77ms | registrar.issueCredential.8101:avg=36.14ms,p95=104.13ms | registrar.submitToRoot.8101:avg=1315.54ms,p95=4609.55ms | registrar.createDraft.8102:avg=26.87ms,p95=81.35ms | registrar.validateDraft.8102:avg=18.03ms,p95=46.21ms | registrar.controlChallenge.8102:avg=24.34ms,p95=58.77ms | registrar.proveControl.8102:avg=60.12ms,p95=121.36ms | registrar.issueCredential.8102:avg=31.99ms,p95=80.88ms | registrar.submitToRoot.8102:avg=1569.78ms,p95=5000.13ms | registrar.createDraft.8105:avg=25.70ms,p95=62.62ms | registrar.validateDraft.8105:avg=18.16ms,p95=49.74ms | registrar.controlChallenge.8105:avg=25.37ms,p95=62.52ms | registrar.proveControl.8105:avg=62.56ms,p95=119.82ms | registrar.issueCredential.8105:avg=28.57ms,p95=63.15ms | registrar.submitToRoot.8105:avg=1963.32ms,p95=5614.27ms
  - cdnPublish: root.publishCdnBatch:avg=2368.11ms,p95=4917.67ms
  - discoverySync: root.notifyDiscoveryBatch:avg=9093.81ms,p95=9093.81ms | discovery.sync.8103:avg=16836.82ms,p95=16836.82ms | discovery.sync.8104:avg=19196.34ms,p95=19196.34ms | discovery.query.8103:avg=712.47ms,p95=712.47ms | discovery.query.8104:avg=607.76ms,p95=607.76ms
- scale=400, concurrency=36, totalWallMs=342062.53, registrationThroughput=7.01/s, endToEndThroughput=3.51/s, missing=0
  - rootAccept: registrar.createDraft.8101:avg=87.30ms,p95=292.90ms | registrar.validateDraft.8101:avg=62.42ms,p95=263.65ms | registrar.controlChallenge.8101:avg=102.86ms,p95=451.68ms | registrar.proveControl.8101:avg=202.06ms,p95=646.91ms | registrar.issueCredential.8101:avg=128.91ms,p95=725.61ms | registrar.submitToRoot.8101:avg=5040.95ms,p95=12607.45ms | registrar.createDraft.8102:avg=45.97ms,p95=145.68ms | registrar.validateDraft.8102:avg=29.22ms,p95=73.91ms | registrar.controlChallenge.8102:avg=37.99ms,p95=98.80ms | registrar.proveControl.8102:avg=95.39ms,p95=266.50ms | registrar.issueCredential.8102:avg=40.98ms,p95=107.59ms | registrar.submitToRoot.8102:avg=4995.12ms,p95=12546.15ms | registrar.createDraft.8105:avg=19.96ms,p95=49.68ms | registrar.validateDraft.8105:avg=13.54ms,p95=34.14ms | registrar.controlChallenge.8105:avg=20.94ms,p95=57.42ms | registrar.proveControl.8105:avg=55.95ms,p95=112.63ms | registrar.issueCredential.8105:avg=24.51ms,p95=54.25ms | registrar.submitToRoot.8105:avg=4297.00ms,p95=17858.18ms
  - cdnPublish: root.publishCdnBatch:avg=3425.11ms,p95=5878.25ms
  - discoverySync: root.notifyDiscoveryBatch:avg=6563.61ms,p95=6563.61ms | discovery.sync.8103:avg=10303.17ms,p95=15214.06ms | discovery.sync.8104:avg=12202.84ms,p95=19617.77ms | discovery.query.8103:avg=1071.02ms,p95=1071.02ms | discovery.query.8104:avg=1077.28ms,p95=1077.28ms

## Observations
- runtime={"hostname":"JINLIANGPC","platform":"win32","node":"v24.15.0"}
- topology=1 root / 3 registrars / 2 discoveries / 1 cdn
- multi-node scale=200 registrationThroughput=19.43/s endToEndThroughput=5.43/s missing=0
- multi-node scale=400 registrationThroughput=7.01/s endToEndThroughput=3.51/s missing=0
