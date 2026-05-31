# Single Node End-to-End Benchmark

- startedAt: 2026-05-31T07:30:07.566Z
- finishedAt: 2026-05-31T07:45:59.873Z

## Scales
- scale=500, concurrency=24, totalWallMs=54132.22, registrationThroughput=17.43/s, endToEndThroughput=9.24/s, missing=0
  - rootAccept: registrar.createDraft:avg=40.72ms,p95=131.33ms | registrar.validateDraft:avg=27.57ms,p95=74.40ms | registrar.controlChallenge:avg=38.83ms,p95=120.58ms | registrar.proveControl:avg=90.46ms,p95=211.92ms | registrar.issueCredential:avg=42.94ms,p95=133.15ms | registrar.submitToRoot:avg=1103.17ms,p95=3537.45ms
  - cdnPublish: root.publishCdnBatch:avg=1145.08ms,p95=1607.31ms
  - discoverySync: root.notifyDiscoveryBatch:avg=2997.42ms,p95=2997.42ms | discovery.sync:avg=8524.86ms,p95=8524.86ms | discovery.query:avg=444.18ms,p95=444.18ms
- scale=1000, concurrency=16, totalWallMs=186348.53, registrationThroughput=8.14/s, endToEndThroughput=5.37/s, missing=0
  - rootAccept: registrar.createDraft:avg=44.45ms,p95=139.18ms | registrar.validateDraft:avg=35.27ms,p95=122.31ms | registrar.controlChallenge:avg=46.58ms,p95=143.63ms | registrar.proveControl:avg=111.35ms,p95=286.18ms | registrar.issueCredential:avg=52.19ms,p95=169.63ms | registrar.submitToRoot:avg=1667.03ms,p95=3695.32ms
  - cdnPublish: root.publishCdnBatch:avg=2009.55ms,p95=2448.80ms
  - discoverySync: root.notifyDiscoveryBatch:avg=2521.02ms,p95=2521.02ms | discovery.sync:avg=7180.58ms,p95=7841.37ms | discovery.query:avg=575.35ms,p95=575.35ms
- scale=2000, concurrency=16, totalWallMs=660407.21, registrationThroughput=6.40/s, endToEndThroughput=3.03/s, missing=0
  - rootAccept: registrar.createDraft:avg=23.88ms,p95=71.13ms | registrar.validateDraft:avg=16.46ms,p95=51.20ms | registrar.controlChallenge:avg=25.86ms,p95=76.48ms | registrar.proveControl:avg=71.93ms,p95=193.73ms | registrar.issueCredential:avg=30.00ms,p95=86.76ms | registrar.submitToRoot:avg=2320.79ms,p95=4972.79ms
  - cdnPublish: root.publishCdnBatch:avg=2247.98ms,p95=6010.91ms
  - discoverySync: root.notifyDiscoveryBatch:avg=1419.78ms,p95=10098.64ms | discovery.sync:avg=34441.93ms,p95=45412.38ms | discovery.query:avg=10170.67ms,p95=10170.67ms

## Observations
- runtime={"hostname":"JINLIANGPC","platform":"win32","node":"v24.15.0"}
- adminToken=local-dev-admin-token
- single-node scale=500 registrationThroughput=17.43/s endToEndThroughput=9.24/s
- single-node scale=1000 registrationThroughput=8.14/s endToEndThroughput=5.37/s
- single-node scale=2000 registrationThroughput=6.40/s endToEndThroughput=3.03/s
