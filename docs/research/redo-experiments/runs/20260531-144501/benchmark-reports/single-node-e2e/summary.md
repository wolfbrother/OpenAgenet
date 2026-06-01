# Single Node End-to-End Benchmark

- startedAt: 2026-05-31T07:02:55.748Z
- finishedAt: 2026-05-31T07:04:47.105Z

## Scales
- scale=10, concurrency=10, totalWallMs=3962.44, registrationThroughput=4.89/s, endToEndThroughput=2.52/s, missing=0
  - rootAccept: registrar.createDraft:avg=82.54ms,p95=133.22ms | registrar.validateDraft:avg=37.31ms,p95=88.86ms | registrar.controlChallenge:avg=53.11ms,p95=81.97ms | registrar.proveControl:avg=71.15ms,p95=90.76ms | registrar.issueCredential:avg=46.99ms,p95=68.53ms | registrar.submitToRoot:avg=1169.37ms,p95=1668.64ms
  - cdnPublish: root.publishCdnBatch:avg=483.99ms,p95=483.99ms
  - discoverySync: root.notifyDiscoveryBatch:avg=1258.04ms,p95=1258.04ms | discovery.sync:avg=90.00ms,p95=90.00ms | discovery.query:avg=7.72ms,p95=7.72ms
- scale=50, concurrency=16, totalWallMs=4460.27, registrationThroughput=25.38/s, endToEndThroughput=11.21/s, missing=0
  - rootAccept: registrar.createDraft:avg=39.46ms,p95=123.69ms | registrar.validateDraft:avg=14.87ms,p95=29.56ms | registrar.controlChallenge:avg=20.45ms,p95=41.87ms | registrar.proveControl:avg=53.79ms,p95=99.89ms | registrar.issueCredential:avg=29.43ms,p95=77.09ms | registrar.submitToRoot:avg=380.58ms,p95=1086.44ms
  - cdnPublish: root.publishCdnBatch:avg=777.91ms,p95=777.91ms
  - discoverySync: root.notifyDiscoveryBatch:avg=1392.67ms,p95=1392.67ms | discovery.sync:avg=125.47ms,p95=125.47ms | discovery.query:avg=32.79ms,p95=32.79ms
- scale=100, concurrency=16, totalWallMs=8455.36, registrationThroughput=25.21/s, endToEndThroughput=11.83/s, missing=0
  - rootAccept: registrar.createDraft:avg=33.70ms,p95=113.88ms | registrar.validateDraft:avg=18.35ms,p95=52.04ms | registrar.controlChallenge:avg=26.46ms,p95=51.66ms | registrar.proveControl:avg=61.14ms,p95=130.12ms | registrar.issueCredential:avg=32.77ms,p95=74.46ms | registrar.submitToRoot:avg=423.37ms,p95=689.16ms
  - cdnPublish: root.publishCdnBatch:avg=883.38ms,p95=893.76ms
  - discoverySync: root.notifyDiscoveryBatch:avg=2039.31ms,p95=2039.31ms | discovery.sync:avg=154.45ms,p95=154.45ms | discovery.query:avg=86.60ms,p95=86.60ms
- scale=200, concurrency=32, totalWallMs=28876.27, registrationThroughput=15.90/s, endToEndThroughput=6.93/s, missing=0
  - rootAccept: registrar.createDraft:avg=56.11ms,p95=191.79ms | registrar.validateDraft:avg=60.65ms,p95=304.62ms | registrar.controlChallenge:avg=69.83ms,p95=228.92ms | registrar.proveControl:avg=115.64ms,p95=284.30ms | registrar.issueCredential:avg=69.28ms,p95=241.13ms | registrar.submitToRoot:avg=1482.78ms,p95=5145.12ms
  - cdnPublish: root.publishCdnBatch:avg=1910.95ms,p95=2350.84ms
  - discoverySync: root.notifyDiscoveryBatch:avg=3630.84ms,p95=3630.84ms | discovery.sync:avg=3390.29ms,p95=3390.29ms | discovery.query:avg=429.05ms,p95=429.05ms

## Observations
- runtime={"hostname":"JINLIANGPC","platform":"win32","node":"v24.15.0"}
- adminToken=local-dev-admin-token
- single-node scale=10 registrationThroughput=4.89/s endToEndThroughput=2.52/s
- single-node scale=50 registrationThroughput=25.38/s endToEndThroughput=11.21/s
- single-node scale=100 registrationThroughput=25.21/s endToEndThroughput=11.83/s
- single-node scale=200 registrationThroughput=15.90/s endToEndThroughput=6.93/s
