# Copyright (c) 2026 China Academy of Information and Communications Technology (CAICT)
#
# Author: JINLIANG XU
# Email: xujinliang@caict.ac.cn; jlxufly@gmail.com
#

$ErrorActionPreference = "Stop"

& powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "run-lifecycle.ps1")
& powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "run-negative.ps1")
& powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "run-auth-discovery.ps1")
& powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "run-scalability.ps1") -Scales 10,50

