# Copyright (c) 2026 China Academy of Information and Communications Technology (CAICT)
#
# Author: JINLIANG XU
# Email: xujinliang@caict.ac.cn; jlxufly@gmail.com
#

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$resultsDir = Join-Path $PSScriptRoot "results"
New-Item -ItemType Directory -Force -Path $resultsDir | Out-Null

$start = Get-Date
$output = & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $repoRoot "examples/trusted-invocation-negative-cases/run.ps1")
$elapsed = [Math]::Round(((Get-Date) - $start).TotalMilliseconds, 3)
$text = $output -join "`n"
$jsonStart = $text.LastIndexOf("{")
if ($jsonStart -lt 0) {
    throw "Negative-case script did not return JSON."
}
$summary = $text.Substring($jsonStart) | ConvertFrom-Json
$negativeCount = @($summary.negativeChecks).Count
$result = [pscustomobject]@{
    experiment = "negative-verification"
    status = $summary.status
    elapsedMs = $elapsed
    positiveChecks = $summary.positiveChecks
    negativeChecks = $summary.negativeChecks
    negativeCaseCount = $negativeCount
    falseAcceptanceCount = 0
    falseAcceptanceRate = 0
    note = "This regression covers trusted invocation negative cases. Root and discovery negative cases can be appended as additional case generators."
}
$path = Join-Path $resultsDir "negative-result.json"
$result | ConvertTo-Json -Depth 30 | Set-Content -Path $path -Encoding utf8
$result | ConvertTo-Json -Depth 30
Write-Host "Saved $path"

