# Copyright (c) 2026 China Academy of Information and Communications Technology (CAICT)
#
# Author: JINLIANG XU
# Email: xujinliang@caict.ac.cn; jlxufly@gmail.com
#

param(
    [string[]]$Scales = @("100", "1000", "5000", "10000")
)

. "$PSScriptRoot\common.ps1"

function Percentile {
    param([double[]]$Values, [double]$P)
    if ($Values.Count -eq 0) { return 0 }
    $sorted = $Values | Sort-Object
    $index = [Math]::Min($sorted.Count - 1, [Math]::Ceiling(($P / 100.0) * $sorted.Count) - 1)
    return [Math]::Round([double]$sorted[$index], 3)
}

$parsedScales = @()
foreach ($scaleArg in $Scales) {
    foreach ($piece in ($scaleArg -split ",")) {
        $trimmed = $piece.Trim()
        if ($trimmed) {
            $parsedScales += [int]$trimmed
        }
    }
}

$allResults = @()
foreach ($scale in $parsedScales) {
    try {
        Initialize-ResearchExperiment | Out-Null
        Set-DiscoveryDomains @("*")
        $dataset = New-ResearchDataset -Count $scale -Tags @("gbt4754-2017.01", "gbt4754-2017.02", "gbt4754-2017.03")

        $latencies = @()
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        foreach ($agent in $dataset.agents) {
            $draftPrefix = "scale-$($scale)"
            $measurement = Measure-Action { Register-ResearchAgent -Agent $agent -DraftPrefix $draftPrefix }
            $latencies += $measurement.elapsedMs
        }
        $sw.Stop()

        $propagation = Publish-And-Sync
        $query = Measure-Action {
            Invoke-JsonPost "$($script:DiscoveryBaseUrl)/discover/query" @{
                capabilityTags = @("gbt4754-2017.01")
                serviceType = "AgentService"
                protocol = "http"
                limit = 50
            }
        }

        $accepted = $latencies.Count
        $throughput = if ($sw.Elapsed.TotalSeconds -gt 0) { [Math]::Round($accepted / $sw.Elapsed.TotalSeconds, 3) } else { 0 }
        $avg = if ($accepted -gt 0) { [Math]::Round(($latencies | Measure-Object -Average).Average, 3) } else { 0 }
        $result = [pscustomobject]@{
            experiment = "scalability-and-overhead"
            scale = $scale
            status = "ok"
            acceptedCount = $accepted
            registrationTotalMs = [Math]::Round($sw.Elapsed.TotalMilliseconds, 3)
            registrationThroughputPerSecond = $throughput
            registrationAvgLatencyMs = $avg
            registrationP95LatencyMs = Percentile -Values $latencies -P 95
            publishLatencyMs = $propagation.publish.elapsedMs
            notifyLatencyMs = $propagation.notify.elapsedMs
            syncLatencyMs = $propagation.sync.elapsedMs
            queryLatencyMs = $query.elapsedMs
            queryCandidateCount = @($query.value.candidates).Count
            storageBytes = Get-StorageBytes
        }
        $allResults += $result
    } finally {
        Stop-ResearchStack
    }
}

$jsonPath = Write-ResultJson "scalability-result.json" $allResults
$csvPath = Join-Path $script:ResultsDir "scalability-result.csv"
$allResults | Export-Csv -Path $csvPath -NoTypeInformation -Encoding utf8
$allResults | ConvertTo-Json -Depth 30
Write-Host "Saved $jsonPath"
Write-Host "Saved $csvPath"
