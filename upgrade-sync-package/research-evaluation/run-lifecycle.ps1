# Copyright (c) 2026 China Academy of Information and Communications Technology (CAICT)
#
# Author: JINLIANG XU
# Email: xujinliang@caict.ac.cn; jlxufly@gmail.com
#

. "$PSScriptRoot\common.ps1"

try {
    Initialize-ResearchExperiment | Out-Null
    Set-DiscoveryDomains @("*")
    $dataset = New-ResearchDataset -Count 1 -Tags @("gbt4754-2017.01")
    $agent = $dataset.agents[0]

    $registration = Measure-Action { Register-ResearchAgent -Agent $agent -DraftPrefix "lifecycle" }
    $propagation = Publish-And-Sync
    $query = Measure-Action {
        Invoke-JsonPost "$($script:DiscoveryBaseUrl)/discover/query" @{
            capabilityTags = @("gbt4754-2017.01")
            serviceType = "AgentService"
            protocol = "http"
            limit = 5
        }
    }

    $candidateCount = @($query.value.candidates).Count
    if ($candidateCount -lt 1) {
        throw "Lifecycle query returned no candidates."
    }

    $result = [pscustomobject]@{
        experiment = "lifecycle-correctness"
        status = "ok"
        registeredDid = $agent.did
        registrationLatencyMs = $registration.elapsedMs
        publishLatencyMs = $propagation.publish.elapsedMs
        notifyLatencyMs = $propagation.notify.elapsedMs
        syncLatencyMs = $propagation.sync.elapsedMs
        queryLatencyMs = $query.elapsedMs
        propagationTimeMs = [Math]::Round($propagation.publish.elapsedMs + $propagation.notify.elapsedMs + $propagation.sync.elapsedMs, 3)
        candidateCount = $candidateCount
        storageBytes = Get-StorageBytes
    }
    $path = Write-ResultJson "lifecycle-result.json" $result
    $result | ConvertTo-Json -Depth 20
    Write-Host "Saved $path"
} finally {
    Stop-ResearchStack
}
