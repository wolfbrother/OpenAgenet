# Copyright (c) 2026 China Academy of Information and Communications Technology (CAICT)
#
# Author: JINLIANG XU
# Email: xujinliang@caict.ac.cn; jlxufly@gmail.com
#

. "$PSScriptRoot\common.ps1"

try {
    Initialize-ResearchExperiment | Out-Null
    $domainA = "gbt4754-2017.01"
    $domainB = "gbt4754-2017.02"
    Set-DiscoveryDomains @($domainA)
    $dataset = New-ResearchDataset -Count 6 -Tags @($domainA, $domainB)

    $registrationLatencies = @()
    foreach ($agent in $dataset.agents) {
        $measurement = Measure-Action { Register-ResearchAgent -Agent $agent -DraftPrefix "auth" }
        $registrationLatencies += $measurement.elapsedMs
    }
    $propagation = Publish-And-Sync

    $queryA = Measure-Action {
        Invoke-JsonPost "$($script:DiscoveryBaseUrl)/discover/query" @{
            capabilityTags = @($domainA)
            serviceType = "AgentService"
            protocol = "http"
            limit = 20
        }
    }
    $queryB = Measure-Action {
        Invoke-JsonPost "$($script:DiscoveryBaseUrl)/discover/query" @{
            capabilityTags = @($domainB)
            serviceType = "AgentService"
            protocol = "http"
            limit = 20
        }
    }

    $countA = @($queryA.value.candidates).Count
    $countB = @($queryB.value.candidates).Count
    if ($countA -lt 1) {
        throw "Authorized domain query returned no candidates."
    }

    $expectedA = @($dataset.agents | Where-Object { $_.capabilityTags -contains $domainA }).Count
    $expectedB = 0
    $accuracy = if (($countA -eq $expectedA) -and ($countB -eq $expectedB)) { 1.0 } else { 0.0 }

    $result = [pscustomobject]@{
        experiment = "authorization-aware-discovery"
        status = "ok"
        authorizedDomains = @($domainA)
        datasetCount = $dataset.count
        expectedAuthorizedCandidates = $expectedA
        observedAuthorizedCandidates = $countA
        expectedUnauthorizedCandidates = $expectedB
        observedUnauthorizedCandidates = $countB
        policyEnforcementAccuracy = $accuracy
        registrationLatencyMs = $registrationLatencies
        publishLatencyMs = $propagation.publish.elapsedMs
        notifyLatencyMs = $propagation.notify.elapsedMs
        syncLatencyMs = $propagation.sync.elapsedMs
        authorizedQueryLatencyMs = $queryA.elapsedMs
        unauthorizedQueryLatencyMs = $queryB.elapsedMs
    }
    $path = Write-ResultJson "auth-discovery-result.json" $result
    $result | ConvertTo-Json -Depth 30
    Write-Host "Saved $path"
} finally {
    Stop-ResearchStack
}
