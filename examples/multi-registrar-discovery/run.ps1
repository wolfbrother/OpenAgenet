# Copyright (c) 2026 China Academy of Information and Communications Technology (CAICT)
#
# Author: JINLIANG XU
# Email: xujinliang@caict.ac.cn; jlxufly@gmail.com
#

$ErrorActionPreference = "Stop"

$exampleDir = $PSScriptRoot
$repoRoot = Split-Path -Parent (Split-Path -Parent $exampleDir)
$pidDir = Join-Path $repoRoot ".oan-multi-node-demo-pids"
New-Item -ItemType Directory -Force -Path $pidDir | Out-Null

$script:startedPids = @()

function Get-ListenerProcessId {
    param([int]$Port)
    try {
        $listener = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction Stop | Select-Object -First 1
        return $listener.OwningProcess
    } catch {
        return $null
    }
}

function Start-Node {
    param(
        [string]$Name,
        [string]$Package,
        [string]$ConfigPath,
        [int]$Port
    )

    $listener = Get-ListenerProcessId -Port $Port
    if ($listener) {
        Stop-Process -Id $listener -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 500
    }

    $stdoutPath = Join-Path $pidDir "$Name.out.log"
    $stderrPath = Join-Path $pidDir "$Name.err.log"
    $process = Start-Process `
        -FilePath "cargo" `
        -ArgumentList @("run", "-p", $Package, "--", $ConfigPath) `
        -WorkingDirectory $repoRoot `
        -NoNewWindow `
        -PassThru `
        -RedirectStandardOutput $stdoutPath `
        -RedirectStandardError $stderrPath
    Set-Content -Path (Join-Path $pidDir "$Name.pid") -Value $process.Id
    $script:startedPids += $process.Id
    Write-Host "Started $Name as PID $($process.Id)"
}

function Wait-Health {
    param([string]$Name, [int]$Port)
    $url = "http://127.0.0.1:$Port/health"
    for ($i = 0; $i -lt 60; $i++) {
        try {
            Invoke-RestMethod -Uri $url -TimeoutSec 1 | Out-Null
            Write-Host "$Name is ready"
            return
        } catch {
            Start-Sleep -Milliseconds 500
        }
    }
    throw "$Name did not become ready at $url"
}

function Invoke-JsonPost {
    param([string]$Uri, [object]$Body)
    Invoke-RestMethod `
        -Method Post `
        -Uri $Uri `
        -ContentType "application/json" `
        -Body ($Body | ConvertTo-Json -Depth 100)
}

function Stop-StartedNodes {
    foreach ($processId in $script:startedPids) {
        try {
            Stop-Process -Id $processId -Force -ErrorAction SilentlyContinue
        } catch {
        }
    }
}

function Assert-Equal {
    param([string]$Name, [object]$Actual, [object]$Expected)
    if ($Actual -ne $Expected) {
        throw "$Name mismatch. Expected '$Expected', got '$Actual'."
    }
}

try {
    & node .\scripts\generate-multi-node-demo.mjs

    Start-Node "root-a" "root-node" ".oan-multi-node-demo/root/config.example.toml" 8100
    Start-Node "registrar-a" "registrar-node" ".oan-multi-node-demo/registrar-a/config.example.toml" 8101
    Start-Node "registrar-b" "registrar-node" ".oan-multi-node-demo/registrar-b/config.example.toml" 8102
    Start-Node "discovery-a" "discovery-node" ".oan-multi-node-demo/discovery-a/config.example.toml" 8103
    Start-Node "discovery-b" "discovery-node" ".oan-multi-node-demo/discovery-b/config.example.toml" 8104
    Start-Node "cdn-a" "cdn-node" ".oan-multi-node-demo/cdn/config.example.toml" 8105

    Wait-Health "root-a" 8100
    Wait-Health "registrar-a" 8101
    Wait-Health "registrar-b" 8102
    Wait-Health "discovery-a" 8103
    Wait-Health "discovery-b" 8104
    Wait-Health "cdn-a" 8105

    $registrarADidDocument = Get-Content (Join-Path $repoRoot ".oan-multi-node-demo/registrar-a/did-document.json") -Raw | ConvertFrom-Json
    $registrarBDidDocument = Get-Content (Join-Path $repoRoot ".oan-multi-node-demo/registrar-b/did-document.json") -Raw | ConvertFrom-Json
    $discoveryADidDocument = Get-Content (Join-Path $repoRoot ".oan-multi-node-demo/discovery-a/did-document.json") -Raw | ConvertFrom-Json
    $discoveryBDidDocument = Get-Content (Join-Path $repoRoot ".oan-multi-node-demo/discovery-b/did-document.json") -Raw | ConvertFrom-Json
    $serviceDidDocument = Get-Content (Join-Path $repoRoot "data/demo-service-agent/did-document.json") -Raw | ConvertFrom-Json
    $serviceDidDocument.ansMetadata.agentDescription.capabilityTags = @("gbt4754-2017.01")

    Invoke-JsonPost "http://127.0.0.1:8100/root/registrars/authorize" @{
        targetDid = $registrarADidDocument.id
        targetRole = "registrar"
        didDocument = $registrarADidDocument
    } | Out-Null
    Invoke-JsonPost "http://127.0.0.1:8100/root/registrars/authorize" @{
        targetDid = $registrarBDidDocument.id
        targetRole = "registrar"
        didDocument = $registrarBDidDocument
    } | Out-Null
    Invoke-JsonPost "http://127.0.0.1:8100/root/discovery-nodes/authorize" @{
        targetDid = $discoveryADidDocument.id
        targetRole = "discovery"
        didDocument = $discoveryADidDocument
    } | Out-Null
    Invoke-JsonPost "http://127.0.0.1:8100/root/discovery-nodes/authorize" @{
        targetDid = $discoveryBDidDocument.id
        targetRole = "discovery"
        didDocument = $discoveryBDidDocument
    } | Out-Null
    Invoke-JsonPost "http://127.0.0.1:8100/root/discovery-nodes/$($discoveryADidDocument.id)/domains" @{
        authorizedDomains = @("*")
        tagTreeVersion = 1
    } | Out-Null
    Invoke-JsonPost "http://127.0.0.1:8100/root/discovery-nodes/$($discoveryBDidDocument.id)/domains" @{
        authorizedDomains = @("*")
        tagTreeVersion = 1
    } | Out-Null

    $rootStatus = Invoke-RestMethod -Uri "http://127.0.0.1:8100/api/v1/root/status"
    Assert-Equal "registrar authorization count" $rootStatus.registrarAuthorizationCount 2
    Assert-Equal "discovery authorization count" $rootStatus.discoveryAuthorizationCount 2

    Invoke-JsonPost "http://127.0.0.1:8101/api/v1/agents/draft" @{
        draftId = "multi-node-service"
        agentDid = $serviceDidDocument.id
        didDocument = $serviceDidDocument
        metadata = @{
            source = "examples/multi-registrar-discovery/run.ps1"
            demo = "multi-registrar-discovery"
            capabilityTags = @("gbt4754-2017.01")
        }
    } | Out-Null
    Invoke-JsonPost "http://127.0.0.1:8101/api/v1/agents/draft/multi-node-service/issue-registration-credential" @{} | Out-Null
    Invoke-JsonPost "http://127.0.0.1:8101/api/v1/agents/draft/multi-node-service/submit" @{} | Out-Null

    $cdnBatch = Invoke-JsonPost "http://127.0.0.1:8100/root/batches/publish-cdn" @{}
    Assert-Equal "cdn published count" $cdnBatch.publishedCount 1
    $discoveryBatch = Invoke-JsonPost "http://127.0.0.1:8100/root/batches/notify-discovery" @{}
    Assert-Equal "discovery target batch count" $discoveryBatch.targetBatchCount 2

    $syncA = Invoke-JsonPost "http://127.0.0.1:8103/discovery/sync" @{}
    $syncB = Invoke-JsonPost "http://127.0.0.1:8104/discovery/sync" @{}
    Assert-Equal "discovery A synced count" $syncA.syncedCount 1
    Assert-Equal "discovery B synced count" $syncB.syncedCount 1

    $queryBody = @{
        capabilityTags = @("gbt4754-2017.01")
        serviceType = "AgentService"
        protocol = "http"
        limit = 5
    }
    $queryA = Invoke-JsonPost "http://127.0.0.1:8103/discover/query" $queryBody
    $queryB = Invoke-JsonPost "http://127.0.0.1:8104/discover/query" $queryBody
    if (-not $queryA.candidates -or $queryA.candidates.Count -lt 1) {
        throw "Discovery A did not return a candidate."
    }
    if (-not $queryB.candidates -or $queryB.candidates.Count -lt 1) {
        throw "Discovery B did not return a candidate."
    }

    @{
        status = "ok"
        example = "multi-registrar-discovery"
        registrarCount = $rootStatus.registrarAuthorizationCount
        discoveryCount = $rootStatus.discoveryAuthorizationCount
        discoveryBatchTargets = $discoveryBatch.targetBatchCount
        discoveryASynced = $syncA.syncedCount
        discoveryBSynced = $syncB.syncedCount
        discoveryACandidates = $queryA.candidates.Count
        discoveryBCandidates = $queryB.candidates.Count
    } | ConvertTo-Json -Depth 20
}
finally {
    Stop-StartedNodes
}
