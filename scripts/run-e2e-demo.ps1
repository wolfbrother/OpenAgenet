# Copyright (c) 2026 China Academy of Information and Communications Technology (CAICT)
#
# Author: JINLIANG XU
# Email: xujinliang@caict.ac.cn; jlxufly@gmail.com
#

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$pidDir = Join-Path $repoRoot ".oan-demo-pids"
New-Item -ItemType Directory -Force -Path $pidDir | Out-Null

$script:startedPids = @()

function Start-Node {
    param(
        [string]$Name,
        [string]$Package,
        [string]$ConfigPath,
        [int]$Port
    )

    $healthUrl = "http://127.0.0.1:$Port/health"
    try {
        Invoke-RestMethod -Uri $healthUrl -TimeoutSec 1 | Out-Null
        Write-Host "$Name already listening on $healthUrl"
        return
    } catch {
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
        -Body ($Body | ConvertTo-Json -Depth 80)
}

function Assert-Equal {
    param([string]$Name, [object]$Actual, [object]$Expected)
    if ($Actual -ne $Expected) {
        throw "$Name mismatch. Expected '$Expected', got '$Actual'."
    }
}

function Assert-Contains {
    param([string]$Name, [object[]]$Actual, [string]$Expected)
    if ($Actual -notcontains $Expected) {
        throw "$Name does not contain '$Expected'."
    }
}

function Get-JsonFromCommandOutput {
    param([string]$Output)
    $start = $Output.IndexOf("{")
    if ($start -lt 0) {
        throw "Command output does not contain a JSON object."
    }
    return $Output.Substring($start) | ConvertFrom-Json
}

function Stop-StartedNodes {
    foreach ($processId in $script:startedPids) {
        try {
            Stop-Process -Id $processId -Force -ErrorAction SilentlyContinue
        } catch {
        }
    }
}

try {

Start-Node "root-node" "root-node" "services/root-node/config.example.toml" 8000
Start-Node "registrar-node" "registrar-node" "services/registrar-node/config.example.toml" 8001
Start-Node "discovery-node" "discovery-node" "services/discovery-node/config.example.toml" 8002
Start-Node "cdn-node" "cdn-node" "services/cdn-node/config.example.toml" 8003

$serviceAgentHealth = "http://127.0.0.1:9001/health"
try {
    Invoke-RestMethod -Uri $serviceAgentHealth -TimeoutSec 1 | Out-Null
    Write-Host "service-agent-python already listening on $serviceAgentHealth"
} catch {
    $serviceAgentOut = Join-Path $pidDir "service-agent-python.out.log"
    $serviceAgentErr = Join-Path $pidDir "service-agent-python.err.log"
    $serviceAgent = Start-Process `
        -FilePath "uv" `
        -ArgumentList @("run", "--project", "agents/service-agent-python", "openagentnet-service-agent") `
        -WorkingDirectory $repoRoot `
        -NoNewWindow `
        -PassThru `
        -RedirectStandardOutput $serviceAgentOut `
        -RedirectStandardError $serviceAgentErr
    Set-Content -Path (Join-Path $pidDir "service-agent-python.pid") -Value $serviceAgent.Id
    $script:startedPids += $serviceAgent.Id
    Write-Host "Started service-agent-python as PID $($serviceAgent.Id)"
}

Wait-Health "root-node" 8000
Wait-Health "registrar-node" 8001
Wait-Health "discovery-node" 8002
Wait-Health "cdn-node" 8003
Wait-Health "service-agent-python" 9001

$serviceDidDocument = Get-Content (Join-Path $repoRoot "data/demo-service-agent/did-document.json") -Raw | ConvertFrom-Json
$registrarDidDocument = Get-Content (Join-Path $repoRoot "data/registrar/did-document.json") -Raw | ConvertFrom-Json
$discoveryDidDocument = Get-Content (Join-Path $repoRoot "data/discovery/did-document.json") -Raw | ConvertFrom-Json
$demoCapabilityTags = @("gbt4754-2017.01")

$serviceDidDocument.ansMetadata.agentDescription.capabilityTags = $demoCapabilityTags

Invoke-JsonPost "http://127.0.0.1:8000/root/registrars/authorize" @{
    targetDid = $registrarDidDocument.id
    targetRole = "registrar"
    didDocument = $registrarDidDocument
} | Out-Null

Invoke-JsonPost "http://127.0.0.1:8000/root/discovery-nodes/authorize" @{
    targetDid = $discoveryDidDocument.id
    targetRole = "discovery"
    didDocument = $discoveryDidDocument
} | Out-Null

Invoke-JsonPost "http://127.0.0.1:8000/root/discovery-nodes/$($discoveryDidDocument.id)/domains" @{
    authorizedDomains = @("*")
    tagTreeVersion = 1
} | Out-Null

$draft = Invoke-JsonPost "http://127.0.0.1:8001/api/v1/agents/draft" @{
    draftId = "trusted-hello-demo"
    agentDid = $serviceDidDocument.id
    didDocument = $serviceDidDocument
    metadata = @{
        source = "scripts/run-e2e-demo.ps1"
        demo = "trusted-agent-hello"
        capabilityTags = $demoCapabilityTags
    }
}
Write-Host "Draft created:"
$draft | ConvertTo-Json -Depth 20

$issued = Invoke-JsonPost "http://127.0.0.1:8001/api/v1/agents/draft/trusted-hello-demo/issue-registration-credential" @{}
Write-Host "Registration credential issued:"
$issued | ConvertTo-Json -Depth 20

$registration = Invoke-JsonPost "http://127.0.0.1:8001/api/v1/agents/draft/trusted-hello-demo/submit" @{}
Write-Host "Registrar submission:"
$registration | ConvertTo-Json -Depth 20

$cdnBatch = Invoke-JsonPost "http://127.0.0.1:8000/root/batches/publish-cdn" @{}
Write-Host "Root CDN batch:"
$cdnBatch | ConvertTo-Json -Depth 20

$discoveryBatch = Invoke-JsonPost "http://127.0.0.1:8000/root/batches/notify-discovery" @{}
Write-Host "Root Discovery notification batch:"
$discoveryBatch | ConvertTo-Json -Depth 20

$sync = Invoke-JsonPost "http://127.0.0.1:8002/discovery/sync" @{}
Write-Host "Discovery sync:"
$sync | ConvertTo-Json -Depth 20

$query = Invoke-JsonPost "http://127.0.0.1:8002/discover/query" @{
    capabilityTags = $demoCapabilityTags
    serviceType = "AgentService"
    protocol = "http"
    limit = 5
}
Write-Host "Discovery query:"
$query | ConvertTo-Json -Depth 30

$userAgentOutput = & uv run --project agents/user-agent-python openagentnet-user-agent
$userAgentDemo = Get-JsonFromCommandOutput ($userAgentOutput -join "`n")
Write-Host "User Agent trusted invocation demo:"
$userAgentDemo | ConvertTo-Json -Depth 40

$hello = $userAgentDemo.helloResponse
Assert-Equal "Service Agent reply verification flag" $hello.verified $true
Assert-Equal "Service Agent caller DID" $hello.callerDid $userAgentDemo.userAgentDid
Assert-Equal "Service Agent request signature verification" $userAgentDemo.checks.requestSignatureVerifiedByServiceAgent $true
Assert-Equal "Service Agent user VC verification" $userAgentDemo.checks.userCredentialVerifiedByServiceAgent $true
Assert-Equal "User Agent response signature verification" $userAgentDemo.checks.responseSignatureVerifiedByUserAgent $true
Assert-Equal "Service Agent provenance verification" $userAgentDemo.checks.provenanceVerified $true
Assert-Equal "Service Agent deployer" $hello.serviceAgent.deployment.deployer "China Academy of Information and Communications Technology (CAICT)"
Assert-Equal "Service Agent author" $hello.serviceAgent.deployment.author "JINLIANG XU"
Assert-Contains "Service Agent email list" $hello.serviceAgent.deployment.email "xujinliang@caict.ac.cn"
Assert-Contains "Service Agent email list" $hello.serviceAgent.deployment.email "jlxufly@gmail.com"
Assert-Contains "User Agent credential list" $userAgentDemo.invocation.credentialTypes "UserAgentRegistrationCredential"

Write-Host "Service Agent provenance verified: CAICT / JINLIANG XU / xujinliang@caict.ac.cn / jlxufly@gmail.com"
Write-Host "Agent-to-Agent trusted invocation verified: User Agent VC, request signature, and Service Agent response signature all passed."
Write-Host "E2E demo completed."
}
finally {
    Stop-StartedNodes
}
