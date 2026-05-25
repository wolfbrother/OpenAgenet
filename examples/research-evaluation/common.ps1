# Copyright (c) 2026 China Academy of Information and Communications Technology (CAICT)
#
# Author: JINLIANG XU
# Email: xujinliang@caict.ac.cn; jlxufly@gmail.com
#

$ErrorActionPreference = "Stop"

$script:ExampleDir = $PSScriptRoot
$script:RepoRoot = Split-Path -Parent (Split-Path -Parent $script:ExampleDir)
$script:WorkDir = Join-Path $script:ExampleDir ".work"
$script:ResultsDir = Join-Path $script:ExampleDir "results"
$script:PidDir = Join-Path $script:WorkDir "pids"
$script:StartedPids = @()
$script:RootBaseUrl = "http://localhost:8000"
$script:RegistrarBaseUrl = "http://localhost:8001"
$script:DiscoveryBaseUrl = "http://localhost:8002"
$script:CdnBaseUrl = "http://localhost:8003"

function New-Directory {
    param([string]$Path)
    New-Item -ItemType Directory -Force -Path $Path | Out-Null
}

function Write-Utf8NoBomJson {
    param(
        [string]$Path,
        [object]$Value
    )
    $json = $Value | ConvertTo-Json -Depth 100
    $encoding = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, "$json`n", $encoding)
}

function Reset-ResearchWorkspace {
    Remove-Item -LiteralPath $script:WorkDir -Recurse -Force -ErrorAction SilentlyContinue
    New-Directory $script:WorkDir
    New-Directory $script:ResultsDir
    New-Directory $script:PidDir
    New-Directory (Join-Path $script:WorkDir "data")
    New-Directory (Join-Path $script:WorkDir "config")

    foreach ($name in @("root", "registrar", "discovery", "cdn", "demo-service-agent", "user-agent")) {
        $source = Join-Path $script:RepoRoot "data/$name"
        if (Test-Path $source) {
            $destination = Join-Path $script:WorkDir "data/$name"
            New-Directory $destination
            Get-ChildItem -LiteralPath $source -Force | ForEach-Object {
                Copy-Item -LiteralPath $_.FullName -Destination $destination -Recurse -Force
            }
        }
    }

    foreach ($relative in @(
        "data/root/keys",
        "data/root/queues",
        "data/registrar/records",
        "data/registrar/drafts",
        "data/discovery/index",
        "data/discovery/keys",
        "data/cdn/documents",
        "data/cdn/metadata",
        "data/cdn/packages"
    )) {
        New-Directory (Join-Path $script:WorkDir $relative)
    }

    foreach ($relative in @(
        "data/root/root.db",
        "data/root/queues",
        "data/registrar/registrar.db",
        "data/registrar/records",
        "data/registrar/drafts",
        "data/discovery/discovery.db",
        "data/discovery/index",
        "data/cdn/cdn.db",
        "data/cdn/manifest.json",
        "data/cdn/documents",
        "data/cdn/metadata",
        "data/cdn/packages"
    )) {
        Remove-Item -LiteralPath (Join-Path $script:WorkDir $relative) -Recurse -Force -ErrorAction SilentlyContinue
    }
    foreach ($relative in @(
        "data/root/queues",
        "data/registrar/records",
        "data/registrar/drafts",
        "data/discovery/index",
        "data/cdn/documents",
        "data/cdn/metadata",
        "data/cdn/packages"
    )) {
        New-Directory (Join-Path $script:WorkDir $relative)
    }

}

function Write-ResearchConfigs {
    $configDir = Join-Path $script:WorkDir "config"
    New-Directory $configDir

@"
[server]
host = "127.0.0.1"
port = 8000
endpoint = "http://localhost:8000"

[node]
name = "Research Root Node"
role = "root"
did_semantic_code = "AGRT"

[paths]
data_dir = "../data/root"
keys_dir = "../data/root/keys"
bulletin_file = "../data/root/bulletin.json"
authorization_state_file = "../data/root/authorization-state.json"
request_nonce_file = "../data/root/request-nonces.json"
capability_tree_file = "../../../docs/capability-tree-v1.json"
database_url = "sqlite:../data/root/root.db"
"@ | Set-Content -Path (Join-Path $configDir "root.toml") -Encoding utf8

@"
[server]
host = "127.0.0.1"
port = 8001
endpoint = "http://localhost:8001"

[node]
name = "Research Registrar Node"
role = "registrar"
did_semantic_code = "AGRG"

[upstream]
root_endpoint = "http://localhost:8000"

[paths]
data_dir = "../data/registrar"
records_dir = "../data/registrar/records"
keys_dir = "../data/registrar/keys"
database_url = "sqlite:../data/registrar/registrar.db"
"@ | Set-Content -Path (Join-Path $configDir "registrar.toml") -Encoding utf8

@"
[server]
host = "127.0.0.1"
port = 8002
endpoint = "http://localhost:8002"

[node]
name = "Research Discovery Node"
role = "discovery"
did_semantic_code = "AGDS"

[upstream]
root_endpoint = "http://localhost:8000"
cdn_endpoint = "http://localhost:8003"

[paths]
data_dir = "../data/discovery"
index_dir = "../data/discovery/index"
database_url = "sqlite:../data/discovery/discovery.db"
keys_dir = "../data/discovery/keys"
"@ | Set-Content -Path (Join-Path $configDir "discovery.toml") -Encoding utf8

@"
[server]
host = "127.0.0.1"
port = 8003
endpoint = "http://localhost:8003"

[service]
name = "Research CDN Service"
role = "cdn-service"
provider = "local"

[upstream]
root_endpoint = "http://localhost:8000"

[paths]
data_dir = "../data/cdn"
manifest_file = "../data/cdn/manifest.json"
documents_dir = "../data/cdn/documents"
metadata_dir = "../data/cdn/metadata"
packages_dir = "../data/cdn/packages"
database_url = "sqlite:../data/cdn/cdn.db"
"@ | Set-Content -Path (Join-Path $configDir "cdn.toml") -Encoding utf8
}

function Get-ListenerProcessId {
    param([int]$Port)
    try {
        return (Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction Stop | Select-Object -First 1).OwningProcess
    } catch {
        return $null
    }
}

function Start-ResearchNode {
    param([string]$Name, [string]$Package, [string]$ConfigPath, [int]$Port)
    $listener = Get-ListenerProcessId -Port $Port
    if ($listener) {
        Stop-Process -Id $listener -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 500
    }
    $process = Start-Process `
        -FilePath "cargo" `
        -ArgumentList @("run", "-p", $Package, "--", $ConfigPath) `
        -WorkingDirectory $script:RepoRoot `
        -NoNewWindow `
        -PassThru `
        -RedirectStandardOutput (Join-Path $script:PidDir "$Name.out.log") `
        -RedirectStandardError (Join-Path $script:PidDir "$Name.err.log")
    Set-Content -Path (Join-Path $script:PidDir "$Name.pid") -Value $process.Id
    $script:StartedPids += $process.Id
}

function Wait-Health {
    param([string]$Name, [int]$Port)
    $url = "http://127.0.0.1:$Port/health"
    for ($i = 0; $i -lt 90; $i++) {
        try {
            Invoke-RestMethod -Uri $url -TimeoutSec 1 | Out-Null
            return
        } catch {
            Start-Sleep -Milliseconds 500
        }
    }
    throw "$Name did not become ready at $url"
}

function Start-ResearchStack {
    $configDir = Join-Path $script:WorkDir "config"
    Start-ResearchNode "root" "root-node" (Join-Path $configDir "root.toml") 8000
    Start-ResearchNode "registrar" "registrar-node" (Join-Path $configDir "registrar.toml") 8001
    Start-ResearchNode "discovery" "discovery-node" (Join-Path $configDir "discovery.toml") 8002
    Start-ResearchNode "cdn" "cdn-node" (Join-Path $configDir "cdn.toml") 8003
    Wait-Health "root" 8000
    Wait-Health "registrar" 8001
    Wait-Health "discovery" 8002
    Wait-Health "cdn" 8003
}

function Stop-ResearchStack {
    foreach ($processId in $script:StartedPids) {
        Stop-Process -Id $processId -Force -ErrorAction SilentlyContinue
    }
    $script:StartedPids = @()
}

function Invoke-JsonPost {
    param([string]$Uri, [object]$Body)
    try {
        Invoke-RestMethod -Method Post -Uri $Uri -ContentType "application/json" -Body ($Body | ConvertTo-Json -Depth 100)
    } catch {
        throw "POST $Uri failed: $($_.Exception.Message)"
    }
}

function Measure-Action {
    param([scriptblock]$Action)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $value = & $Action
    $sw.Stop()
    [pscustomobject]@{ value = $value; elapsedMs = [Math]::Round($sw.Elapsed.TotalMilliseconds, 3) }
}

function Assert-Equal {
    param([string]$Name, [object]$Actual, [object]$Expected)
    if ($Actual -ne $Expected) {
        throw "$Name mismatch. Expected '$Expected', got '$Actual'."
    }
}

function Initialize-ResearchExperiment {
    Reset-ResearchWorkspace
    Write-ResearchConfigs
    Start-ResearchStack
    $registrarDoc = Get-Content (Join-Path $script:WorkDir "data/registrar/did-document.json") -Raw | ConvertFrom-Json
    $discoveryDoc = Get-Content (Join-Path $script:WorkDir "data/discovery/did-document.json") -Raw | ConvertFrom-Json
    Invoke-JsonPost "$($script:RootBaseUrl)/root/registrars/authorize" @{
        targetDid = $registrarDoc.id
        targetRole = "registrar"
        didDocument = $registrarDoc
    } | Out-Null
    Invoke-JsonPost "$($script:RootBaseUrl)/root/discovery-nodes/authorize" @{
        targetDid = $discoveryDoc.id
        targetRole = "discovery"
        didDocument = $discoveryDoc
    } | Out-Null
    return @{ registrarDid = $registrarDoc.id; discoveryDid = $discoveryDoc.id }
}

function Set-DiscoveryDomains {
    param([string[]]$Domains)
    $discoveryDoc = Get-Content (Join-Path $script:WorkDir "data/discovery/did-document.json") -Raw | ConvertFrom-Json
    Invoke-JsonPost "$($script:RootBaseUrl)/root/discovery-nodes/$($discoveryDoc.id)/domains" @{
        authorizedDomains = $Domains
        tagTreeVersion = 1
    } | Out-Null
}

function New-ResearchDataset {
    param([int]$Count, [string[]]$Tags)
    $out = Join-Path $script:WorkDir "dataset-$Count.json"
    & node (Join-Path $script:ExampleDir "generate-dataset.mjs") `
        --repo-root $script:RepoRoot `
        --output $out `
        --count $Count `
        --tags ($Tags -join ",") | Out-Null
    return (Get-Content $out -Raw | ConvertFrom-Json)
}

function Register-ResearchAgent {
    param([object]$Agent, [string]$DraftPrefix)
    $draftId = "$DraftPrefix-$($Agent.index)"
    Invoke-JsonPost "$($script:RegistrarBaseUrl)/api/v1/agents/draft" @{
        draftId = $draftId
        agentDid = $Agent.did
        didDocument = $Agent.didDocument
        metadata = @{
            source = "examples/research-evaluation"
            datasetIndex = $Agent.index
            capabilityTags = $Agent.capabilityTags
        }
    } | Out-Null
    Invoke-JsonPost "$($script:RegistrarBaseUrl)/api/v1/agents/draft/$draftId/issue-registration-credential" @{} | Out-Null
    return Invoke-JsonPost "$($script:RegistrarBaseUrl)/api/v1/agents/draft/$draftId/submit" @{}
}

function Publish-And-Sync {
    $publish = Measure-Action { Invoke-JsonPost "$($script:RootBaseUrl)/root/batches/publish-cdn" @{} }
    $notify = Measure-Action { Invoke-JsonPost "$($script:RootBaseUrl)/root/batches/notify-discovery" @{} }
    $sync = Measure-Action { Invoke-JsonPost "$($script:DiscoveryBaseUrl)/discovery/sync" @{} }
    return [pscustomobject]@{ publish = $publish; notify = $notify; sync = $sync }
}

function Write-ResultJson {
    param([string]$Name, [object]$Value)
    New-Directory $script:ResultsDir
    $path = Join-Path $script:ResultsDir $Name
    $Value | ConvertTo-Json -Depth 100 | Set-Content -Path $path -Encoding utf8
    return $path
}

function Get-StorageBytes {
    $dataPath = Join-Path $script:WorkDir "data"
    if (-not (Test-Path $dataPath)) { return 0 }
    return (Get-ChildItem -LiteralPath $dataPath -Recurse -File | Measure-Object -Property Length -Sum).Sum
}
