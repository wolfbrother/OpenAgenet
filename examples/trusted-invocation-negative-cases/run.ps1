# Copyright (c) 2026 China Academy of Information and Communications Technology (CAICT)
#
# Author: JINLIANG XU
# Email: xujinliang@caict.ac.cn; jlxufly@gmail.com
#

$ErrorActionPreference = "Stop"

$exampleDir = $PSScriptRoot
$repoRoot = Split-Path -Parent (Split-Path -Parent $exampleDir)
$pidDir = Join-Path $repoRoot ".oan-example-pids"
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

function Run-NodeScript {
    param([string]$Script)
    $output = & node --input-type=module -e $Script
    $jsonText = ($output -join "`n")
    $start = $jsonText.IndexOf("{")
    if ($start -lt 0) {
        throw "Node output did not contain JSON."
    }
    return ($jsonText.Substring($start) | ConvertFrom-Json)
}

function New-InvocationPayload {
    param(
        [string]$TargetDid,
        [string]$CredentialMode,
        [string]$TimestampMode,
        [string]$BodyMode
    )

    $repoRootJson = ($repoRoot -replace "\\", "\\")
    $script = @"
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const repoRoot = '$repoRootJson';

function readJson(relativePath) {
  return JSON.parse(fs.readFileSync(path.join(repoRoot, relativePath), 'utf8'));
}

function canonicalJson(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonicalJson).join(',') + ']';
  return '{' + Object.keys(value).sort().map((key) => JSON.stringify(key) + ':' + canonicalJson(value[key])).join(',') + '}';
}

function sha256Hex(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function signValue(value, keypair) {
  const unsigned = { ...value };
  delete unsigned.proof;
  const privateKey = crypto.createPrivateKey({ key: keypair.privateKeyJwk, format: 'jwk' });
  const payloadHash = sha256Hex(canonicalJson(unsigned));
  return {
    ...unsigned,
    proof: {
      type: 'Ed25519Signature2020',
      creator: keypair.keyId,
      created: new Date().toISOString(),
      proofPurpose: 'authentication',
      proofValue: crypto.sign(null, Buffer.from(payloadHash, 'utf8'), privateKey).toString('base64url')
    }
  };
}

function requestBody(mode) {
  if (mode === 'tampered') return { message: 'tampered after signing', purpose: 'trusted-invocation-negative-cases' };
  return { message: 'hello from OAN example tests', purpose: 'trusted-invocation-negative-cases' };
}

function credentials(mode) {
  if (mode === 'missing') return [];
  const credential = readJson('data/user-agent/credentials/user-agent-registration.json');
  if (mode === 'wrong-subject') {
    credential.subject = 'did:ans:AGUS:wrong-subject';
  }
  if (mode === 'tampered-signature') {
    credential.proof.proofValue = 'invalid-credential-signature';
  }
  if (mode === 'invalid-type') {
    credential.type = 'UnsupportedCredential';
  }
  return [credential];
}

const body = requestBody('$BodyMode');
const userDidDocument = readJson('data/user-agent/did-document.json');
const baseTimestamp = new Date();
if ('$TimestampMode' === 'expired') {
  baseTimestamp.setUTCFullYear(2020);
}
const invocation = {
  type: 'OANTrustedInvocation',
  callerDid: userDidDocument.id,
  targetDid: '$TargetDid',
  nonce: crypto.randomBytes(18).toString('base64url'),
  timestamp: baseTimestamp.toISOString(),
  body,
  bodyHash: sha256Hex(canonicalJson(body)),
  callerDidDocument: userDidDocument,
  credentials: credentials('$CredentialMode'),
  discoveryProof: { example: 'trusted-invocation-negative-cases' }
};

const signed = signValue(invocation, readJson('data/user-agent/keys/keypair.json'));
if ('$BodyMode' === 'wrong-hash') {
  signed.bodyHash = '00';
}
if ('$BodyMode' === 'wrong-target') {
  signed.targetDid = 'did:ans:AGDM:wrong-target';
}
console.log(JSON.stringify(signed));
"@
    return Run-NodeScript $script
}

function Remove-NestedProperty {
    param(
        [object]$Object,
        [string]$Path
    )

    $parts = $Path.Split('.')
    if ($parts.Length -eq 0) {
        return
    }
    $current = $Object
    for ($i = 0; $i -lt $parts.Length - 1; $i++) {
        $key = $parts[$i]
        if ($null -eq $current.$key) {
            return
        }
        $current = $current.$key
    }
    $leaf = $parts[$parts.Length - 1]
    if ($current -is [System.Collections.IDictionary]) {
        [void]$current.Remove($leaf)
    } else {
        $current.PSObject.Properties.Remove($leaf) | Out-Null
    }
}

function Invoke-JsonPostAllowFailure {
    param([string]$Uri, [object]$Body)
    $payloadJson = $Body | ConvertTo-Json -Depth 100 -Compress
    $payloadB64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($payloadJson))
    $uriB64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Uri))
    $script = @"
import http from 'node:http';
import https from 'node:https';

const uri = Buffer.from('$uriB64', 'base64').toString('utf8');
const payload = JSON.parse(Buffer.from('$payloadB64', 'base64').toString('utf8'));
const client = uri.startsWith('https:') ? https : http;
const body = JSON.stringify(payload);
const request = client.request(uri, { method: 'POST', headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) } }, (response) => {
  let data = '';
  response.setEncoding('utf8');
  response.on('data', (chunk) => { data += chunk; });
  response.on('end', () => {
    console.log(JSON.stringify({
      status: response.statusCode,
      rawBody: data,
      body: data ? JSON.parse(data) : null
    }));
  });
});
request.on('error', (error) => {
  console.log(JSON.stringify({ status: 0, rawBody: '', body: { error: error.message } }));
});
request.write(body);
request.end();
"@
    return Run-NodeScript $script
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

try {
    Start-Node "root-node" "root-node" "services/root-node/config.example.toml" 8000
    Start-Node "registrar-node" "registrar-node" "services/registrar-node/config.example.toml" 8001
    Start-Node "discovery-node" "discovery-node" "services/discovery-node/config.example.toml" 8002
    Start-Node "cdn-node" "cdn-node" "services/cdn-node/config.example.toml" 8003

    $listener = Get-ListenerProcessId -Port 9001
    if ($listener) {
        Stop-Process -Id $listener -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 500
    }
    $serviceAgentOut = Join-Path $pidDir "service-agent-python.out.log"
    $serviceAgentErr = Join-Path $pidDir "service-agent-python.err.log"
    $serviceAgent = Start-Process `
        -FilePath "uv" `
        -ArgumentList @("run", "--project", "agents/service-agent-python", "oan-service-agent") `
        -WorkingDirectory $repoRoot `
        -NoNewWindow `
        -PassThru `
        -RedirectStandardOutput $serviceAgentOut `
        -RedirectStandardError $serviceAgentErr
    Set-Content -Path (Join-Path $pidDir "service-agent-python.pid") -Value $serviceAgent.Id
    $script:startedPids += $serviceAgent.Id
    Write-Host "Started service-agent-python as PID $($serviceAgent.Id)"

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

    Invoke-JsonPost "http://127.0.0.1:8001/api/v1/agents/draft" @{
        draftId = "trusted-negative-cases"
        agentDid = $serviceDidDocument.id
        didDocument = $serviceDidDocument
        metadata = @{
            source = "examples/trusted-invocation-negative-cases/run.ps1"
            demo = "trusted-invocation-negative-cases"
            capabilityTags = $demoCapabilityTags
        }
    } | Out-Null
    Invoke-JsonPost "http://127.0.0.1:8001/api/v1/agents/draft/trusted-negative-cases/issue-registration-credential" @{} | Out-Null
    Invoke-JsonPost "http://127.0.0.1:8001/api/v1/agents/draft/trusted-negative-cases/submit" @{} | Out-Null
    Invoke-JsonPost "http://127.0.0.1:8000/root/batches/publish-cdn" @{} | Out-Null
    Invoke-JsonPost "http://127.0.0.1:8000/root/batches/notify-discovery" @{} | Out-Null
    Invoke-JsonPost "http://127.0.0.1:8002/discovery/sync" @{} | Out-Null

    $query = Invoke-JsonPost "http://127.0.0.1:8002/discover/query" @{
        capabilityTags = $demoCapabilityTags
        serviceType = "AgentService"
        protocol = "http"
        limit = 1
    }
    if (-not $query.candidates -or $query.candidates.Count -lt 1) {
        throw "Discovery did not return a Service Agent candidate."
    }

    $targetDid = $query.candidates[0].did
    $serviceEndpoint = ($query.candidates[0].services | Where-Object { $_.type -eq "AgentService" } | Select-Object -First 1).serviceEndpoint
    $serviceBase = $serviceEndpoint -replace "/invoke$", ""
    $helloEndpoint = "$serviceBase/hello"

    $validInvocation = New-InvocationPayload -TargetDid $targetDid -CredentialMode "valid" -TimestampMode "valid" -BodyMode "valid"
    $valid = Invoke-JsonPostAllowFailure $helloEndpoint $validInvocation
    Assert-Equal "valid invocation HTTP status" $valid.status 200
    Assert-Equal "valid invocation verified flag" $valid.body.verified $true
    Assert-Equal "valid request signature verification" $valid.body.verification.requestSignatureVerified $true
    Assert-Equal "valid user credential verification" $valid.body.verification.userCredentialVerified $true

    $cases = @(
        @{ name = "tampered request signature"; payload = (New-InvocationPayload -TargetDid $targetDid -CredentialMode "valid" -TimestampMode "valid" -BodyMode "valid"); reason = "request_signature_invalid"; mutate = "proof" }
        @{ name = "missing proof"; payload = (New-InvocationPayload -TargetDid $targetDid -CredentialMode "valid" -TimestampMode "valid" -BodyMode "valid"); reason = "request_signature_invalid"; mutate = "remove-proof" }
        @{ name = "invalid proof creator"; payload = (New-InvocationPayload -TargetDid $targetDid -CredentialMode "valid" -TimestampMode "valid" -BodyMode "valid"); reason = "request_signature_invalid"; mutate = "bad-proof-creator" }
        @{ name = "missing User Agent VC"; payload = (New-InvocationPayload -TargetDid $targetDid -CredentialMode "missing" -TimestampMode "valid" -BodyMode "valid"); reason = "missing_user_agent_credential" }
        @{ name = "wrong VC subject"; payload = (New-InvocationPayload -TargetDid $targetDid -CredentialMode "wrong-subject" -TimestampMode "valid" -BodyMode "valid"); reason = "missing_user_agent_credential" }
        @{ name = "tampered VC signature"; payload = (New-InvocationPayload -TargetDid $targetDid -CredentialMode "tampered-signature" -TimestampMode "valid" -BodyMode "valid"); reason = "user_credential_signature_invalid" }
        @{ name = "invalid VC type"; payload = (New-InvocationPayload -TargetDid $targetDid -CredentialMode "invalid-type" -TimestampMode "valid" -BodyMode "valid"); reason = "missing_user_agent_credential" }
        @{ name = "credentials not array"; payload = (New-InvocationPayload -TargetDid $targetDid -CredentialMode "valid" -TimestampMode "valid" -BodyMode "valid"); reason = "credentials_must_be_array"; mutate = "credentials-not-array" }
        @{ name = "wrong body hash"; payload = (New-InvocationPayload -TargetDid $targetDid -CredentialMode "valid" -TimestampMode "valid" -BodyMode "wrong-hash"); reason = "body_hash_mismatch" }
        @{ name = "missing body"; payload = (New-InvocationPayload -TargetDid $targetDid -CredentialMode "valid" -TimestampMode "valid" -BodyMode "valid"); reason = "missing_or_invalid_body_hash"; mutate = "remove-body" }
        @{ name = "missing bodyHash"; payload = (New-InvocationPayload -TargetDid $targetDid -CredentialMode "valid" -TimestampMode "valid" -BodyMode "valid"); reason = "missing_or_invalid_body_hash"; mutate = "remove-bodyHash" }
        @{ name = "expired timestamp"; payload = (New-InvocationPayload -TargetDid $targetDid -CredentialMode "valid" -TimestampMode "expired" -BodyMode "valid"); reason = "timestamp_expired" }
        @{ name = "future timestamp"; payload = (New-InvocationPayload -TargetDid $targetDid -CredentialMode "valid" -TimestampMode "valid" -BodyMode "valid"); reason = "timestamp_in_future"; mutate = "future-timestamp" }
        @{ name = "invalid timestamp format"; payload = (New-InvocationPayload -TargetDid $targetDid -CredentialMode "valid" -TimestampMode "valid" -BodyMode "valid"); reason = "invalid_timestamp"; mutate = "bad-timestamp" }
        @{ name = "timestamp without timezone"; payload = (New-InvocationPayload -TargetDid $targetDid -CredentialMode "valid" -TimestampMode "valid" -BodyMode "valid"); reason = "timestamp_must_include_timezone"; mutate = "naive-timestamp" }
        @{ name = "missing caller DID"; payload = (New-InvocationPayload -TargetDid $targetDid -CredentialMode "valid" -TimestampMode "valid" -BodyMode "valid"); reason = "missing_invocation_fields"; mutate = "remove-callerDid" }
        @{ name = "missing target DID"; payload = (New-InvocationPayload -TargetDid $targetDid -CredentialMode "valid" -TimestampMode "valid" -BodyMode "valid"); reason = "missing_invocation_fields"; mutate = "remove-targetDid" }
        @{ name = "missing nonce"; payload = (New-InvocationPayload -TargetDid $targetDid -CredentialMode "valid" -TimestampMode "valid" -BodyMode "valid"); reason = "missing_invocation_fields"; mutate = "remove-nonce" }
        @{ name = "missing timestamp"; payload = (New-InvocationPayload -TargetDid $targetDid -CredentialMode "valid" -TimestampMode "valid" -BodyMode "valid"); reason = "missing_invocation_fields"; mutate = "remove-timestamp" }
        @{ name = "missing caller DID document"; payload = (New-InvocationPayload -TargetDid $targetDid -CredentialMode "valid" -TimestampMode "valid" -BodyMode "valid"); reason = "caller_did_document_mismatch"; mutate = "remove-callerDidDocument" }
        @{ name = "mismatched caller DID document id"; payload = (New-InvocationPayload -TargetDid $targetDid -CredentialMode "valid" -TimestampMode "valid" -BodyMode "valid"); reason = "caller_did_document_mismatch"; mutate = "callerDidDocument-id" }
        @{ name = "wrong target DID"; payload = (New-InvocationPayload -TargetDid $targetDid -CredentialMode "valid" -TimestampMode "valid" -BodyMode "wrong-target"); reason = "target_did_mismatch" }
    )

    foreach ($case in $cases) {
        if ($case.mutate -eq "proof") {
            $case.payload.proof.proofValue = "invalid-signature"
        } elseif ($case.mutate -eq "remove-proof") {
            Remove-NestedProperty -Object $case.payload -Path "proof"
        } elseif ($case.mutate -eq "bad-proof-creator") {
            $case.payload.proof.creator = "did:ans:AGUS:unknown#keys-1"
        } elseif ($case.mutate -eq "credentials-not-array") {
            $case.payload.credentials = @{
                type = "UserAgentRegistrationCredential"
            }
        } elseif ($case.mutate -eq "remove-body") {
            Remove-NestedProperty -Object $case.payload -Path "body"
        } elseif ($case.mutate -eq "remove-bodyHash") {
            Remove-NestedProperty -Object $case.payload -Path "bodyHash"
        } elseif ($case.mutate -eq "future-timestamp") {
            $case.payload.timestamp = (Get-Date).AddMinutes(10).ToUniversalTime().ToString("o")
        } elseif ($case.mutate -eq "bad-timestamp") {
            $case.payload.timestamp = "not-a-timestamp"
        } elseif ($case.mutate -eq "naive-timestamp") {
            $case.payload.timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss")
        } elseif ($case.mutate -eq "remove-callerDid") {
            Remove-NestedProperty -Object $case.payload -Path "callerDid"
        } elseif ($case.mutate -eq "remove-targetDid") {
            Remove-NestedProperty -Object $case.payload -Path "targetDid"
        } elseif ($case.mutate -eq "remove-nonce") {
            Remove-NestedProperty -Object $case.payload -Path "nonce"
        } elseif ($case.mutate -eq "remove-timestamp") {
            Remove-NestedProperty -Object $case.payload -Path "timestamp"
        } elseif ($case.mutate -eq "remove-callerDidDocument") {
            Remove-NestedProperty -Object $case.payload -Path "callerDidDocument"
        } elseif ($case.mutate -eq "callerDidDocument-id") {
            $case.payload.callerDidDocument.id = "did:ans:AGUS:wrong-document"
        }
        $result = Invoke-JsonPostAllowFailure $helloEndpoint $case.payload
        Assert-Equal "$($case.name) HTTP status" $result.status 401
        Assert-Equal "$($case.name) error" $result.body.error "trusted_invocation_rejected"
        if (-not ($result.body.reason -like "*$($case.reason)*")) {
            throw "$($case.name) reason mismatch. Expected to contain '$($case.reason)', got '$($result.body.reason)'."
        }
        Write-Host "Rejected as expected: $($case.name)"
    }

    $replayInvocation = New-InvocationPayload -TargetDid $targetDid -CredentialMode "valid" -TimestampMode "valid" -BodyMode "valid"
    $firstReplay = Invoke-JsonPostAllowFailure $helloEndpoint $replayInvocation
    Assert-Equal "replay setup HTTP status" $firstReplay.status 200
    $secondReplay = Invoke-JsonPostAllowFailure $helloEndpoint $replayInvocation
    Assert-Equal "replayed nonce HTTP status" $secondReplay.status 401
    Assert-Equal "replayed nonce error" $secondReplay.body.error "trusted_invocation_rejected"
    if (-not ($secondReplay.body.reason -like "*replayed_nonce*")) {
        throw "replayed nonce reason mismatch. Got '$($secondReplay.body.reason)'."
    }
    Write-Host "Rejected as expected: replayed nonce"

    @{
        status = "ok"
        example = "trusted-invocation-negative-cases"
        positiveChecks = @("valid signed invocation", "service verified request signature", "service verified user credential")
        negativeChecks = $cases.name + @("replayed nonce")
    } | ConvertTo-Json -Depth 20
} finally {
    Stop-StartedNodes
}

