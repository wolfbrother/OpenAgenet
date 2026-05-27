# Copyright (c) 2026 China Academy of Information and Communications Technology (CAICT)
#
# Author: JINLIANG XU
# Email: xujinliang@caict.ac.cn; jlxufly@gmail.com
#

. "$PSScriptRoot\common.ps1"

function Read-ErrorResponseBody {
    param([System.Exception]$Exception)
    if (-not $Exception.Response) {
        return $null
    }
    $stream = $Exception.Response.GetResponseStream()
    if (-not $stream) {
        return $null
    }
    $reader = New-Object System.IO.StreamReader($stream)
    return $reader.ReadToEnd()
}

try {
    Initialize-ResearchExperiment | Out-Null
    Set-DiscoveryDomains @("*")
    $dataset = New-ResearchDataset -Count 1 -Tags @("gbt4754-2017.01")
    $agent = $dataset.agents[0]

    Register-ResearchAgent -Agent $agent -DraftPrefix "debug" | Out-Null
    Invoke-JsonPost "$($script:RootBaseUrl)/root/batches/publish-cdn" @{} | Out-Null
    Invoke-JsonPost "$($script:RootBaseUrl)/root/batches/notify-discovery" @{} | Out-Null

    Write-Host "--- MANIFEST ---"
    & curl.exe -sS "$($script:CdnBaseUrl)/cdn/manifest"
    Write-Host ""

    $url = "$($script:CdnBaseUrl)/cdn/packages/$($agent.did)"
    Write-Host "--- PACKAGE URL ---"
    Write-Host $url
    try {
        & curl.exe -sS $url
        Write-Host ""
    } catch {
        Write-Host $_.Exception.Message
        $body = Read-ErrorResponseBody $_.Exception
        if ($body) {
            Write-Host $body
        }
    }

    Write-Host "--- DISCOVERY SYNC ---"
    try {
        & curl.exe -i -sS -X POST "$($script:DiscoveryBaseUrl)/discovery/sync" -H "Content-Type: application/json" -d "{}"
        Write-Host ""
    } catch {
        Write-Host $_.Exception.Message
        $body = Read-ErrorResponseBody $_.Exception
        if ($body) {
            Write-Host $body
        }
        if (Test-Path (Join-Path $script:PidDir "discovery.err.log")) {
            Write-Host "--- discovery.err.log ---"
            Get-Content (Join-Path $script:PidDir "discovery.err.log") -Raw | Write-Host
        }
        if (Test-Path (Join-Path $script:PidDir "discovery.out.log")) {
            Write-Host "--- discovery.out.log ---"
            Get-Content (Join-Path $script:PidDir "discovery.out.log") -Raw | Write-Host
        }
    }
} finally {
    Stop-ResearchStack
}
