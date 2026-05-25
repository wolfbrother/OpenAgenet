# Copyright (c) 2026 China Academy of Information and Communications Technology (CAICT)
#
# Author: JINLIANG XU
# Email: xujinliang@caict.ac.cn; jlxufly@gmail.com
#

. "$PSScriptRoot\common.ps1"

try {
    Reset-ResearchWorkspace
    Write-ResearchConfigs
    Start-ResearchStack

    $doc = Get-Content (Join-Path $script:WorkDir "data/registrar/did-document.json") -Raw | ConvertFrom-Json
    $body = @{
        targetDid = $doc.id
        targetRole = "registrar"
        didDocument = $doc
    } | ConvertTo-Json -Depth 50

    try {
        Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8200/root/registrars/authorize" -ContentType "application/json" -Body $body | ConvertTo-Json -Depth 10
    } catch {
        if ($_.ErrorDetails.Message) {
            Write-Output $_.ErrorDetails.Message
        }
        Write-Output $_.Exception.Message
    }
} finally {
    Stop-ResearchStack
}
