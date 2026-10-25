# ==============================================================================
# Osiris Hybrid Swarm - Automatisches Katalog-Publishing Skript
# ==============================================================================

$ErrorActionPreference = "Stop"
$WorkspacePath = "F:\DeutschThek"
$GitHubClonePath = "C:\Users\PC MARKET\Documents\GitHub\DeutschThek"
$GitExe = "C:\Users\PC MARKET\AppData\Local\GitHubDesktop\app-3.6.7\resources\app\git\cmd\git.exe"

Write-Host "🏛️ [Osiris Admin] Starte Katalog-Publishing..." -ForegroundColor Cyan

# 1. Überprüfen, ob neue Export-Dateien im Download-Ordner liegen
$Downloads = [System.IO.Path]::Combine($env:USERPROFILE, "Downloads")
$JsonDownload = Join-Path $Downloads "official-catalog.json"
$JsDownload = Join-Path $Downloads "official-catalog.js"

$TargetJson = Join-Path $WorkspacePath "data\official-catalog.json"
$TargetJs = Join-Path $WorkspacePath "data\official-catalog.js"

if (Test-Path $JsonDownload) {
    Copy-Item -Path $JsonDownload -Destination $TargetJson -Force
    Write-Host "✅ official-catalog.json aus Downloads übernommen." -ForegroundColor Green
} else {
    Write-Host "ℹ️ Keine neue official-catalog.json in Downloads gefunden. Verwende existierende Datei in data/." -ForegroundColor Yellow
}

if (Test-Path $JsDownload) {
    Copy-Item -Path $JsDownload -Destination $TargetJs -Force
    Write-Host "✅ official-catalog.js aus Downloads übernommen." -ForegroundColor Green
}

# 2. Synchronisieren mit dem GitHub Clone
if (Test-Path $GitHubClonePath) {
    Write-Host "🔄 Synchronisiere zu GitHub Clone..." -ForegroundColor Cyan
    Copy-Item -Path (Join-Path $WorkspacePath "data\*") -Destination (Join-Path $GitHubClonePath "data") -Recurse -Force
    Copy-Item -Path (Join-Path $WorkspacePath "ADMIN_CATALOG.html") -Destination (Join-Path $GitHubClonePath "ADMIN_CATALOG.html") -Force
    Copy-Item -Path (Join-Path $WorkspacePath "index.html") -Destination (Join-Path $GitHubClonePath "index.html") -Force
    Copy-Item -Path (Join-Path $WorkspacePath "js\core\community-swarm.js") -Destination (Join-Path $GitHubClonePath "js\core\community-swarm.js") -Force

    # 3. Git Commit & Push
    Push-Location $GitHubClonePath
    try {
        & $GitExe add data/ official-catalog.* ADMIN_CATALOG.html index.html js/core/community-swarm.js
        $status = & $GitExe status --porcelain
        if ($status) {
            & $GitExe commit -m "Update official document catalog [skip ci]"
            & $GitExe push origin main
            Write-Host "🚀 Katalog erfolgreich auf GitHub Pages veröffentlicht!" -ForegroundColor Green
        } else {
            Write-Host "✓ Keine Änderungen im Katalog vorhanden. Git-Status ist bereits aktuell." -ForegroundColor Yellow
        }
    } finally {
        Pop-Location
    }
} else {
    Write-Host "⚠️ GitHub-Klon unter $GitHubClonePath nicht gefunden." -ForegroundColor Red
}

Write-Host "🎉 Vorgang abgeschlossen! Alle Lehrkräfte erhalten diese Updates jetzt automatisch." -ForegroundColor Green
