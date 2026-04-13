param(
    [string]$InputMarkdown = "RAPPORT.md",
    [string]$OutputHtml = "docs/rapport-phishguard.html",
    [string]$OutputPdf = "docs/rapport-phishguard.pdf"
)

$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
$docsDir = Join-Path $projectRoot "docs"
$sourceMarkdown = Join-Path $projectRoot $InputMarkdown
$htmlPath = Join-Path $projectRoot $OutputHtml
$pdfPath = Join-Path $projectRoot $OutputPdf
$cssPath = Join-Path $docsDir "report.css"
$browserProfileDir = Join-Path $docsDir ".report-browser-profile"

if (-not (Test-Path $sourceMarkdown)) {
    throw "Source markdown not found: $sourceMarkdown"
}

if (-not (Test-Path $cssPath)) {
    throw "CSS file not found: $cssPath"
}

$pandoc = (Get-Command pandoc -ErrorAction Stop).Source

$browserCandidates = @(
    "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    "C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    "C:\Program Files\Google\Chrome\Application\chrome.exe",
    "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"
)

$browser = $browserCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $browser) {
    throw "No Chromium-based browser found for PDF generation."
}

New-Item -ItemType Directory -Force -Path $docsDir | Out-Null
New-Item -ItemType Directory -Force -Path $browserProfileDir | Out-Null

Push-Location $docsDir
try {
    & $pandoc "..\$InputMarkdown" `
        --from gfm `
        --to html5 `
        --standalone `
        --toc `
        --toc-depth=3 `
        --css "report.css" `
        --metadata title="Rapport technique du projet PhishGuard AI" `
        --output (Split-Path $htmlPath -Leaf)

    $htmlUri = [System.Uri]::new((Resolve-Path $htmlPath).Path).AbsoluteUri
    & $browser `
        "--headless" `
        "--disable-gpu" `
        "--no-sandbox" `
        "--disable-crash-reporter" `
        "--disable-crashpad" `
        "--user-data-dir=$browserProfileDir" `
        "--allow-file-access-from-files" `
        "--print-to-pdf=$pdfPath" `
        $htmlUri | Out-Null
}
finally {
    Pop-Location
}

Write-Output "HTML generated: $htmlPath"
Write-Output "PDF generated:  $pdfPath"
