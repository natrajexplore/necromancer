# Lighthouse (desktop preset) against the production build, with the real engine behind it.
# Starts the engine and `vite preview`, runs Lighthouse with the installed Chrome, stops both.
# Usage, from frontend/:  powershell -File scripts/lighthouse.ps1 [-Out lighthouse.json]
param([string]$Out = "lighthouse.json")

$ErrorActionPreference = "Stop"
$frontend = Split-Path -Parent $PSScriptRoot
$backend = Join-Path (Split-Path -Parent $frontend) "backend"
$chrome = @(
  "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
  "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $chrome) { throw "Install Google Chrome, or edit this script to point at another Chrome." }

$env:UV_PYTHON_PREFERENCE = "only-system"
$env:NECRO_API_PROXY = "http://127.0.0.1:8000"
$api = $null
$preview = $null
try {
  Push-Location $frontend
  npm.cmd run build | Out-Null
  $api = Start-Process -FilePath "uv" -ArgumentList "run", "python", "-m", "uvicorn", "api.main:app", "--port", "8000" `
    -WorkingDirectory $backend -WindowStyle Hidden -PassThru
  $preview = Start-Process -FilePath "npx.cmd" -ArgumentList "vite", "preview", "--port", "4173", "--strictPort" `
    -WorkingDirectory $frontend -WindowStyle Hidden -PassThru
  foreach ($url in "http://127.0.0.1:8000/healthz", "http://localhost:4173/") {
    for ($i = 0; $i -lt 60; $i++) {
      try { Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 2 | Out-Null; break } catch { Start-Sleep -Seconds 1 }
    }
  }
  npx.cmd lighthouse "http://localhost:4173/" --preset=desktop --chrome-path="$chrome" `
    --chrome-flags="--headless=new --no-sandbox" --output=json --output-path=$Out --quiet `
    --only-categories=performance,accessibility,best-practices,seo
  $report = Get-Content $Out -Raw | ConvertFrom-Json
  foreach ($key in "performance", "accessibility", "best-practices", "seo") {
    "{0,-15} {1}" -f $key, [math]::Round($report.categories.$key.score * 100)
  }
  "lighthouse " + $report.lighthouseVersion
}
finally {
  Pop-Location
  foreach ($p in $preview, $api) {
    if ($p -and -not $p.HasExited) { taskkill /PID $p.Id /T /F | Out-Null }
  }
}
