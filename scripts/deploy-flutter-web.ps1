param(
  [string]$FlutterWebBuildDir,
  [switch]$SetBaseHref
)

$ErrorActionPreference = 'Stop'

if (-not $FlutterWebBuildDir) {
  Write-Error "Usage: .\deploy-flutter-web.ps1 -FlutterWebBuildDir <path-to-flutter-build-web> [-SetBaseHref]"
}

$dst = Join-Path -Path (Split-Path -Parent $PSScriptRoot) -ChildPath 'flutter_build'

if (Test-Path $dst) { Remove-Item -Recurse -Force $dst }
New-Item -ItemType Directory -Path $dst | Out-Null

Copy-Item -Recurse -Force (Join-Path $FlutterWebBuildDir '*') $dst

$indexPath = Join-Path $dst 'index.html'
if (Test-Path $indexPath) {
  $html = Get-Content -Raw -Encoding UTF8 $indexPath
  if ($SetBaseHref) {
    if ($html -notmatch '<base ') {
      $pattern = '(<head[^>]*>)'
      $replacement = "$1`n    <base href='/static/flutter-web/'>"
      $html = [regex]::Replace($html, $pattern, $replacement, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
      Set-Content -Path $indexPath -Value $html -Encoding UTF8
      Write-Host "Injected <base href='/static/flutter-web/'> into index.html"
    }
  }
}

# Collect static so WhiteNoise serves Flutter assets
Push-Location (Split-Path -Parent $PSScriptRoot)
python manage.py collectstatic --noinput
Pop-Location

Write-Host "Flutter web deployed to $dst and static collected."