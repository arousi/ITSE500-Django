param(
  [string]$ReactAppDir = "",
  [switch]$SkipBuild
)

$ErrorActionPreference = 'Stop'

function Write-Info($msg) { Write-Host "[react-deploy] $msg" -ForegroundColor Cyan }
function Write-Warn($msg) { Write-Host "[react-deploy] $msg" -ForegroundColor Yellow }

# Resolve defaults
if (-not $ReactAppDir -or -not (Test-Path $ReactAppDir)) {
  # Default to the repo React app path if not provided
  $defaultPath = Join-Path (Split-Path -Parent $PSScriptRoot) '..\codebase\deploy\front-end\web' | Resolve-Path -ErrorAction SilentlyContinue
  if ($defaultPath) {
    $ReactAppDir = $defaultPath.Path
  } else {
    Write-Error "React app directory not found. Pass -ReactAppDir <path-to-react-app>"
  }
}

Write-Info "Using React app at: $ReactAppDir"

# Verify package.json exists
$pkgJson = Join-Path $ReactAppDir 'package.json'
if (-not (Test-Path $pkgJson)) {
  Write-Error "No package.json found in $ReactAppDir"
}

# Build React app unless skipped
if (-not $SkipBuild) {
  Write-Info "Installing dependencies and building React app..."
  Push-Location $ReactAppDir
  try {
    if (Test-Path (Join-Path $ReactAppDir 'package-lock.json')) {
      npm ci
    } else {
      npm install
    }
    npm run build
  } finally {
    Pop-Location
  }
} else {
  Write-Warn "Skipping build as requested (-SkipBuild)."
}

# Source build directory
$srcBuild = Join-Path $ReactAppDir 'build'
if (-not (Test-Path $srcBuild)) {
  Write-Error "React build folder not found at: $srcBuild"
}

# Destination in Django
$djangoRoot = Split-Path -Parent $PSScriptRoot
$dstRoot = Join-Path $djangoRoot 'frontend_build'
$dstStatic = Join-Path $dstRoot 'static'

# Reset destination
if (Test-Path $dstRoot) {
  Write-Info "Removing old frontend_build at $dstRoot"
  Remove-Item -Recurse -Force $dstRoot
}
New-Item -ItemType Directory -Path $dstRoot | Out-Null

# Copy index.html and static folder
Write-Info "Copying index.html and static assets to $dstRoot"
Copy-Item -Force (Join-Path $srcBuild 'index.html') $dstRoot
if (Test-Path (Join-Path $srcBuild 'static')) {
  Copy-Item -Recurse -Force (Join-Path $srcBuild 'static') $dstRoot
} else {
  Write-Warn "No 'static' folder found in build. CRA usually outputs 'build/static'."
}

# Collect static files so WhiteNoise serves them under /static/
Write-Info "Collecting Django static files..."
Push-Location $djangoRoot
try {
  python manage.py collectstatic --noinput
} finally {
  Pop-Location
}

Write-Info "Done. React app deployed. Visit your Django site to verify the SPA loads."
