param([Parameter(ValueFromRemainingArguments=$true)][string[]]$Args)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSCommandPath

# Default behavior: launch in a fresh PowerShell window unless --current-window is set.
$isChild = $Args -contains '--child'
$inCurrent = $Args -contains '--current-window'
if (-not $isChild -and -not $inCurrent) {
	$forward = @()
	foreach ($a in $Args) { if ($a -ne '--current-window' -and $a -ne '--child') { $forward += $a } }
	$argList = @('-NoExit','-ExecutionPolicy','Bypass','-File',"$PSCommandPath",'--child') + $forward
	Start-Process -FilePath 'powershell.exe' -ArgumentList $argList | Out-Null
	return
}

# Normalize args for inner execution (strip control flags)
$execArgs = @()
foreach ($a in $Args) { if ($a -ne '--current-window' -and $a -ne '--child' -and $a -ne '--new-window') { $execArgs += $a } }

# Try to activate a local venv (PowerShell) if present
$venvNames = @('server_venv','venv','.venv')
$venvPath = $null
foreach ($name in $venvNames) {
	$p = Join-Path $root $name
	if (Test-Path $p) { $venvPath = $p; break }
}

if ($venvPath) {
	$activate = Join-Path $venvPath 'Scripts\\Activate.ps1'
	if (Test-Path $activate) {
		try {
			. $activate
		} catch {
			Write-Warning "Venv activation failed: $($_.Exception.Message). Continuing with direct python."
		}
	}
}

$venvPy = if ($venvPath) { Join-Path $venvPath 'Scripts\\python.exe' } else { $null }
$py = if ($venvPy -and (Test-Path $venvPy)) { $venvPy } else { 'python' }

& $py (Join-Path $root 'manage.py') dev_up --no-input @execArgs