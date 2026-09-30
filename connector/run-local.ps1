param([string]$PnpmPath, [string]$NodePath)

$ErrorActionPreference = "Stop"
$connectorDir = Split-Path -Parent $PSCommandPath
$projectDir = Split-Path -Parent $connectorDir
$envFile = Join-Path $connectorDir ".env"
$caFile = Join-Path $connectorDir "certs\indexer-ca.pem"
$logDir = Join-Path $connectorDir "logs"
$logFile = Join-Path $logDir "connector.log"
$allowedNames = @(
  "SUPABASE_URL", "SUPABASE_PUBLISHABLE_KEY", "WAZUH_CONNECTION_ID",
  "WAZUH_INGEST_TOKEN", "WAZUH_INDEXER_URL", "WAZUH_INDEXER_USERNAME",
  "WAZUH_INDEXER_PASSWORD", "WAZUH_INDEXER_CA_FILE", "INDEXER_INDEX_PATTERN",
  "INDEXER_PAGE_SIZE", "SYNC_INTERVAL_SECONDS"
)

if (-not (Test-Path -LiteralPath $envFile)) { throw "Arquivo connector/.env não encontrado." }
if (-not (Test-Path -LiteralPath $caFile)) { throw "Certificado connector/certs/indexer-ca.pem não encontrado." }

foreach ($line in [System.IO.File]::ReadLines($envFile)) {
  if ($line -match '^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$') {
    $name = $Matches[1]
    if ($allowedNames -notcontains $name) { continue }
    $value = $Matches[2].Trim()
    if ($value.Length -ge 2 -and (($value.StartsWith('"') -and $value.EndsWith('"')) -or ($value.StartsWith("'") -and $value.EndsWith("'")))) {
      $value = $value.Substring(1, $value.Length - 2)
    }
    [Environment]::SetEnvironmentVariable($name, $value, "Process")
  }
}

$env:NODE_EXTRA_CA_CERTS = $caFile
New-Item -ItemType Directory -Path $logDir -Force | Out-Null
if (-not $PnpmPath) { $PnpmPath = (Get-Command "pnpm.cmd" -ErrorAction Stop).Source }
if (-not (Test-Path -LiteralPath $PnpmPath)) { throw "Executável pnpm.cmd não encontrado no caminho configurado." }
if (-not $NodePath) { $NodePath = (Get-Command "node.exe" -ErrorAction Stop).Source }
if (-not (Test-Path -LiteralPath $NodePath)) { throw "Executável node.exe não encontrado no caminho configurado." }
$env:PATH = "$(Split-Path -Parent $NodePath);$env:PATH"

while ($true) {
  Add-Content -LiteralPath $logFile -Value "[$(Get-Date -Format o)] Conector Wazuh iniciado."
  Push-Location $projectDir
  try {
    $previousErrorAction = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    & $PnpmPath connector:run *>> $logFile
    $exitCode = $LASTEXITCODE
    $ErrorActionPreference = $previousErrorAction
    Add-Content -LiteralPath $logFile -Value "[$(Get-Date -Format o)] Conector terminou com código $exitCode; nova tentativa em 30 segundos."
  } catch {
    $ErrorActionPreference = $previousErrorAction
    $errorMessage = $_.Exception.Message
    foreach ($name in $allowedNames) {
      $secret = [Environment]::GetEnvironmentVariable($name, "Process")
      if ($secret -and $name -match "KEY|TOKEN|PASSWORD" -and $errorMessage.Contains($secret)) {
        $errorMessage = $errorMessage.Replace($secret, "[REDACTED]")
      }
    }
    Add-Content -LiteralPath $logFile -Value "[$(Get-Date -Format o)] Falha ao iniciar o conector ($($_.Exception.GetType().Name)): $errorMessage"
  } finally {
    Pop-Location
  }
  Start-Sleep -Seconds 30
}
