$ErrorActionPreference = "Stop"
$taskName = "PierVuln Wazuh Connector"
$runner = Join-Path $PSScriptRoot "run-local.ps1"
$envFile = Join-Path $PSScriptRoot ".env"
$caFile = Join-Path $PSScriptRoot "certs\indexer-ca.pem"
$userId = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

if (-not (Test-Path -LiteralPath $envFile)) { throw "Copie connector/.env.example para connector/.env e configure a conexão Wazuh." }
if (-not (Test-Path -LiteralPath $caFile)) { throw "Adicione o certificado da CA em connector/certs/indexer-ca.pem." }

$existing = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($existing -and -not (@($existing.Actions | Where-Object { $_.Arguments -and $_.Arguments.Contains($runner) }).Count)) {
  throw "Já existe uma tarefa '$taskName' com outra ação; ela foi mantida sem alteração."
}

$powershell = Join-Path $PSHOME "powershell.exe"
$pnpmPath = (Get-Command "pnpm.cmd" -ErrorAction Stop).Source
$nodePath = (Get-Command "node.exe" -ErrorAction Stop).Source
$actionArgs = "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$runner`" -PnpmPath `"$pnpmPath`" -NodePath `"$nodePath`""
$action = New-ScheduledTaskAction -Execute $powershell -Argument $actionArgs -WorkingDirectory (Split-Path -Parent $PSScriptRoot)
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $userId
$principal = New-ScheduledTaskPrincipal -UserId $userId -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero)

Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description "Mantém o conector Wazuh do PierVuln ativo enquanto o usuário está conectado." -Force | Out-Null
Start-ScheduledTask -TaskName $taskName
Write-Output "Tarefa '$taskName' instalada e iniciada. Logs: connector/logs/connector.log"
