<#
.SYNOPSIS
  Installe (ou met à jour) NetWatch sur le serveur (SRV-APP) : copie dans C:\NetWatch, règles de pare-feu,
  tâche planifiée « NetWatch » au démarrage (compte SYSTEM, redémarrage automatique).

.EXAMPLE
  .\install.ps1                 # installation ou mise à jour (les données de C:\NetWatch\data sont conservées)
  .\install.ps1 -Uninstall      # retire la tâche et les règles de pare-feu (le dossier est conservé)
#>
param(
    [string]$Dest = 'C:\NetWatch',
    [switch]$NoFirewall,
    [switch]$NoStart,
    [switch]$Uninstall
)
$ErrorActionPreference = 'Stop'
$TaskName = 'NetWatch'
$Rules = @(
    @{ Name = 'NetWatch DNS (UDP 53)'; Protocol = 'UDP'; Port = 53 },
    @{ Name = 'NetWatch DNS (TCP 53)'; Protocol = 'TCP'; Port = 53 },
    @{ Name = 'NetWatch Web (TCP 8795)'; Protocol = 'TCP'; Port = 8795 },
    @{ Name = 'NetWatch page de blocage (TCP 80)'; Protocol = 'TCP'; Port = 80 }
)

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Error "Ouvrez PowerShell « en tant qu'administrateur » puis relancez ce script."; exit 1 }

if ($Uninstall) {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    foreach ($r in $Rules) { Remove-NetFirewallRule -DisplayName $r.Name -ErrorAction SilentlyContinue }
    Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like "*$Dest\netwatch.py*" } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    Write-Host "NetWatch désinstallé. Le dossier $Dest (données, config.json) est conservé ; supprimez-le à la main si voulu."
    exit 0
}

# --- copie ------------------------------------------------------------------------
# The package carries its own Python in .\python: nothing to install first.
$src = $PSScriptRoot
if ([IO.Path]::GetFullPath($src).TrimEnd('\') -ne [IO.Path]::GetFullPath($Dest).TrimEnd('\')) {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like "*$Dest\netwatch.py*" } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    Start-Sleep -Seconds 2
    New-Item -ItemType Directory -Force -Path $Dest | Out-Null
    robocopy $src $Dest /E /XD data data-test .git .claude qa __pycache__ /XF *.pyc config.json /NFL /NDL /NJH /NJS /NP | Out-Null
    if ($LASTEXITCODE -ge 8) { Write-Error "Copie vers $Dest échouée (robocopy $LASTEXITCODE)."; exit 1 }
    Write-Host "Fichiers copiés dans $Dest (data et config.json conservés)."
}

# --- Python ---------------------------------------------------------------
$python = $null
foreach ($cand in @("$Dest\python\python.exe")) {
    if (Test-Path $cand) { $python = $cand; break }
}
if (-not $python) {
    $c = Get-Command python.exe -ErrorAction SilentlyContinue | Where-Object { $_.Source -notlike '*\WindowsApps\*' } | Select-Object -First 1
    if ($c) { $python = $c.Source }
}
if (-not $python) { Write-Error 'Python introuvable : le dossier python\ du paquet manque. Recopiez le paquet complet.'; exit 1 }
$ver = (& $python -c "import sys; print('%d.%d' % sys.version_info[:2])").Trim()
if ([version]$ver -lt [version]'3.9') { Write-Error "Python $ver trouvé ; 3.9 ou plus récent requis."; exit 1 }
$pythonw = Join-Path (Split-Path $python) 'pythonw.exe'
if (-not (Test-Path $pythonw)) { $pythonw = $python }
Write-Host "Python $ver : $pythonw"

# --- vérification du port 53 ----------------------------------------------------------
$udp53 = Get-NetUDPEndpoint -LocalPort 53 -ErrorAction SilentlyContinue | Select-Object -First 1
if ($udp53) {
    $proc = Get-Process -Id $udp53.OwningProcess -ErrorAction SilentlyContinue
    if (-not ($proc -and $proc.ProcessName -like 'python*')) {
        Write-Warning "Le port UDP 53 est déjà utilisé par $($proc.ProcessName) (PID $($udp53.OwningProcess)). NetWatch ne pourra pas écouter le DNS tant que ce service tourne."
    }
}

# --- pare-feu ---------------------------------------------------------------------------
if (-not $NoFirewall) {
    foreach ($r in $Rules) {
        Remove-NetFirewallRule -DisplayName $r.Name -ErrorAction SilentlyContinue
        New-NetFirewallRule -DisplayName $r.Name -Direction Inbound -Protocol $r.Protocol -LocalPort $r.Port -Action Allow -Profile Any | Out-Null
    }
    Write-Host 'Règles de pare-feu créées (UDP/TCP 53, TCP 8795, TCP 80).'
}

# --- tâche planifiée ----------------------------------------------------------------------
$action = New-ScheduledTaskAction -Execute $pythonw -Argument "`"$Dest\netwatch.py`" --service" -WorkingDirectory $Dest
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -RestartCount 99 -RestartInterval (New-TimeSpan -Minutes 1) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew
$settings.ExecutionTimeLimit = 'PT0S'
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
if (-not $NoStart) {
    Start-ScheduledTask -TaskName $TaskName
    Start-Sleep -Seconds 4
}
$ip = (Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway } | Select-Object -First 1).IPv4Address.IPAddress
Write-Host ''
Write-Host "NetWatch installé. Tâche « $TaskName » (SYSTEM, au démarrage, relance automatique). Journal : $Dest\data\netwatch.log"
Write-Host "Interface : http://$ip`:8795/   (premier démarrage : choisir le mot de passe administrateur)"
Write-Host 'Étape suivante : dans le DHCP (DC01), mettre l''option 006 « Serveurs DNS » = adresse de ce serveur, puis ipconfig /renew sur un PC pour tester.'
