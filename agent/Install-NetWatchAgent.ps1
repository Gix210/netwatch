<#
.SYNOPSIS
  Agent NetWatch pour les PC de l'entreprise (à exécuter en administrateur sur chaque PC).

.DESCRIPTION
  - Crée la tâche planifiée « NetWatch Agent » (à l'ouverture de session, puis toutes les 5 minutes) qui
    signale au serveur NetWatch le nom du PC, l'utilisateur connecté, l'adresse IP/MAC, les serveurs DNS
    utilisés et l'état des politiques anti-contournement. Aucune capture d'écran, aucune frappe clavier.
  - Désactive le DNS chiffré (DoH) dans Chrome, Edge, Firefox et Windows (stratégies locales) pour que le
    filtre réseau ne puisse pas être contourné.
  - Par défaut laisse le DNS fourni par le DHCP ; -DnsMode Static force le serveur NetWatch comme DNS.

.EXAMPLE
  .\Install-NetWatchAgent.ps1 -Server 192.168.1.11 -Port 8795 -Token <jeton>
  .\Install-NetWatchAgent.ps1 -Uninstall
#>
param(
    [string]$Server,
    [int]$Port = 8795,
    [string]$Token,
    [ValidateSet('Dhcp', 'Static')][string]$DnsMode = 'Dhcp',
    [switch]$NoPolicies,
    [switch]$Uninstall
)
$ErrorActionPreference = 'Stop'
$Dir = 'C:\ProgramData\NetWatch'
$TaskName = 'NetWatch Agent'
$Version = '1.0.0'

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Error "Ouvrez PowerShell « en tant qu'administrateur » puis relancez ce script."; exit 1 }

$policies = @(
    @{ Path = 'HKLM:\SOFTWARE\Policies\Google\Chrome';            Name = 'DnsOverHttpsMode'; Value = 'off'; Type = 'String' },
    @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge';           Name = 'DnsOverHttpsMode'; Value = 'off'; Type = 'String' },
    @{ Path = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS'; Name = 'Enabled'; Value = 0; Type = 'DWord' },
    @{ Path = 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS'; Name = 'Locked';  Value = 1; Type = 'DWord' },
    @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'; Name = 'DoHPolicy'; Value = 1; Type = 'DWord' }
)

if ($Uninstall) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    foreach ($p in $policies) { if (Test-Path $p.Path) { Remove-ItemProperty -Path $p.Path -Name $p.Name -ErrorAction SilentlyContinue } }
    if (Test-Path "$Dir\static-dns.flag") {
        Get-NetAdapter -Physical | Where-Object Status -eq 'Up' | ForEach-Object { Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ResetServerAddresses }
    }
    Remove-Item -Recurse -Force $Dir -ErrorAction SilentlyContinue
    Write-Host 'Agent NetWatch désinstallé (tâche, politiques DoH et dossier retirés).'
    exit 0
}
if (-not $Server -or -not $Token) { Write-Error 'Paramètres -Server et -Token requis : voir la page « PC (agents) » de NetWatch.'; exit 1 }

New-Item -ItemType Directory -Force -Path $Dir | Out-Null
@{ server = $Server; port = $Port; token = $Token; version = $Version } | ConvertTo-Json | Set-Content -Path "$Dir\agent.json" -Encoding UTF8

$heartbeat = @'
# NetWatch Agent : signale ce PC au serveur NetWatch (exécuté par la tâche planifiée « NetWatch Agent »).
$ErrorActionPreference = 'SilentlyContinue'
$cfg = Get-Content 'C:\ProgramData\NetWatch\agent.json' -Raw | ConvertFrom-Json
$route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 | Sort-Object RouteMetric | Select-Object -First 1
$if = $route.ifIndex
$ip = (Get-NetIPAddress -InterfaceIndex $if -AddressFamily IPv4 | Where-Object PrefixOrigin -ne 'WellKnown' | Select-Object -First 1).IPAddress
$mac = (Get-NetAdapter -InterfaceIndex $if).MacAddress
$dns = @((Get-DnsClientServerAddress -InterfaceIndex $if -AddressFamily IPv4).ServerAddresses)
$ips = @(Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } | Select-Object -ExpandProperty IPAddress)
$os = Get-CimInstance Win32_OperatingSystem
$uptime = [int]((Get-Date) - $os.LastBootUpTime).TotalMinutes
$chrome = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Google\Chrome' -Name DnsOverHttpsMode).DnsOverHttpsMode
$win = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name DoHPolicy).DoHPolicy
$doh = ($chrome -eq 'off') -and ($win -eq 1)
$body = @{ host = $env:COMPUTERNAME; user = $env:USERNAME; ip = $ip; mac = $mac; dns = $dns; ips = $ips; os = $os.Caption;
           uptime_min = $uptime; version = $cfg.version; doh_policy = [bool]$doh } | ConvertTo-Json -Compress
$bytes = [System.Text.Encoding]::UTF8.GetBytes($body)
Invoke-RestMethod -Uri "http://$($cfg.server):$($cfg.port)/api/agent/heartbeat" -Method Post -ContentType 'application/json; charset=utf-8' `
    -Headers @{ 'X-NetWatch-Token' = $cfg.token } -Body $bytes -TimeoutSec 10 | Out-Null
'@
Set-Content -Path "$Dir\heartbeat.ps1" -Value $heartbeat -Encoding UTF8

if (-not $NoPolicies) {
    foreach ($p in $policies) {
        New-Item -Path $p.Path -Force | Out-Null
        New-ItemProperty -Path $p.Path -Name $p.Name -Value $p.Value -PropertyType $p.Type -Force | Out-Null
    }
    Write-Host 'Politiques appliquées : DNS chiffré (DoH) désactivé dans Chrome, Edge, Firefox et Windows.'
}

if ($DnsMode -eq 'Static') {
    Get-NetAdapter -Physical | Where-Object Status -eq 'Up' | ForEach-Object {
        Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ServerAddresses $Server
    }
    Set-Content -Path "$Dir\static-dns.flag" -Value 'static'
    Write-Host "DNS forcé vers $Server sur les cartes réseau actives."
} else {
    Write-Host 'DNS laissé au DHCP (le serveur DHCP doit distribuer NetWatch comme serveur DNS).'
}

$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$Dir\heartbeat.ps1`""
$trigLogon = New-ScheduledTaskTrigger -AtLogOn
$trigRepeat = New-ScheduledTaskTrigger -Once -At (Get-Date).Date -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration (New-TimeSpan -Days 3650)
$principal = New-ScheduledTaskPrincipal -GroupId 'BUILTIN\Users' -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 2) -Hidden
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger @($trigLogon, $trigRepeat) -Principal $principal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName
Write-Host "Agent NetWatch $Version installé : tâche « $TaskName » créée, premier signalement envoyé à http://$Server`:$Port/."
