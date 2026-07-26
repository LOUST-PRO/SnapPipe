<#
.SYNOPSIS
    Installs the SnapPipe TCP-over-QUIC tunnel client on a Windows laptop.

.DESCRIPTION
    Sets up a per-user Scheduled Task that runs `snappipe.exe tunnel connect`
    on logon, exposing 127.0.0.1:25566 to local applications (e.g.
    TLauncher, Prism). The tunnel wraps every TCP byte inside QUIC streams
    to the operator's relay, bypassing restrictive ISP port filters
    (Infinitum AS8151 / Telmex / etc. drop 25565/25566 outbound).

    Prerequisite: the user has received a signed ticket file from the
    operator. Drop it next to this script as `friend.ticket.json` and
    `friend.secret` (Ed25519, base64url, single-line) before running.

.PARAMETER RelayHost
    Operator's relay host (e.g. 167.88.38.25). Do NOT include :port.

.PARAMETER ListenPort
    Local TCP port exposed for Minecraft clients. Default 25566.

.PARAMETER TcpBackendHost
    Local TCP host exposed to the Minecraft client. Default 127.0.0.1.

.EXAMPLE
    .\snappipe-tunnel-client.ps1 -RelayHost "167.88.38.25" -ListenPort 25566
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$RelayHost,

    [Parameter(Mandatory = $false)]
    [int]$ListenPort = 25566,

    [Parameter(Mandatory = $false)]
    [string]$TcpBackendHost = "127.0.0.1"
)

$ErrorActionPreference = "Stop"

$BinDir      = "$env:LOCALAPPDATA\Programs\SnapPipe"
$BinPath     = "$BinDir\snappipe.exe"
$ConfigDir   = "$env:USERPROFILE\snappipe"
$TicketPath  = "$ConfigDir\friend.ticket.json"
$SecretPath  = "$ConfigDir\friend.secret"
$RelayPort   = "4443"
$TaskName    = "SnapPipeTunnelClient"

function Test-Command([string]$name) {
    if (-not (Get-Command $name -ErrorAction SilentlyContinue)) {
        throw "Required command not found: $name"
    }
}

function Ensure-Directory([string]$path) {
    if (-not (Test-Path $path)) {
        New-Item -ItemType Directory -Force -Path $path | Out-Null
    }
}

function Test-OutboundFirewall {
    # Friendly nudge: ask Windows if UDP/4443 outbound is blocked. If the
    # user has Group Policy enforcing egress, we cannot auto-allow it.
    $rule = Get-NetFirewallRule -DisplayName "SnapPipe QUIC" `
        -ErrorAction SilentlyContinue
    if (-not $rule) {
        Write-Host "Adding outbound firewall rule for UDP/$RelayPort ..." -ForegroundColor Yellow
        New-NetFirewallRule -DisplayName "SnapPipe QUIC" `
            -Direction Outbound `
            -Protocol UDP `
            -RemotePort $RelayPort `
            -Action Allow `
            -Profile Any `
            -ErrorAction SilentlyContinue | Out-Null
    } else {
        Write-Host "Outbound firewall rule 'SnapPipe QUIC' already present." -ForegroundColor Green
    }
}

try {
    Test-Command "Get-NetFirewallRule"
    Ensure-Directory $BinDir
    Ensure-Directory $ConfigDir

    if (-not (Test-Path $BinPath)) {
        throw "snappipe.exe not found at $BinPath. Download it first from `https://github.com/LOUST-PRO/SnapPipe/releases`."
    }
    if (-not (Test-Path $TicketPath)) {
        throw "Ticket file missing at $TicketPath. Ask the operator for `friend.ticket.json`."
    }
    if (-not (Test-Path $SecretPath)) {
        throw "Secret key file missing at $SecretPath. Save your Ed25519 secret (single-line, base64url) as `friend.secret`."
    }

    Test-OutboundFirewall

    # Build the action.
    $arguments = @(
        "tunnel", "connect",
        "--secret-key", "`"$SecretPath`"",
        "--ticket", "`"$TicketPath`"",
        "--relay", "`"$RelayHost`:$RelayPort`"",
        "--listen", "`"$TcpBackendHost`:$ListenPort`""
    )
    $argumentString = $arguments -join " "

    $action = New-ScheduledTaskAction -Execute $BinPath -Argument $argumentString
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)

    Register-ScheduledTask -TaskName $TaskName `
        -Action $action `
        -Trigger $trigger `
        -Settings $settings `
        -User $env:USERNAME `
        -RunLevel "Limited" `
        -Description "SnapPipe TCP tunnel: $TcpBackendHost`:$ListenPort -> QUIC $RelayHost`:$RelayPort" `
        -Force | Out-Null

    Write-Host ""
    Write-Host "SnapPipe tunnel client installed." -ForegroundColor Green
    Write-Host "  Listening on: $TcpBackendHost`:$ListenPort"
    Write-Host "  Tunneled to:  $RelayHost`:$RelayPort (QUIC/UDP)"
    Write-Host "  Task:         $TaskName (runs at logon)"
    Write-Host ""
    Write-Host "Start it now:" -ForegroundColor Cyan
    Write-Host "  Start-ScheduledTask -TaskName $TaskName"
    Write-Host "Inspect logs:" -ForegroundColor Cyan
    Write-Host "  Get-ScheduledTaskInfo -TaskName $TaskName"
}
catch {
    Write-Error $_
    exit 1
}