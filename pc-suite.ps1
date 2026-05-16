<#
.SYNOPSIS
    PC Security Suite - Komplexni nastroj pro zabezpeceni domaciho PC s Windows 10/11.
.DESCRIPTION
    Integruje tri moduly v jednom skriptu:
      - Modul 1: Zabezpeceni (Hardening)
          ASR pravidla, Defender, SmartScreen, Firewall, Sysmon, DNS,
          LSA PPL, WDigest, NTLMv2, NetBIOS, WSH, UAC, Event log velikost,
          Windows Update, Winget aktualizace, BitLocker a dalsi...
      - Modul 2: Monitoring a Audit
          Security events, failed/successful logons, kriticke udalosti,
          persistence mechanismy, suspektni procesy, DNS cache, Sysmon
          parent-child detekce, export dat, PowerShell/CMD/WMI monitoring...
      - Modul 3: Application Whitelisting (WDAC + Makra)
          WDAC politiky (audit/enforce), vlastni pravidla, WDAC Wizard,
          Office macro whitelisting, Trusted Locations/Publishers,
          PowerShell Constrained Language Mode...
.AUTHOR
    Mischa Princ
.NOTES
    Spoustejte jako Administrator.
    Kompatibilni s Windows 10/11. WDAC vyzaduje Pro edici nebo vyssi.
#>

# ==============================================================================
#                     K O N T R O L A   A D M I N A
# ==============================================================================
if (-not ([bool]([Security.Principal.WindowsIdentity]::GetCurrent().Groups -match 'S-1-5-32-544'))) {
    Write-Host ""
    Write-Host "  +===========================================================+" -ForegroundColor Red
    Write-Host "  |   CHYBA: Tento skript musi byt spusten jako ADMINISTRATOR! |" -ForegroundColor Red
    Write-Host "  +===========================================================+" -ForegroundColor Red
    Write-Host ""
    Write-Host "  Kliknete pravym tlacitkem na PowerShell -> Spustit jako spravce" -ForegroundColor Yellow
    Write-Host ""
    Read-Host "  Stisknete Enter pro ukonceni"
    exit 1
}

# Aktivni modul - prepina se pri prechodu do modulu (pouziva Show-Banner)
$script:ActiveMode = ""

# QuickNav: fronta automaticky predvolenych voleb (x-kod navigace)
$script:QNPath = @()

# ==============================================================================
#                   P O M O C N E   F U N K C E   ( S D I L E N E )
# ==============================================================================
function Write-Header {
    param([string]$Text)
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
}

function Write-SubHeader {
    param([string]$Title, [string]$Description)
    Write-Host ""
    Write-Host "  +------------------------------------------------------------+" -ForegroundColor Cyan
    Write-Host "  |  $($Title.PadRight(58))|" -ForegroundColor Cyan
    Write-Host "  +------------------------------------------------------------+" -ForegroundColor Cyan
    if ($Description) {
        foreach ($line in $Description -split "`n") {
            Write-Host "  $line" -ForegroundColor DarkGray
        }
    }
    Write-Host ""
}

function Write-Status {
    param([string]$Label, [string]$Value, [ConsoleColor]$Color = 'Yellow')
    $padded = $Label.PadRight(30)
    Write-Host "  $padded : " -NoNewline
    Write-Host $Value -ForegroundColor $Color
}

function Write-MenuItem {
    param([string]$Key, [string]$Text, [ConsoleColor]$Color = 'White')
    $padKey = $Key.PadLeft(4)
    Write-Host "    ${padKey})  $Text" -ForegroundColor $Color
}

function Pause-Menu {
    Write-Host ""
    Read-Host "Stiskni Enter pro pokracovani"
}

# QuickNav: pokud je QNPath neprazdna, vezme prvni prvek; jinak standardni Read-Host
function Read-MenuChoice {
    param([string]$Prompt = "  Vyberte volbu")
    if ($script:QNPath.Count -gt 0) {
        $choice = $script:QNPath[0]
        $script:QNPath = if ($script:QNPath.Count -gt 1) {
            $script:QNPath[1..($script:QNPath.Count - 1)]
        } else { @() }
        Write-Host "${Prompt}: $choice  [QuickNav]" -ForegroundColor DarkGray
        return $choice
    }
    return Read-Host $Prompt
}

function Show-Banner {
    Clear-Host
    Write-Host ""
    Write-Host "  +============================================================+" -ForegroundColor Cyan
    switch ($script:ActiveMode) {
        "SECURE"    { Write-Host "  |       ZABEZPECENI DOMACIHO PC - Interaktivni nastroj      |" -ForegroundColor Cyan }
        "MONITOR"   { Write-Host "  |      MONITORING DOMACIHO PC - Interaktivni nastroj         |" -ForegroundColor Cyan }
        "APPLOCKER" { Write-Host "  |  APPLICATION + MACRO WHITELISTING - Interaktivni nastroj   |" -ForegroundColor Cyan }
        default     { Write-Host "  |         PC SECURITY SUITE - Interaktivni nastroj            |" -ForegroundColor Cyan }
    }
    Write-Host "  |                   vytvoril: Mischa Princ                   |" -ForegroundColor DarkCyan
    Write-Host "  +============================================================+" -ForegroundColor Cyan
}

# ==============================================================================
#   M O D U L   1 :   Z A B E Z P E C E N I   ( H A R D E N I N G )
# ==============================================================================
# ==============================================================================
#          D E F I N I C E   A S R   P R A V I D E L
# ==============================================================================
$ASR_RULES = [ordered]@{
    "56a863a9-875e-4185-98a7-b882c64b5ce5" = "Blokovat zneuziti zranitelnych podepsanych ovladacu"
    "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" = "Blokovat Adobe Reader - vytvareni podprocesy"
    "d4f940ab-401b-4efc-aadc-ad5f3c50688a" = "Blokovat Office - vytvareni podprocesy"
    "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" = "Blokovat kradez prihlasovacich udaju z LSASS"
    "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550" = "Blokovat spustitelny obsah z e-mailu a webmailu"
    "01443614-cd74-433a-b99e-2ecdc07bfc25" = "Blokovat exe pokud nesplnuji kriteria (prevalence/vek)"
    "5beb7efe-fd9a-4556-801d-275e5ffc04cc" = "Blokovat spousteni potencialne obfuskovanych skriptu"
    "d3e037e1-3eb8-44c8-a917-57927947596d" = "Blokovat JS/VBS spousteni stazeneho obsahu"
    "3b576869-a4ec-4529-8536-b80a7769e899" = "Blokovat Office - vytvareni spustitelneho obsahu"
    "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84" = "Blokovat Office - injektovani kodu do jinych procesu"
    "26190899-1602-49e8-8b27-eb1d0a1ce869" = "Blokovat Office komunikacni app - podprocesy"
    "e6db77e5-3df2-4cf1-b95a-636979351e5b" = "Blokovat persistenci pres WMI event subscription"
    "d1e49aac-8f56-4280-b9ba-993a6d77406c" = "Blokovat vytvareni procesu z PSExec a WMI prikazu"
    "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" = "Blokovat neduveryhodne/nepodepsane procesy z USB"
    "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b" = "Blokovat Win32 API volani z Office maker"
    "c1db55ab-c21a-4637-bb3f-a12568109d35" = "Blokovat predstirani systemovych nastroju"
    "a8f5898e-1dc8-49a9-9878-85004b8a61e6" = "Blokovat Webshell vytvareni pro servery"
    "c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb" = "Blokovat zneuziti zranitelnych ovladacu (rozsirene)"
}

# ==============================================================================
#      G E T / S H O W / S E T   -   D E F E N D E R
# ==============================================================================

# -- ASR ----------------------------------------------------------------------
function Get-ASRStatus {
    try {
        $pref = Get-MpPreference
        $ids     = $pref.AttackSurfaceReductionRules_Ids
        $actions = $pref.AttackSurfaceReductionRules_Actions
        $result = @{}
        if ($ids) {
            for ($i = 0; $i -lt $ids.Count; $i++) {
                $result[$ids[$i].ToLower()] = $actions[$i]
            }
        }
        return $result
    } catch {
        Write-Host "  CHYBA: Nelze ziskat stav ASR pravidel." -ForegroundColor Red
        return @{}
    }
}

function Get-ASRSummary {
    $current = Get-ASRStatus
    $total   = $ASR_RULES.Count
    $blocked = ($current.Values | Where-Object { $_ -eq 1 }).Count
    $audit   = ($current.Values | Where-Object { $_ -eq 2 }).Count
    $off     = $total - $blocked - $audit
    return "Blok: $blocked | Audit: $audit | Vyp: $off ($total celkem)"
}

function Show-ASRDetail {
    Write-Header "Stav ASR pravidel"
    $current = Get-ASRStatus
    $modeMap = @{ 0 = "Vypnuto"; 1 = "Blokovat"; 2 = "Audit"; 6 = "Varovani" }
    foreach ($guid in $ASR_RULES.Keys) {
        $action = if ($current.ContainsKey($guid)) { $current[$guid] } else { 0 }
        $modeText = if ($modeMap.ContainsKey([int]$action)) { $modeMap[[int]$action] } else { "Neznamy ($action)" }
        $color = switch ([int]$action) {
            0 { 'Red' }
            1 { 'Green' }
            2 { 'Yellow' }
            6 { 'DarkYellow' }
            default { 'Gray' }
        }
        Write-Host "  [$modeText]" -ForegroundColor $color -NoNewline
        Write-Host " $($ASR_RULES[$guid])" -ForegroundColor White
    }
}

function Set-AllASR {
    param([int]$Mode)
    $modeMap = @{ 0 = "Vypnuto"; 1 = "Blokovat"; 2 = "Audit" }
    Write-Host ""
    Write-Host "  Nastavuji vsechna ASR pravidla na: $($modeMap[$Mode]) ..." -ForegroundColor Yellow

    # Vsechna pravidla najednou v jednom volani - jinak Set-MpPreference prepise predchozi
    $allIds     = [string[]]@($ASR_RULES.Keys)
    $allActions = [int[]]@($Mode) * $allIds.Count

    try {
        Set-MpPreference -AttackSurfaceReductionRules_Ids $allIds -AttackSurfaceReductionRules_Actions $allActions -ErrorAction Stop
        foreach ($guid in $ASR_RULES.Keys) {
            Write-Host "    [OK] $($ASR_RULES[$guid])" -ForegroundColor Green
        }
    } catch {
        Write-Host "    [CHYBA] $_" -ForegroundColor Red
        # Fallback - zkusit po jednom pres Add-MpPreference
        Write-Host "  Zkousim alternativni metodu (Add-MpPreference) ..." -ForegroundColor Yellow
        foreach ($guid in $ASR_RULES.Keys) {
            try {
                Add-MpPreference -AttackSurfaceReductionRules_Ids $guid -AttackSurfaceReductionRules_Actions $Mode -ErrorAction Stop
                Write-Host "    [OK] $($ASR_RULES[$guid])" -ForegroundColor Green
            } catch {
                Write-Host "    [CHYBA] $($ASR_RULES[$guid]): $_" -ForegroundColor Red
            }
        }
    }
    Write-Host "  Hotovo." -ForegroundColor Green
}

# -- PUA ----------------------------------------------------------------------
function Get-PUAStatus {
    try {
        $pua = (Get-MpPreference).PUAProtection
        switch ($pua) { 0 { "Vypnuto" } 1 { "Blokovat" } 2 { "Audit" } default { "Neznamy ($pua)" } }
    } catch { "Chyba" }
}

function Set-PUA {
    param([int]$Mode)
    $modeMap = @{ 0 = "Vypnuto"; 1 = "Blokovat"; 2 = "Audit" }
    try {
        Set-MpPreference -PUAProtection $Mode -ErrorAction Stop
        Write-Host "  PUA ochrana nastavena na: $($modeMap[$Mode])" -ForegroundColor Green
    } catch { Write-Host "  CHYBA: $_" -ForegroundColor Red }
}

# -- Defender Real-Time + Cloud ------------------------------------------------
function Get-DefenderRTStatus {
    try {
        $pref  = Get-MpPreference
        $rt    = -not $pref.DisableRealtimeMonitoring
        $cloud = -not ($pref.MAPSReporting -eq 0)
        $auto  = -not ($pref.SubmitSamplesConsent -eq 0)
        $parts = @()
        if ($rt)    { $parts += "RealTime" }
        if ($cloud) { $parts += "Cloud" }
        if ($auto)  { $parts += "Samples" }
        if ($parts.Count -eq 3) { "Vse zapnuto" }
        elseif ($parts.Count -eq 0) { "Vse vypnuto" }
        else { $parts -join " + " }
    } catch { "Neznamy" }
}

function Set-DefenderRT {
    param([bool]$Enabled)
    try {
        if ($Enabled) {
            Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop
            Set-MpPreference -MAPSReporting Advanced -ErrorAction Stop
            Set-MpPreference -SubmitSamplesConsent SendAllSamples -ErrorAction Stop
            Write-Host "  Defender Real-Time + Cloud + Samples: Zapnuto" -ForegroundColor Green
        } else {
            Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction Stop
            Write-Host "  Defender Real-Time: Vypnuto (POZOR!)" -ForegroundColor Red
        }
    } catch { Write-Host "  CHYBA: $_" -ForegroundColor Red }
}

# -- Controlled Folder Access -------------------------------------------------
function Get-CFAStatus {
    try {
        $cfa = (Get-MpPreference).EnableControlledFolderAccess
        switch ($cfa) { 0 { "Vypnuto" } 1 { "Zapnuto" } 2 { "Audit" } default { "Neznamy ($cfa)" } }
    } catch { "Neznamy" }
}

function Set-CFA {
    param([int]$Mode)
    $modeMap = @{ 0 = "Vypnuto"; 1 = "Zapnuto"; 2 = "Audit" }
    try {
        Set-MpPreference -EnableControlledFolderAccess $Mode -ErrorAction Stop
        Write-Host "  Controlled Folder Access: $($modeMap[$Mode])" -ForegroundColor Green
    } catch { Write-Host "  CHYBA: $_" -ForegroundColor Red }
}

# -- Tamper Protection ---------------------------------------------------------
function Get-TamperProtectionStatus {
    try {
        $tp = (Get-MpComputerStatus -ErrorAction Stop).IsTamperProtected
        if ($tp) { "Zapnuto" } else { "Vypnuto" }
    } catch {
        try {
            $val = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features" -Name "TamperProtection" -ErrorAction Stop).TamperProtection
            switch ($val) { 5 { "Zapnuto" } 4 { "Vypnuto" } 0 { "Vypnuto" } default { "Neznamy ($val)" } }
        } catch { "Neznamy" }
    }
}

function Set-TamperProtection {
    param([bool]$Enabled)
    $requestedState = if ($Enabled) { "Zapnuto" } else { "Vypnuto" }
    Write-Host "  Tamper Protection nelze spolehlive menit timto skriptem." -ForegroundColor Yellow
    Write-Host "  Pozadovany stav: $requestedState" -ForegroundColor DarkGray
    Write-Host "  Nastavte rucne: Windows Zabezpeceni > Ochrana pred viry a hrozbami > Spravovat nastaveni." -ForegroundColor Yellow
    if (-not $Enabled) {
        Write-Host "  VAROVANI: Vypnuti Tamper Protection snizuje odolnost Defenderu proti manipulaci." -ForegroundColor Red
    }
}

# ==============================================================================
#         G E T / S E T   -   S M A R T S C R E E N
# ==============================================================================
function Get-SmartScreenStatus {
    try {
        $val = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -ErrorAction Stop).SmartScreenEnabled
        switch ($val) { "RequireAdmin" { "Zapnuto (RequireAdmin)" } "Prompt" { "Zapnuto (Prompt)" } "Off" { "Vypnuto" } default { $val } }
    } catch { "Neznamy" }
}

function Set-SmartScreen {
    param([string]$Mode)
    try {
        Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Value $Mode -ErrorAction Stop
        Write-Host "  SmartScreen (Windows): $Mode" -ForegroundColor Green
    } catch { Write-Host "  CHYBA: $_" -ForegroundColor Red }
}

function Get-EdgeSmartScreenStatus {
    try {
        $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
        if (-not (Test-Path $regPath)) { return "Nenastaveno (politika)" }
        $val = Get-ItemProperty -Path $regPath -Name "SmartScreenEnabled" -ErrorAction SilentlyContinue
        if ($null -eq $val -or $null -eq $val.SmartScreenEnabled) { return "Nenastaveno (politika)" }
        if ($val.SmartScreenEnabled -eq 1) { "Zapnuto" } else { "Vypnuto" }
    } catch { "Neznamy" }
}

function Set-EdgeSmartScreen {
    param([bool]$Enabled)
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    try {
        if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
        $val = if ($Enabled) { 1 } else { 0 }
        Set-ItemProperty -Path $regPath -Name "SmartScreenEnabled" -Value $val -Type DWord -ErrorAction Stop
        $state = if ($Enabled) { "Zapnuto" } else { "Vypnuto" }
        Write-Host "  SmartScreen (Edge): $state" -ForegroundColor Green
    } catch { Write-Host "  CHYBA: $_" -ForegroundColor Red }
}

# ==============================================================================
#         G E T / S E T   -   S I T   a   P R O T O K O L Y
# ==============================================================================
function Get-FirewallStatus {
    try {
        $profiles = Get-NetFirewallProfile -ErrorAction Stop
        $allOn = ($profiles | Where-Object { $_.Enabled -eq $true }).Count -eq $profiles.Count
        if ($allOn) { "Zapnuto (vsechny profily)" }
        else {
            $on = ($profiles | Where-Object { $_.Enabled }).Name -join ", "
            if ($on) { "Castecne ($on)" } else { "Vypnuto" }
        }
    } catch { "Neznamy" }
}

function Set-FirewallState {
    param([bool]$Enabled)
    try {
        $gpoVal = if ($Enabled) { [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.GpoBoolean]::True } else { [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.GpoBoolean]::False }
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled $gpoVal -ErrorAction Stop
        $state = if ($Enabled) { "Zapnuto" } else { "Vypnuto" }
        Write-Host "  Windows Firewall: $state (vsechny profily)" -ForegroundColor Green
    } catch { Write-Host "  CHYBA: $_" -ForegroundColor Red }
}

function Get-RDPStatus {
    try {
        $val = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction Stop).fDenyTSConnections
        if ($val -eq 1) { "Zakazano (bezpecne)" } else { "Povoleno (riziko!)" }
    } catch { "Neznamy" }
}

function Set-RDPState {
    param([bool]$Disabled)
    try {
        $val = if ($Disabled) { 1 } else { 0 }
        Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value $val -Type DWord -ErrorAction Stop
        $state = if ($Disabled) { "Zakazano" } else { "Povoleno" }
        Write-Host "  Vzdalena plocha (RDP): $state" -ForegroundColor Green
        if ($Disabled) { Disable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue }
        else { Enable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue }
    } catch { Write-Host "  CHYBA: $_" -ForegroundColor Red }
}

function Get-SMBv1Status {
    try {
        $smb = Get-SmbServerConfiguration -ErrorAction Stop
        if ($smb.EnableSMB1Protocol) { "Povoleno (riziko!)" } else { "Zakazano (bezpecne)" }
    } catch { "Neznamy" }
}

function Set-SMBv1State {
    param([bool]$Enabled)
    try {
        Set-SmbServerConfiguration -EnableSMB1Protocol $Enabled -Force -ErrorAction Stop
        $state = if ($Enabled) { "Povoleno" } else { "Zakazano" }
        Write-Host "  SMBv1: $state" -ForegroundColor Green
    } catch { Write-Host "  CHYBA: $_" -ForegroundColor Red }
}

function Get-LLMNRStatus {
    try {
        $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
        if (-not (Test-Path $regPath)) { return "Povoleno (vychozi)" }
        $val = Get-ItemProperty -Path $regPath -Name "EnableMulticast" -ErrorAction SilentlyContinue
        if ($null -eq $val -or $val.EnableMulticast -ne 0) { "Povoleno" } else { "Zakazano (bezpecne)" }
    } catch { "Neznamy" }
}

function Set-LLMNRState {
    param([bool]$Disabled)
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
    try {
        if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
        $val = if ($Disabled) { 0 } else { 1 }
        Set-ItemProperty -Path $regPath -Name "EnableMulticast" -Value $val -Type DWord -ErrorAction Stop
        $state = if ($Disabled) { "Zakazano" } else { "Povoleno" }
        Write-Host "  LLMNR: $state" -ForegroundColor Green
    } catch { Write-Host "  CHYBA: $_" -ForegroundColor Red }
}

# ==============================================================================
#         G E T / S E T   -   S Y S T E M
# ==============================================================================
function Get-AutoRunStatus {
    try {
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
        if (-not (Test-Path $regPath)) { return "Povoleno (vychozi)" }
        $val = Get-ItemProperty -Path $regPath -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue
        if ($null -eq $val) { "Povoleno (vychozi)" }
        elseif ($val.NoDriveTypeAutoRun -eq 255) { "Zakazano (bezpecne)" }
        else { "Castecne ($($val.NoDriveTypeAutoRun))" }
    } catch { "Neznamy" }
}

function Set-AutoRunState {
    param([bool]$Disabled)
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    try {
        if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
        if ($Disabled) {
            Set-ItemProperty -Path $regPath -Name "NoDriveTypeAutoRun" -Value 255 -Type DWord -ErrorAction Stop
            Write-Host "  AutoRun/AutoPlay: Zakazano (vsechny disky)" -ForegroundColor Green
        } else {
            Remove-ItemProperty -Path $regPath -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue
            Write-Host "  AutoRun/AutoPlay: Obnoveno na vychozi" -ForegroundColor Yellow
        }
    } catch { Write-Host "  CHYBA: $_" -ForegroundColor Red }
}

function Get-PSLoggingStatus {
    try {
        $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
        if (-not (Test-Path $regPath)) { return "Vypnuto" }
        $val = Get-ItemProperty -Path $regPath -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue
        if ($null -eq $val -or $val.EnableScriptBlockLogging -ne 1) { "Vypnuto" } else { "Zapnuto" }
    } catch { "Neznamy" }
}

function Set-PSLogging {
    param([bool]$Enabled)
    $baseRegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"
    $regPath = Join-Path $baseRegPath "ScriptBlockLogging"
    try {
        if ($Enabled) {
            if (-not (Test-Path $baseRegPath)) { New-Item -Path $baseRegPath -Force | Out-Null }
            New-Item -Path $baseRegPath -Name "ModuleLogging" -Force | Out-Null
            New-Item -Path $baseRegPath -Name "ScriptBlockLogging" -Force | Out-Null
            New-Item -Path $baseRegPath -Name "Transcription" -Force | Out-Null
            Set-ItemProperty -Path (Join-Path $baseRegPath "ModuleLogging") -Name "EnableModuleLogging" -Value 1 -Type DWord -Force -ErrorAction Stop
            Set-ItemProperty -Path $regPath -Name "EnableScriptBlockLogging" -Value 1 -Type DWord -ErrorAction Stop
            Set-ItemProperty -Path (Join-Path $baseRegPath "Transcription") -Name "EnableTranscripting" -Value 1 -Type DWord -Force -ErrorAction Stop
            auditpol /set /subcategory:"{0cce923f-69ae-11d9-bed3-505054503030}" /success:enable /failure:enable | Out-Null
            Write-Host "  PowerShell logging + Process Creation audit: Zapnuto" -ForegroundColor Green
        } else {
            if (Test-Path (Join-Path $baseRegPath "ModuleLogging")) {
                Set-ItemProperty -Path (Join-Path $baseRegPath "ModuleLogging") -Name "EnableModuleLogging" -Value 0 -Type DWord -Force -ErrorAction Stop
            }
            if (Test-Path $regPath) {
                Set-ItemProperty -Path $regPath -Name "EnableScriptBlockLogging" -Value 0 -Type DWord -Force -ErrorAction Stop
            }
            if (Test-Path (Join-Path $baseRegPath "Transcription")) {
                Set-ItemProperty -Path (Join-Path $baseRegPath "Transcription") -Name "EnableTranscripting" -Value 0 -Type DWord -Force -ErrorAction Stop
            }
            auditpol /set /subcategory:"{0cce923f-69ae-11d9-bed3-505054503030}" /success:disable /failure:disable | Out-Null
            Write-Host "  PowerShell logging + Process Creation audit: Vypnuto" -ForegroundColor Yellow
        }
    } catch { Write-Host "  CHYBA: $_" -ForegroundColor Red }
}

# ==============================================================================
#                          S Y S M O N
# ==============================================================================
$SysmonExeUrl     = "https://live.sysinternals.com/Sysmon64.exe"
$SysmonConfigUrl  = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/refs/heads/master/sysmonconfig-export.xml"
$SysmonDir        = "$env:ProgramData\Sysmon"
$SysmonExePath    = "$SysmonDir\Sysmon64.exe"
$SysmonConfigPath = "$SysmonDir\sysmonconfig.xml"
$SysmonCleanupTaskName = "UklidSysmon"
$SysmonCleanupTaskUrl  = "https://raw.githubusercontent.com/MischaPrinc/HomeSecurity/refs/heads/main/UklidSysmon.xml"
$SysmonCleanupXmlPath  = Join-Path $PSScriptRoot "UklidSysmon.xml"

function Get-SysmonStatus {
    $svc = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
    if (-not $svc) { $svc = Get-Service -Name "Sysmon" -ErrorAction SilentlyContinue }
    if ($svc) {
        if ($svc.Status -eq "Running") { "Bezi ($($svc.Name))" }
        else { "Zastaveny ($($svc.Status))" }
    } else { "Nenainstalovan" }
}

function Import-SysmonCleanupTask {
    param(
        [string]$TaskXmlPath = $SysmonCleanupXmlPath
    )

    Write-Host "  Importuji naplanovanou ulohu pro uklid Sysmon slozek..." -ForegroundColor Yellow

    $downloadedTaskXmlPath = Join-Path $SysmonDir "UklidSysmon.xml"
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $SysmonCleanupTaskUrl -OutFile $downloadedTaskXmlPath -UseBasicParsing -ErrorAction Stop
        $TaskXmlPath = $downloadedTaskXmlPath
        Write-Host "  [OK] UklidSysmon.xml stazen z GitHub: $SysmonCleanupTaskUrl" -ForegroundColor Green
    } catch {
        Write-Host "  [VAROVANI] Stazeni UklidSysmon.xml z GitHub selhalo, pouziji lokalni soubor pokud existuje." -ForegroundColor Yellow
    }

    if (-not (Test-Path $TaskXmlPath)) {
        Write-Host "  [VAROVANI] Soubor UklidSysmon.xml nebyl nalezen: $TaskXmlPath" -ForegroundColor Yellow
        return
    }

    try {
        $taskXml = Get-Content -Path $TaskXmlPath -Raw -Encoding Unicode
        Register-ScheduledTask -TaskName $SysmonCleanupTaskName -Xml $taskXml -Force -ErrorAction Stop | Out-Null

        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        Set-ScheduledTask -TaskName $SysmonCleanupTaskName -Principal $principal -ErrorAction Stop | Out-Null
        Enable-ScheduledTask -TaskName $SysmonCleanupTaskName -ErrorAction SilentlyContinue | Out-Null

        Write-Host "  [OK] Uloha '$SysmonCleanupTaskName' byla naimportovana a bezi s nejvyssim opravnenim." -ForegroundColor Green
    } catch {
        Write-Host "  [VAROVANI] Import pres ScheduledTasks cmdlety selhal, zkousim schtasks.exe ..." -ForegroundColor Yellow
        try {
            schtasks /Create /TN "\$SysmonCleanupTaskName" /XML "$TaskXmlPath" /F | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "schtasks /Create vratil kod $LASTEXITCODE" }

            schtasks /Change /TN "\$SysmonCleanupTaskName" /RU "SYSTEM" /RL HIGHEST | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "schtasks /Change vratil kod $LASTEXITCODE" }

            Write-Host "  [OK] Uloha '$SysmonCleanupTaskName' byla naimportovana pres schtasks.exe." -ForegroundColor Green
        } catch {
            Write-Host "  [CHYBA] Nepodarilo se naimportovat UklidSysmon ulohu: $_" -ForegroundColor Red
        }
    }
}

function Install-Sysmon {
    param(
        [string]$CustomConfigPath
    )
    Write-Host ""
    Write-Host "  -- Instalace Sysmon64 --" -ForegroundColor Cyan

    if (-not (Test-Path $SysmonDir)) {
        New-Item -Path $SysmonDir -ItemType Directory -Force | Out-Null
        Write-Host "  Vytvoren adresar: $SysmonDir" -ForegroundColor Green
    }

    # Stazeni Sysmon.exe pokud neexistuje
    if (-not (Test-Path $SysmonExePath)) {
        Write-Host "  Stahuji Sysmon64.exe z live.sysinternals.com ..." -ForegroundColor Yellow
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -Uri $SysmonExeUrl -OutFile $SysmonExePath -UseBasicParsing -ErrorAction Stop
            Write-Host "  [OK] Sysmon64.exe stazen" -ForegroundColor Green
        } catch {
            Write-Host "  [CHYBA] Nelze stahnout Sysmon64.exe: $_" -ForegroundColor Red
            return
        }
    } else {
        Write-Host "  Sysmon64.exe jiz existuje v $SysmonDir" -ForegroundColor DarkGray
    }

    $configToUse = ""
    if (-not ([string]::IsNullOrEmpty($CustomConfigPath))) {
        $configToUse = $CustomConfigPath
        Write-Host "  Pouzivam vlastni konfiguraci: $configToUse" -ForegroundColor Cyan
    } else {
        $configToUse = $SysmonConfigPath
        Write-Host "  Stahuji konfiguraci (sysmon-modular by Olaf Hartong) ..." -ForegroundColor Yellow
        try {
            Invoke-WebRequest -Uri $SysmonConfigUrl -OutFile $configToUse -UseBasicParsing -ErrorAction Stop
            Write-Host "  [OK] Konfigurace stazena" -ForegroundColor Green
        } catch {
            Write-Host "  [CHYBA] Nelze stahnout konfiguraci: $_" -ForegroundColor Red
            return
        }
    }

    $existingSvc = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
    if (-not $existingSvc) { $existingSvc = Get-Service -Name "Sysmon" -ErrorAction SilentlyContinue }
    if ($existingSvc) {
        Write-Host "  Odinstalovavam starsi verzi Sysmon ..." -ForegroundColor Yellow
        & $SysmonExePath -u force 2>$null
        Start-Sleep -Seconds 2
    }

    Write-Host "  Instaluji Sysmon64 s konfiguraci ..." -ForegroundColor Yellow
    try {
        $proc = Start-Process -FilePath $SysmonExePath -ArgumentList "-accepteula -i `"$configToUse`"" -Wait -PassThru -NoNewWindow
        if ($proc.ExitCode -eq 0) {
            Write-Host "  [OK] Sysmon64 nainstalovan a bezi!" -ForegroundColor Green
            Write-Host "  Logy: Event Viewer -> Microsoft-Windows-Sysmon/Operational" -ForegroundColor DarkGray
            Import-SysmonCleanupTask
        } else {
            Write-Host "  [VAROVANI] Sysmon se vratil s kodem: $($proc.ExitCode)" -ForegroundColor Yellow
            Write-Host "  Zkontrolujte, zda je XML konfigurace platna." -ForegroundColor Yellow
        }
    } catch {
        Write-Host "  [CHYBA] Instalace selhala: $_" -ForegroundColor Red
    }
}

function Update-SysmonConfig {
    param(
        [string]$CustomConfigPath
    )
    Write-Host ""
    Write-Host "  -- Aktualizace konfigurace Sysmon --" -ForegroundColor Cyan

    $svc = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
    if (-not $svc) { $svc = Get-Service -Name "Sysmon" -ErrorAction SilentlyContinue }
    if (-not $svc) {
        Write-Host "  Sysmon neni nainstalovan. Nejprve ho nainstalujte." -ForegroundColor Red
        return
    }

    if (-not (Test-Path $SysmonDir)) { New-Item -Path $SysmonDir -ItemType Directory -Force | Out-Null }

    $configToUse = ""
    if (-not ([string]::IsNullOrEmpty($CustomConfigPath))) {
        $configToUse = $CustomConfigPath
        Write-Host "  Pouzivam vlastni konfiguraci: $configToUse" -ForegroundColor Cyan
    } else {
        $configToUse = $SysmonConfigPath
        Write-Host "  Stahuji nejnovejsi konfiguraci ..." -ForegroundColor Yellow
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -Uri $SysmonConfigUrl -OutFile $configToUse -UseBasicParsing -ErrorAction Stop
            Write-Host "  [OK] Konfigurace stazena" -ForegroundColor Green
        } catch {
            Write-Host "  [CHYBA] Nelze stahnout konfiguraci: $_" -ForegroundColor Red
            return
        }
    }

    $sysmonPath = $SysmonExePath
    if (-not (Test-Path $sysmonPath)) {
        $sysmonPath = (Get-Command Sysmon64.exe -ErrorAction SilentlyContinue).Source
        if (-not $sysmonPath) { $sysmonPath = (Get-Command Sysmon.exe -ErrorAction SilentlyContinue).Source }
    }
    if (-not $sysmonPath) {
        Write-Host "  [CHYBA] Nelze najit Sysmon64.exe" -ForegroundColor Red
        return
    }

    Write-Host "  Aplikuji konfiguraci ..." -ForegroundColor Yellow
    try {
        $proc = Start-Process -FilePath $sysmonPath -ArgumentList "-c `"$configToUse`"" -Wait -PassThru -NoNewWindow
        if ($proc.ExitCode -eq 0) {
            Write-Host "  [OK] Konfigurace aktualizovana!" -ForegroundColor Green
        } else {
            Write-Host "  [VAROVANI] Kod: $($proc.ExitCode)" -ForegroundColor Yellow
            Write-Host "  Zkontrolujte, zda je XML konfigurace platna." -ForegroundColor Yellow
        }
    } catch {
        Write-Host "  [CHYBA]: $_" -ForegroundColor Red
    }
}

function Use-CustomSysmonConfig {
    Write-Host ""
    Write-Host "  -- Pouziti vlastni Sysmon XML konfigurace --" -ForegroundColor Cyan
    $xmlPath = Read-Host "  Zadejte prosim plnou cestu k vasemu XML souboru"

    if (-not (Test-Path $xmlPath)) {
        Write-Host "  [CHYBA] Soubor nebyl nalezen: $xmlPath" -ForegroundColor Red
        return
    }

    if ($xmlPath -notlike "*.xml") {
        Write-Host "  [CHYBA] Soubor musi mit priponu .xml" -ForegroundColor Red
        return
    }

    # Zakladni validace XML
    try {
        $xmlContent = Get-Content $xmlPath -Raw
        $xml = [xml]$xmlContent
        if ($xml.SelectSingleNode("Sysmon")) {
            Write-Host "  [OK] XML soubor se zda byt platny (obsahuje element <Sysmon>)." -ForegroundColor Green
        } else {
            Write-Host "  [VAROVANI] XML soubor neobsahuje root element <Sysmon>. Muze byt neplatny." -ForegroundColor Yellow
        }
    } catch {
        Write-Host "  [CHYBA] Nelze zpracovat XML soubor. Ujistete se, ze je spravne formatovan." -ForegroundColor Red
        Write-Host "  Detail chyby: $($_.Exception.Message)" -ForegroundColor DarkGray
        return
    }

    $svc = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
    if (-not $svc) { $svc = Get-Service -Name "Sysmon" -ErrorAction SilentlyContinue }

    if ($svc) {
        Write-Host "  Sysmon je jiz nainstalovan, provadim aktualizaci konfigurace." -ForegroundColor Yellow
        Update-SysmonConfig -CustomConfigPath $xmlPath
    } else {
        Write-Host "  Sysmon neni nainstalovan, provadim instalaci s vasi konfiguraci." -ForegroundColor Yellow
        Install-Sysmon -CustomConfigPath $xmlPath
    }
}

function Uninstall-Sysmon {
    Write-Host ""
    Write-Host "  -- Odinstalace Sysmon --" -ForegroundColor Cyan

    $sysmonPath = $SysmonExePath
    if (-not (Test-Path $sysmonPath)) {
        $sysmonPath = (Get-Command Sysmon64.exe -ErrorAction SilentlyContinue).Source
        if (-not $sysmonPath) { $sysmonPath = (Get-Command Sysmon.exe -ErrorAction SilentlyContinue).Source }
    }
    if (-not $sysmonPath) {
        Write-Host "  Sysmon nebyl nalezen." -ForegroundColor Yellow
        return
    }

    try {
        $proc = Start-Process -FilePath $sysmonPath -ArgumentList "-u force" -Wait -PassThru -NoNewWindow
        if ($proc.ExitCode -eq 0) {
            Write-Host "  [OK] Sysmon odinstalovany." -ForegroundColor Green
        } else {
            Write-Host "  [VAROVANI] Kod: $($proc.ExitCode)" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "  [CHYBA]: $_" -ForegroundColor Red
    }
}

# ==============================================================================
#         G E T / S E T   -   D A L S I   N A S T A V E N I
# ==============================================================================
function Get-LMHashStatus {
    try {
        $val = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLMHash" -ErrorAction Stop).NoLMHash
        if ($val -eq 1) { "Zakazano (bezpecne)" } else { "Povoleno (riziko)" }
    } catch { "Povoleno (vychozi)" }
}

function Set-LMHashState {
    param([bool]$Disabled)
    try {
        $val = if ($Disabled) { 1 } else { 0 }
        Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLMHash" -Value $val -Type DWord -ErrorAction Stop
        $state = if ($Disabled) { "Zakazano" } else { "Povoleno" }
        Write-Host "  Ukladani LM hashe: $state" -ForegroundColor Green
    } catch { Write-Host "  CHYBA: $_" -ForegroundColor Red }
}

function Get-StickyKeysStatus {
    try {
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe"
        if (-not (Test-Path $regPath)) { return "Vychozi stav (bezpecne)" }
        $val = Get-ItemProperty -Path $regPath -Name "Debugger" -ErrorAction SilentlyContinue
        if ($null -eq $val -or [string]::IsNullOrWhiteSpace($val.Debugger)) {
            "Vychozi stav (bezpecne)"
        } else {
            "Riziko - Debugger nastaven: $($val.Debugger)"
        }
    } catch { "Neznamy" }
}

function Set-StickyKeysState {
    param([bool]$Secured)
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe"
    try {
        if ($Secured) {
            if (Test-Path $regPath) {
                Remove-ItemProperty -Path $regPath -Name "Debugger" -ErrorAction SilentlyContinue
                $remaining = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
                if ($remaining -and $remaining.PSObject.Properties.Name.Count -le 4) {
                    Remove-Item -Path $regPath -Force -ErrorAction SilentlyContinue
                }
            }
            Write-Host "  Sticky Keys: Odstranen zneuzitelny Debugger a obnoven vychozi stav." -ForegroundColor Green
        } else {
            Write-Host "  Z bezpecnostnich duvodu skript neumoznuje nastavit Debugger pro sethc.exe." -ForegroundColor Yellow
            Write-Host "  Vychozi stav bez Debuggeru je pro domaci PC spravna volba." -ForegroundColor DarkGray
        }
    } catch { Write-Host "  CHYBA: $_" -ForegroundColor Red }
}

function Get-BitLockerStatus {
    try {
        $vols = Get-BitLockerVolume -ErrorAction SilentlyContinue
        if (-not $vols) { return "Neznamy (mozna neni podporovan)" }
        $osVol = $vols | Where-Object { $_.MountPoint -eq $env:SystemDrive }
        if (-not $osVol) { return "Systemovy disk nenalezen" }
        
        switch ($osVol.VolumeStatus) {
            "FullyEncrypted" { "Zapnuto (sifrovano)" }
            "FullyDecrypted" { "Vypnuto (nesifrovano!)" }
            "Encrypting"     { "Sifruje se..." }
            "Decrypting"     { "Desifruje se..." }
            default          { $osVol.VolumeStatus }
        }
    } catch { "Neznamy" }
}

function Show-BitLockerHelp {
    Write-Host ""
    Write-Host "  -- Informace o BitLockeru --" -ForegroundColor Cyan
    Write-Host "  BitLocker je technologie pro sifrovani celeho disku, ktera chrani" -ForegroundColor White
    Write-Host "  vase data v pripade ztraty nebo kradeze pocitace." -ForegroundColor White
    Write-Host ""
    Write-Host "  Tento skript nemuze BitLocker bezpecne zapnout za vas." -ForegroundColor Yellow
    Write-Host "  Musite to udelat rucne, abyste si mohli bezpecne ulozit obnovovaci klic." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  JAK ZAPNOUT BITLOCKER:" -ForegroundColor Green
    Write-Host "  1. Otevete Start a napiste 'Spravovat nastroj BitLocker'." -ForegroundColor Green
    Write-Host "  2. Kliknete na 'Zapnout nastroj BitLocker' u vaseho systemoveho disku (C:)." -ForegroundColor Green
    Write-Host "  3. Postupujte podle pruvodce." -ForegroundColor Green
    Write-Host "  4. **VELMI DULEZITE:** Ulozte si obnovovaci klic na bezpecne misto" -ForegroundColor Red
    Write-Host "     (napr. do uctu Microsoft, na USB disk nebo si ho vytisknete)." -ForegroundColor Red
    Write-Host "     Bez tohoto klice prijdete o sva data pri selhani hardwaru!" -ForegroundColor Red
    Write-Host ""
}

# ==============================================================================
#              G E T / S E T   -   B E Z P E C N E   D N S
# ==============================================================================
# Cloudflare DNS varianty:
#   1.1.1.1 / 1.0.0.1          = Standardni (rychle, soukrome)
#   1.1.1.2 / 1.0.0.2          = Malware Blocking (blokuje skodlive domeny)
#   1.1.1.3 / 1.0.0.3          = Malware + Adult Content (blokuje skodlive + obsah pro dospele)

$DNS_PROFILES = [ordered]@{
    "cloudflare_malware" = @{
        Name        = "Cloudflare - Blokace malware"
        Primary     = "1.1.1.2"
        Secondary   = "1.0.0.2"
        PrimaryIPv6  = "2606:4700:4700::1112"
        SecondaryIPv6 = "2606:4700:4700::1002"
        Info        = "Blokuje pristup ke znamym skodlivym domenam (phishing, malware C2)."
    }
    "cloudflare_family" = @{
        Name        = "Cloudflare - Blokace malware + obsah pro dospele"
        Primary     = "1.1.1.3"
        Secondary   = "1.0.0.3"
        PrimaryIPv6  = "2606:4700:4700::1113"
        SecondaryIPv6 = "2606:4700:4700::1003"
        Info        = "Blokuje malware domeny + obsah pro dospele (family filter)."
    }
    "cloudflare_standard" = @{
        Name        = "Cloudflare - Standardni (bez filtrace)"
        Primary     = "1.1.1.1"
        Secondary   = "1.0.0.1"
        PrimaryIPv6  = "2606:4700:4700::1111"
        SecondaryIPv6 = "2606:4700:4700::1001"
        Info        = "Rychle a soukrome DNS bez filtrace obsahu."
    }
}

function Get-ActiveNetAdapters {
    Get-NetAdapter -Physical -ErrorAction SilentlyContinue |
        Where-Object { $_.Status -eq "Up" }
}

function Get-DNSStatus {
    try {
        $adapters = Get-ActiveNetAdapters
        if (-not $adapters) { return "Zadny aktivni adapter" }
        $results = @()
        foreach ($adapter in $adapters) {
            $dns = Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
            $servers = $dns.ServerAddresses
            if ($servers) {
                $label = "$($adapter.Name): $($servers -join ', ')"
                # Rozpoznej profil
                foreach ($key in $DNS_PROFILES.Keys) {
                    $prof = $DNS_PROFILES[$key]
                    if ($servers -contains $prof.Primary) {
                        $label = "$($adapter.Name): $($prof.Name) ($($servers -join ', '))"
                        break
                    }
                }
                $results += $label
            } else {
                $results += "$($adapter.Name): DHCP (automaticky)"
            }
        }
        return ($results -join " | ")
    } catch { "Neznamy" }
}

function Get-DNSStatusShort {
    try {
        $adapters = Get-ActiveNetAdapters
        if (-not $adapters) { return "Zadny adapter" }
        $adapter = $adapters | Select-Object -First 1
        $dns = Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
        $servers = $dns.ServerAddresses
        if (-not $servers -or $servers.Count -eq 0) { return "DHCP (auto)" }
        foreach ($key in $DNS_PROFILES.Keys) {
            $prof = $DNS_PROFILES[$key]
            if ($servers -contains $prof.Primary) {
                return "$($prof.Primary)/$($prof.Secondary)"
            }
        }
        return ($servers -join ", ")
    } catch { "Neznamy" }
}

function Show-DNSDetail {
    Write-Header "Aktualni DNS na vsech adapterech"
    $adapters = Get-ActiveNetAdapters
    if (-not $adapters) {
        Write-Host "  Zadny aktivni sitovy adapter." -ForegroundColor Red
        return
    }
    foreach ($adapter in $adapters) {
        $dns4 = Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
        $dns6 = Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv6 -ErrorAction SilentlyContinue
        Write-Host ""
        Write-Host "  Adapter: $($adapter.Name) ($($adapter.InterfaceDescription))" -ForegroundColor White
        if ($dns4.ServerAddresses) {
            Write-Host "    IPv4 DNS: $($dns4.ServerAddresses -join ', ')" -ForegroundColor Cyan
        } else {
            Write-Host "    IPv4 DNS: DHCP (automaticky)" -ForegroundColor Yellow
        }
        if ($dns6.ServerAddresses) {
            Write-Host "    IPv6 DNS: $($dns6.ServerAddresses -join ', ')" -ForegroundColor Cyan
        }
    }
}

function Set-SecureDNS {
    param([string]$ProfileKey)
    $prof = $DNS_PROFILES[$ProfileKey]
    if (-not $prof) {
        Write-Host "  CHYBA: Neznamy DNS profil." -ForegroundColor Red
        return
    }
    $adapters = Get-ActiveNetAdapters
    if (-not $adapters) {
        Write-Host "  CHYBA: Zadny aktivni sitovy adapter." -ForegroundColor Red
        return
    }
    Write-Host ""
    Write-Host "  Nastavuji DNS: $($prof.Name)" -ForegroundColor Yellow
    Write-Host "  IPv4: $($prof.Primary), $($prof.Secondary)" -ForegroundColor DarkGray
    if ($prof.PrimaryIPv6) {
        Write-Host "  IPv6: $($prof.PrimaryIPv6), $($prof.SecondaryIPv6)" -ForegroundColor DarkGray
    }
    foreach ($adapter in $adapters) {
        try {
            Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses @($prof.Primary, $prof.Secondary) -AddressFamily IPv4 -ErrorAction Stop
            if ($prof.PrimaryIPv6) {
                Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses @($prof.PrimaryIPv6, $prof.SecondaryIPv6) -AddressFamily IPv6 -ErrorAction Stop
            }
            Write-Host "    [OK] $($adapter.Name)" -ForegroundColor Green
        } catch {
            Write-Host "    [CHYBA] $($adapter.Name): $_" -ForegroundColor Red
        }
    }
    Write-Host "  Hotovo." -ForegroundColor Green
}

function Reset-DNS {
    $adapters = Get-ActiveNetAdapters
    if (-not $adapters) {
        Write-Host "  CHYBA: Zadny aktivni sitovy adapter." -ForegroundColor Red
        return
    }
    Write-Host ""
    Write-Host "  Resetuji DNS na automaticke (DHCP) ..." -ForegroundColor Yellow
    foreach ($adapter in $adapters) {
        try {
            Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ResetServerAddresses -ErrorAction Stop
            Write-Host "    [OK] $($adapter.Name) - DHCP" -ForegroundColor Green
        } catch {
            Write-Host "    [CHYBA] $($adapter.Name): $_" -ForegroundColor Red
        }
    }
    Write-Host "  Hotovo." -ForegroundColor Green
}

# ==============================================================================
#    V O L B A   9 9   -   K O M P L E T N I   P R E H L E D
# ==============================================================================
function Show-FullStatus {
    Show-Banner
    Write-Header "KOMPLETNI PREHLED ZABEZPECENI"

    function Get-StatusColor([string]$Value) {
        if ($Value -match "Zapnuto|Blokovat|Zakazano \(bezpecne\)|Bezi|Vse zapnuto") { 'Green' }
        elseif ($Value -match "Vypnuto|Povoleno \(riziko|Vse vypnuto|Nenainstalovan") { 'Red' }
        else { 'Yellow' }
    }

    Write-Host ""
    Write-Host "  -- DEFENDER a ASR -------------------------------------------------" -ForegroundColor Magenta
    $v = Get-DefenderRTStatus;        Write-Status "Defender (RT+Cloud+Samples)" $v (Get-StatusColor $v)
    $v = Get-TamperProtectionStatus;  Write-Status "Tamper Protection"           $v (Get-StatusColor $v)
    $v = Get-PUAStatus;               Write-Status "PUA ochrana"                 $v (Get-StatusColor $v)
    $v = Get-CFAStatus;               Write-Status "Controlled Folder Access"    $v (Get-StatusColor $v)

    Write-Host ""
    Write-Host "  ASR pravidla:" -ForegroundColor White
    $current = Get-ASRStatus
    $modeMap = @{ 0 = "Vypnuto"; 1 = "Blokovat"; 2 = "Audit"; 6 = "Varovani" }
    foreach ($guid in $ASR_RULES.Keys) {
        $action = if ($current.ContainsKey($guid)) { $current[$guid] } else { 0 }
        $modeText = if ($modeMap.ContainsKey([int]$action)) { $modeMap[[int]$action] } else { "?" }
        $color = switch ([int]$action) { 0 { 'Red' } 1 { 'Green' } 2 { 'Yellow' } default { 'Gray' } }
        $desc = $ASR_RULES[$guid]
        if ($desc.Length -gt 58) { $desc = $desc.Substring(0,55) + "..." }
        Write-Host "    [$modeText]" -ForegroundColor $color -NoNewline
        Write-Host " $desc" -ForegroundColor White
    }

    Write-Host ""
    Write-Host "  -- SMARTSCREEN ----------------------------------------------------" -ForegroundColor Magenta
    $v = Get-SmartScreenStatus;       Write-Status "SmartScreen (Windows)"       $v (Get-StatusColor $v)
    $v = Get-EdgeSmartScreenStatus;   Write-Status "SmartScreen (Edge)"          $v (Get-StatusColor $v)

    Write-Host ""
    Write-Host "  -- SIT a PROTOKOLY ------------------------------------------------" -ForegroundColor Magenta
    $v = Get-FirewallStatus;          Write-Status "Windows Firewall"            $v (Get-StatusColor $v)
    $v = Get-RDPStatus;               Write-Status "Vzdalena plocha (RDP)"       $v (Get-StatusColor $v)
    $v = Get-SMBv1Status;             Write-Status "SMBv1 protokol"              $v (Get-StatusColor $v)
    $v = Get-LLMNRStatus;             Write-Status "LLMNR"                       $v (Get-StatusColor $v)

    Write-Host ""
    Write-Host "  -- SYSTEM a LOGGING -----------------------------------------------" -ForegroundColor Magenta
    $v = Get-AutoRunStatus;           Write-Status "AutoRun / AutoPlay"          $v (Get-StatusColor $v)
    $v = Get-PSLoggingStatus;         Write-Status "PS Script Block Logging"     $v (Get-StatusColor $v)

    Write-Host ""
    Write-Host "  -- DNS ----------------------------------------------------------------" -ForegroundColor Magenta
    $dnsInfo = Get-DNSStatus
    Write-Status "DNS servery" $dnsInfo 'Cyan'

    Write-Host ""
    Write-Host "  -- MONITORING -----------------------------------------------------" -ForegroundColor Magenta
    $v = Get-SysmonStatus;            Write-Status "Sysmon"                      $v (Get-StatusColor $v)

    Write-Host ""
    Write-Host "  -- POKROCILE ZABEZPECENI ------------------------------------------" -ForegroundColor Magenta

    function Get-AdvStatusColor([string]$Value) {
        if ($Value -match "Zakazano \(bezpecne\)|Zakazana|Zapnuto \(chraneny|Zapnuto \(Blokovat\)|pouze NTLMv2|Zapnuto - .*Secure|Zastavena") { 'Green' }
        elseif ($Value -match "RIZIKO|KRITICKE|Povoleno \(riziko|Povoleno \(vychozi - riziko\)|Bezi.*riziko|Vypnuto \(riziko\)|Vypnuto$") { 'Red' }
        else { 'Yellow' }
    }

    $v = Get-WDigestStatus;           Write-Status "WDigest (plaintext hesla)"  $v (Get-AdvStatusColor $v)
    $v = Get-LSAPPLStatus;            Write-Status "LSA Protected Process"       $v (Get-AdvStatusColor $v)
    $v = Get-NetworkProtectionStatus; Write-Status "Network Protection"          $v (Get-AdvStatusColor $v)
    $v = Get-NetBIOSStatus;           Write-Status "NetBIOS over TCP/IP"         $v (Get-AdvStatusColor $v)
    $v = Get-NTLMStatus;              Write-Status "NTLM uroven"                 $v (Get-AdvStatusColor $v)
    $v = Get-WSHStatus;               Write-Status "Windows Script Host"         $v (Get-AdvStatusColor $v)
    $v = Get-UACStatus;               Write-Status "UAC uroven"                  $v (Get-AdvStatusColor $v)
    $v = Get-EventLogSizeStatus;      Write-Status "Event Log velikost"          $v (Get-AdvStatusColor $v)
    $v = Get-RemoteRegistryStatus;    Write-Status "Remote Registry sluzba"      $v (Get-AdvStatusColor $v)
    $v = Get-SecureBootStatus;        Write-Status "Secure Boot"                 $v (Get-AdvStatusColor $v)
    $v = Get-VBSStatus;               Write-Status "VBS / HVCI / Cred. Guard"   $v (Get-AdvStatusColor $v)

    Write-Host ""
}

# ==============================================================================
#           Z A P N O U T   V S E   N A   M A X I M U M
# ==============================================================================
function Enable-MaxSecurity {
    Write-Header "Zapinam MAXIMUM zabezpeceni"
    Write-Host ""
    Set-AllASR -Mode 1
    Set-PUA -Mode 1
    Set-DefenderRT -Enabled $true
    Set-CFA -Mode 1
    # Tamper Protection - casto nelze menit pres registr, jen informujeme
    $tpSt = Get-TamperProtectionStatus
    if ($tpSt -eq "Zapnuto") {
        Write-Host "  Tamper Protection: jiz Zapnuto" -ForegroundColor Green
    } else {
        Write-Host "  Tamper Protection: Nelze nastavit skriptem - Windows ho chrani." -ForegroundColor Yellow
        Write-Host "  -> Zapnete rucne: Windows Zabezpeceni > Ochrana pred viry > Nastaveni" -ForegroundColor Yellow
    }
    Set-SmartScreen -Mode "RequireAdmin"
    Set-EdgeSmartScreen -Enabled $true
    Set-FirewallState -Enabled $true
    Write-Host "  Vzdalena plocha (RDP): zakazuji (pro domaci PC doporuceno)..." -ForegroundColor DarkGray
    Set-RDPState -Disabled $true
    Set-SMBv1State -Enabled $false
    Set-LLMNRState -Disabled $true
    Set-AutoRunState -Disabled $true
    Set-PSLogging -Enabled $true
    Set-SecureDNS -ProfileKey "cloudflare_malware"
    Set-LMHashState -Disabled $true
    Set-StickyKeysState -Secured $true
    # Nove: Office registry
    Set-OfficeSecurityRegistry
    # Nove: Defender sandboxing
    Set-DefenderSandboxing -Enabled $true
    # Nove: Update Defender signatur
    Update-DefenderSignatures
    # Pokrocile zabezpeceni
    Write-Host "  -- Pokrocile zabezpeceni --" -ForegroundColor DarkGray
    Set-WDigest -Disabled $true
    Set-LSAPPL -Enabled $true
    Set-NetworkProtection -Mode 1
    Set-NetBIOSState -Disabled $true
    Set-NTLMLevel -Level 5
    Set-WSHState -Disabled $true
    Set-UACLevel -Level 0
    Set-EventLogSize
    Set-RemoteRegistryState -Disabled $true
    Write-Host ""
    Write-Host "  *** Vse nastaveno na maximalni ochranu! ***" -ForegroundColor Green
    Write-Host ""
    $blSt = Get-BitLockerStatus
    if ($blSt -notmatch "Zapnuto") {
        Write-Host "  DOPORUCENI: Nezapomente zapnout sifrovani disku BitLocker!" -ForegroundColor Yellow
        Show-BitLockerHelp
    }
}
function Set-OfficeSecurityRegistry {
    Write-Host "  Nastavuji registry pro zabezpeceni Office..." -ForegroundColor Yellow
    $officeVersions = @("12.0", "14.0", "15.0", "16.0", "19.0")
    foreach ($ver in $officeVersions) {
        $apps = @("Word", "Excel", "PowerPoint", "Publisher", "Outlook")
        foreach ($app in $apps) {
            $base = "HKCU:\Software\Policies\Microsoft\Office\$ver\$app\Security"
            if ($app -eq "Outlook") {
                New-Item -Path $base -Force | Out-Null
                Set-ItemProperty -Path $base -Name "markinternalasunsafe" -Value 0 -Type DWord -ErrorAction SilentlyContinue
            } else {
                New-Item -Path $base -Force | Out-Null
                Set-ItemProperty -Path $base -Name "vbawarnings" -Value 4 -Type DWord -ErrorAction SilentlyContinue
                Set-ItemProperty -Path $base -Name "blockcontentexecutionfrominternet" -Value 1 -Type DWord -ErrorAction SilentlyContinue
            }
        }
    }
    # Dalsi registry pro WordMail a DontUpdateLinks
    foreach ($ver in @("14.0", "15.0", "16.0")) {
        $base = "HKCU:\Software\Microsoft\Office\$ver\Word\Options"
        New-Item -Path $base -Force | Out-Null
        Set-ItemProperty -Path $base -Name "DontUpdateLinks" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        $wm = "$base\WordMail"
        New-Item -Path $wm -Force | Out-Null
        Set-ItemProperty -Path $wm -Name "DontUpdateLinks" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    }
    Write-Host "  Office registry nastaveny." -ForegroundColor Green
}

function Set-DefenderSandboxing {
    param([bool]$Enabled)
    $strVal = if ($Enabled) { "1" } else { "0" }
    Write-Host "  Nastavuji Defender sandboxing..." -ForegroundColor Yellow
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -Name "MP_FORCE_USE_SANDBOX" -Value $strVal -Type String -ErrorAction SilentlyContinue
    Write-Host "  Defender sandboxing nastaven na: $strVal (restart vyzadovan)" -ForegroundColor Green
}

function Update-DefenderSignatures {
    Write-Host "  Aktualizuji Defender signatury..." -ForegroundColor Yellow
    try {
        Update-MpSignature -ErrorAction Stop
        Write-Host "  Defender signatury aktualizovany." -ForegroundColor Green
    } catch {
        Write-Host "  CHYBA pri aktualizaci signatur: $_" -ForegroundColor Red
    }
}

# ==============================================================================
#     P O K R O C I L E   Z A B E Z P E C E N I
# ==============================================================================

# -- WDigest -------------------------------------------------------------------
function Get-WDigestStatus {
    try {
        $val = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -ErrorAction SilentlyContinue
        if ($null -eq $val -or $null -eq $val.UseLogonCredential) { return "Nenastaveno (default bezpecne)" }
        if ([int]$val.UseLogonCredential -eq 0) { return "Zakazano (bezpecne)" }
        return "Povoleno (RIZIKO - hesla v pameti!)"
    } catch { return "Nelze zjistit" }
}

function Set-WDigest {
    param([bool]$Disabled)
    $keyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
    $newVal  = if ($Disabled) { 0 } else { 1 }
    $label   = if ($Disabled) { "ZAKAZANO (bezpecne)" } else { "POVOLENO (riziko)" }
    Write-Host "  Nastavuji WDigest na: $label ..." -ForegroundColor Yellow
    try {
        New-Item -Path $keyPath -Force -ErrorAction SilentlyContinue | Out-Null
        Set-ItemProperty -Path $keyPath -Name "UseLogonCredential" -Value $newVal -Type DWord -ErrorAction Stop
        Write-Host "  [OK] WDigest UseLogonCredential = $newVal" -ForegroundColor Green
        Write-Host "  POZN: Zmena se plne projevi po restartu nebo novem prihlaseni." -ForegroundColor DarkGray
    } catch {
        Write-Host "  [CHYBA] $_" -ForegroundColor Red
    }
}

# -- LSA Protected Process (RunAsPPL) -----------------------------------------
function Get-LSAPPLStatus {
    try {
        $val = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue
        if ($null -eq $val -or $null -eq $val.RunAsPPL) { return "Vypnuto (riziko - Mimikatz dump)" }
        if ([int]$val.RunAsPPL -ge 1) { return "Zapnuto (chraneny lsass.exe)" }
        return "Vypnuto (riziko - Mimikatz dump)"
    } catch { return "Nelze zjistit" }
}

function Set-LSAPPL {
    param([bool]$Enabled)
    $newVal = if ($Enabled) { 1 } else { 0 }
    $label  = if ($Enabled) { "ZAPNUTO (chraneny lsass)" } else { "VYPNUTO (riziko)" }
    Write-Host "  Nastavuji LSA Protected Process: $label ..." -ForegroundColor Yellow
    try {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value $newVal -Type DWord -ErrorAction Stop
        Write-Host "  [OK] RunAsPPL = $newVal" -ForegroundColor Green
        Write-Host "  POZN: Vyzaduje restart PC. Po restartu lsass.exe bude chraneny proces." -ForegroundColor DarkGray
        if ($Enabled) {
            Write-Host "  INFO: Nektere starsi antiviry nebo debug nastroje mohou preststat fungovat." -ForegroundColor Yellow
        }
    } catch {
        Write-Host "  [CHYBA] $_" -ForegroundColor Red
    }
}

# -- LSA Registry Protection Audit --------------------------------------------
function Show-LSARegistryAudit {
    Write-Header "LSA REGISTRY PROTECTION AUDIT"
    $lsaKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"

    # 1) RunAsPPL + RunAsPPLBoot
    Write-Host ""
    Write-Host "  [ 1. LSA Protected Process Light (PPL) ]" -ForegroundColor Cyan
    try {
        $lsaProps = Get-ItemProperty $lsaKey -ErrorAction Stop
        $ppl  = $lsaProps.RunAsPPL
        $boot = $lsaProps.RunAsPPLBoot
        if ($ppl -ge 1) {
            Write-Host "    RunAsPPL       : $ppl  --> ZAPNUTO - lsass.exe je chraneny proces" -ForegroundColor Green
        } else {
            Write-Host "    RunAsPPL       : $ppl  --> VYPNUTO - lsass.exe je zranitelny (Mimikatz)" -ForegroundColor Red
        }
        if ($null -ne $boot -and $boot -ge 1) {
            Write-Host "    RunAsPPLBoot   : $boot --> ZAPNUTO - UEFI/Secure Boot uzamceni PPL" -ForegroundColor Green
        } else {
            Write-Host "    RunAsPPLBoot   : (neni nastaveno) - PPL neni uzamceno pres UEFI" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "    [CHYBA] Nelze cist LSA klic: $_" -ForegroundColor Red
    }

    # 2) WDigest + DisableRestrictedAdmin
    Write-Host ""
    Write-Host "  [ 2. LSA hodnoty - ochrana hesel ]" -ForegroundColor Cyan
    try {
        $lsaProps = Get-ItemProperty $lsaKey -ErrorAction Stop
        $wdigest = try { (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -EA Stop).UseLogonCredential } catch { $null }
        if ($null -eq $wdigest -or $wdigest -eq 0) {
            Write-Host "    WDigest        : VYPNUTO (hesla nejsou v RAM plaintext) OK" -ForegroundColor Green
        } else {
            Write-Host "    WDigest        : ZAPNUTO - RIZIKO! hesla ukladana v RAM" -ForegroundColor Red
        }
        $dra = $lsaProps.DisableRestrictedAdmin
        if ($dra -eq 0) {
            Write-Host "    RestrictedAdmin: $dra --> ZAPNUTO (RDP neodesila hesla na server)" -ForegroundColor Green
        } else {
            Write-Host "    RestrictedAdmin: $dra --> VYPNUTO - RDP muze odeslat hash na zly server" -ForegroundColor Yellow
        }
        $lmHash = $lsaProps.NoLMHash
        if ($lmHash -eq 1) {
            Write-Host "    NoLMHash       : ZAPNUTO - LM hash se neukl da" -ForegroundColor Green
        } else {
            Write-Host "    NoLMHash       : VYPNUTO - slabe LM hashe se ukladaji" -ForegroundColor Red
        }
        $ntlmLvl = $lsaProps.LmCompatibilityLevel
        $ntlmTxt = switch ($ntlmLvl) {
            5 { "5 (pouze NTLMv2 - nejsilnejsi)" }
            3 { "3 (NTLMv2 i NTLM)" }
            $null { "(nenastaveno = Windows default = uroven 3)" }
            default { "$ntlmLvl" }
        }
        $ntlmColor = if ($ntlmLvl -eq 5) { 'Green' } elseif ($ntlmLvl -ge 3) { 'Yellow' } else { 'Red' }
        Write-Host "    NTLMv2 uroven  : $ntlmTxt" -ForegroundColor $ntlmColor
    } catch {
        Write-Host "    [CHYBA] $_" -ForegroundColor Red
    }

    # 3) ACL na LSA klici - kdo ma prava zapisu/smazani
    Write-Host ""
    Write-Host "  [ 3. ACL - prava na HKLM\...\Lsa klici ]" -ForegroundColor Cyan
    Write-Host "    (Kdo muze modifikovat LSA registry klic)" -ForegroundColor DarkGray
    try {
        $acl = (Get-Item $lsaKey).GetAccessControl()
        $dangerous = @()
        foreach ($ace in $acl.Access) {
            $rights = $ace.RegistryRights.ToString()
            $id     = $ace.IdentityReference.Value
            # Preskoc standardni bezpecne identity
            if ($id -match 'NT AUTHORITY\\SYSTEM|BUILTIN\\Administrators|TrustedInstaller|NT SERVICE\\TrustedInstaller') { continue }
            # Zkontroluj nebezpecna prava
            if ($rights -match 'FullControl|SetValue|Delete|WriteKey|ChangePermissions|TakeOwnership') {
                $dangerous += "    [!] $id  -->  $rights"
            }
        }
        if ($dangerous.Count -gt 0) {
            Write-Host "    VAROVANI - neocekavane identity s pravem zapisu:" -ForegroundColor Red
            $dangerous | ForEach-Object { Write-Host $_ -ForegroundColor Red }
        } else {
            Write-Host "    OK - LSA klic maji zapis pouze SYSTEM, Administrators, TrustedInstaller" -ForegroundColor Green
        }
        # Zobraz vlastnika
        $owner = $acl.Owner
        Write-Host "    Vlastnik klice : $owner" -ForegroundColor DarkGray
    } catch {
        Write-Host "    [CHYBA] Nelze cist ACL: $_" -ForegroundColor Yellow
        Write-Host "    Tip: Spustite jako Administrator" -ForegroundColor DarkGray
    }

    # 4) SACL - je nastavene auditovani pristupu na LSA klic?
    Write-Host ""
    Write-Host "  [ 4. SACL - auditovani pristupu na LSA klic ]" -ForegroundColor Cyan
    try {
        $sacl = (Get-Item $lsaKey).GetAccessControl('Audit')
        $rules = $sacl.GetAuditRules($true, $true, [System.Security.Principal.NTAccount])
        if ($rules.Count -gt 0) {
            Write-Host "    SACL nastavena - pristupy se auditují:" -ForegroundColor Green
            foreach ($r in $rules) {
                Write-Host "      $($r.IdentityReference) : $($r.RegistryRights) [$($r.AuditFlags)]" -ForegroundColor DarkGray
            }
        } else {
            Write-Host "    SACL neni nastavena - zmeny LSA klice se NElogují do Event Logu" -ForegroundColor Yellow
            Write-Host "    Tip: Pro zapnuti auditovani pouzijte auditpol nebo Volba 20 tohoto menu" -ForegroundColor DarkGray
        }
    } catch {
        Write-Host "    Nelze cist SACL (vyzaduje SeSecurityPrivilege / admin): $_" -ForegroundColor Yellow
    }

    # 5) Protected Users skupina
    Write-Host ""
    Write-Host "  [ 5. Protected Users skupina ]" -ForegroundColor Cyan
    Write-Host "    (Clenove nepodlehaji NTLM, WDigest, Kerberos delegaci, RC4)" -ForegroundColor DarkGray
    try {
        $pu = Get-LocalGroupMember -Group "Protected Users" -ErrorAction SilentlyContinue
        if ($pu) {
            Write-Host "    Clenove Protected Users:" -ForegroundColor Green
            $pu | ForEach-Object { Write-Host "      - $($_.Name)  [$($_.ObjectClass)]" -ForegroundColor Green }
        } else {
            Write-Host "    Protected Users je prazdna - zadny ucet nema extra ochranu" -ForegroundColor Yellow
            Write-Host "    Tip: Pridejte spravce do Protected Users pro silnejsi ochranu" -ForegroundColor DarkGray
        }
    } catch {
        Write-Host "    Nelze zjistit (skupina Protected Users neexistuje nebo chyba): $_" -ForegroundColor DarkGray
    }

    # 6) Credential Guard
    Write-Host ""
    Write-Host "  [ 6. Credential Guard / VBS ]" -ForegroundColor Cyan
    try {
        $vbs = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -EA SilentlyContinue).EnableVirtualizationBasedSecurity
        $cg  = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -EA SilentlyContinue).LsaCfgFlags
        if ($vbs -eq 1) {
            Write-Host "    VBS            : ZAPNUTO - Virtualizace bezpecnosti aktivni" -ForegroundColor Green
        } else {
            Write-Host "    VBS            : VYPNUTO - Credential Guard nefunguje bez VBS" -ForegroundColor Yellow
        }
        $cgTxt = switch ($cg) {
            1 { "Zapnuto s UEFI zamkem (nelze deaktivovat bez fyzickeho pristupu)" }
            2 { "Zapnuto bez zamku (lze deaktivovat GPO)" }
            0 { "Vypnuto" }
            $null { "(nenastaveno)" }
            default { $cg }
        }
        $cgColor = if ($cg -ge 1) { 'Green' } else { 'Yellow' }
        Write-Host "    Credential Guard: $cgTxt" -ForegroundColor $cgColor
        # Zkontroluj zda bezi sluzba
        $svc = Get-Service -Name "LsaIso" -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -eq 'Running') {
            Write-Host "    LsaIso.exe     : BEZI - Credential Guard aktivne ochranuji povereni" -ForegroundColor Green
        } elseif ($svc) {
            Write-Host "    LsaIso.exe     : NEBEZI (sluzba existuje ale je zastavena)" -ForegroundColor Yellow
        } else {
            Write-Host "    LsaIso.exe     : NENI - Credential Guard neni aktivni" -ForegroundColor DarkGray
        }
    } catch {
        Write-Host "    [CHYBA] $_" -ForegroundColor Red
    }

    # 7) Souhrn doporuceni
    Write-Host ""
    Write-Host "  [ SOUHRN - klicova doporuceni ]" -ForegroundColor Cyan
    Write-Host "    Volba 3  : Zapnout RunAsPPL (ochrana lsass.exe pred Mimikatz)" -ForegroundColor DarkGray
    Write-Host "    Volba 1  : Zakazat WDigest (plaintext hesla v RAM)" -ForegroundColor DarkGray
    Write-Host "    Volba 10 : Nastavit NTLMv2 uroven 5" -ForegroundColor DarkGray
    Write-Host "    Volba 20 : Zapnout auditovani zmen LSA klice (SACL)" -ForegroundColor DarkGray
    Write-Host "    Manual   : Pridat administratorsky ucet do skupiny Protected Users" -ForegroundColor DarkGray
    Write-Host ""
}

function Enable-LSARegistryAuditing {
    Write-Host ""
    Write-Host "  Nastavuji auditovani pristupu na LSA registry klic..." -ForegroundColor Yellow
    try {
        # Zapnout Object Access auditing v audit policy
        $out = auditpol /set /subcategory:"Registry" /success:enable /failure:enable 2>&1
        Write-Host "  [OK] Audit policy: Registry - Success + Failure zapnuto" -ForegroundColor Green

        # Nastavit SACL na LSA klic pres icacls/reg (PowerShell nativne vyzaduje SeSecurityPrivilege)
        # Pouzijeme auditpol jako minimalni zaznam
        Write-Host ""
        Write-Host "  POZN: SACL na registry klic vyzaduje nastroj 'regini' nebo 'SetSecInfo'." -ForegroundColor DarkGray
        Write-Host "  Alternativa - nastavte SACL manualne:" -ForegroundColor DarkGray
        Write-Host "    1) Spustte regedit jako Administrator" -ForegroundColor DarkGray
        Write-Host "    2) Prejdete na: HKLM\SYSTEM\CurrentControlSet\Control\Lsa" -ForegroundColor DarkGray
        Write-Host "    3) Klik pravy -> Opravneni -> Pokrocile -> zalozka Audit" -ForegroundColor DarkGray
        Write-Host "    4) Pridejte: Everyone, SetValue+Delete+WriteKey, Failure" -ForegroundColor DarkGray
        Write-Host "       (loguje neuspesne pokusy o zmenu - detekce utoky)" -ForegroundColor DarkGray
        Write-Host "    5) Pridejte: Everyone, SetValue+Delete+WriteKey, Success" -ForegroundColor DarkGray
        Write-Host "       (loguje vsechny zmeny - forenzni audit)" -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "  Audit policy pro Registry byl zapnut - udalosti se budou zobrazovat" -ForegroundColor Green
        Write-Host "  v Event Logu: Security -> Event ID 4657 (Registry value modified)" -ForegroundColor DarkGray
        Write-Host "             Security -> Event ID 4663 (Registry key access attempt)" -ForegroundColor DarkGray
    } catch {
        Write-Host "  [CHYBA] $_" -ForegroundColor Red
    }
}

# -- Defender Network Protection -----------------------------------------------
function Get-NetworkProtectionStatus {
    try {
        $pref = Get-MpPreference -ErrorAction SilentlyContinue
        if (-not $pref) { return "Nelze zjistit (Defender nedostupny)" }
        switch ([int]$pref.EnableNetworkProtection) {
            0 { return "Vypnuto" }
            1 { return "Zapnuto (Blokovat)" }
            2 { return "Audit (jen log)" }
            default { return "Neznamy stav" }
        }
    } catch { return "Nelze zjistit" }
}

function Set-NetworkProtection {
    param([int]$Mode)
    $label = switch ($Mode) { 0 { "VYPNUTO" } 1 { "BLOKOVAT (doporuceno)" } 2 { "AUDIT (jen log)" } default { "?" } }
    Write-Host "  Nastavuji Defender Network Protection: $label ..." -ForegroundColor Yellow
    try {
        Set-MpPreference -EnableNetworkProtection $Mode -ErrorAction Stop
        Write-Host "  [OK] Network Protection nastavena na uroven: $Mode" -ForegroundColor Green
        if ($Mode -eq 1) {
            Write-Host "  Blokuje pristupy na zname phishingove, malwarove a C2 domeny a IP." -ForegroundColor DarkGray
        }
    } catch {
        Write-Host "  [CHYBA] $_" -ForegroundColor Red
    }
}

# -- NetBIOS over TCP/IP -------------------------------------------------------
function Get-NetBIOSStatus {
    try {
        $adapters = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" -ErrorAction SilentlyContinue
        if (-not $adapters) { return "Nelze zjistit" }
        $enabled = @($adapters | Where-Object { $_.TcpipNetbiosOptions -ne 2 })
        if ($enabled.Count -eq 0) { return "Zakazano (bezpecne)" }
        return "Povoleno na $($enabled.Count) adapteru (riziko)"
    } catch { return "Nelze zjistit" }
}

function Set-NetBIOSState {
    param([bool]$Disabled)
    $optionValue = if ($Disabled) { 2 } else { 0 }  # 2 = Disable, 0 = DHCP default
    $label       = if ($Disabled) { "ZAKAZAT (bezpecne)" } else { "POVOLIT (DHCP vychozi)" }
    Write-Host "  Nastavuji NetBIOS over TCP/IP: $label ..." -ForegroundColor Yellow
    try {
        $adapters = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" -ErrorAction Stop
        $ok = 0; $fail = 0
        foreach ($adapter in $adapters) {
            $result = Invoke-CimMethod -InputObject $adapter -MethodName "SetTcpipNetbios" -Arguments @{ TcpipNetbiosOptions = [uint32]$optionValue }
            if ($result.ReturnValue -eq 0) { $ok++ } else { $fail++ }
        }
        Write-Host "  [OK] NetBIOS upraven na $ok adapteru." -ForegroundColor Green
        if ($fail -gt 0) { Write-Host "  [VAROV] $fail adapteru se nepodarilo nastavit." -ForegroundColor Yellow }
    } catch {
        Write-Host "  [CHYBA] $_" -ForegroundColor Red
    }
}

# -- NTLMv2 uroven (LmCompatibilityLevel) -------------------------------------
function Get-NTLMStatus {
    try {
        $val = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -ErrorAction SilentlyContinue
        $level = if ($null -eq $val -or $null -eq $val.LmCompatibilityLevel) { 3 } else { [int]$val.LmCompatibilityLevel }
        $desc = switch ($level) {
            0 { "0 - LM a NTLM (nejslabsi)" }
            1 { "1 - LM a NTLM, NTLMv2 volitelne" }
            2 { "2 - NTLM (bez LM)" }
            3 { "3 - NTLMv2 (vychozi Windows)" }
            4 { "4 - NTLMv2, odmita LM od serveru" }
            5 { "5 - pouze NTLMv2 (nejsilnejsi)" }
            default { "$level - neznamy" }
        }
        $color = if ($level -ge 5) { "bezpecne" } elseif ($level -ge 3) { "standard" } else { "RIZIKO" }
        return "Uroven $desc [$color]"
    } catch { return "Nelze zjistit" }
}

function Set-NTLMLevel {
    param([int]$Level)
    $desc = switch ($Level) {
        5 { "5 - pouze NTLMv2 (doporuceno)" }
        3 { "3 - NTLMv2 (Windows vychozi)" }
        default { "$Level" }
    }
    Write-Host "  Nastavuji LmCompatibilityLevel: $desc ..." -ForegroundColor Yellow
    try {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Value $Level -Type DWord -ErrorAction Stop
        Write-Host "  [OK] LmCompatibilityLevel = $Level" -ForegroundColor Green
    } catch {
        Write-Host "  [CHYBA] $_" -ForegroundColor Red
    }
}

# -- Windows Script Host (.vbs/.js/.wsf) ---------------------------------------
function Get-WSHStatus {
    try {
        $val = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -ErrorAction SilentlyContinue
        if ($null -eq $val -or $null -eq $val.Enabled) { return "Povoleno (vychozi - riziko)" }
        if ([int]$val.Enabled -eq 0) { return "Zakazano (bezpecne)" }
        return "Povoleno (riziko)"
    } catch { return "Nelze zjistit" }
}

function Set-WSHState {
    param([bool]$Disabled)
    $newVal = if ($Disabled) { 0 } else { 1 }
    $label  = if ($Disabled) { "ZAKAZANO (bezpecne)" } else { "POVOLENO (riziko)" }
    Write-Host "  Nastavuji Windows Script Host: $label ..." -ForegroundColor Yellow
    if ($Disabled) {
        Write-Host "  VAROVANI: Zakazani WSH znemozni spousteni .vbs/.js/.wsf souboru." -ForegroundColor Yellow
        Write-Host "  Pokud pouzivate starsi software s VBScript, tento skript muze prestat fungovat." -ForegroundColor DarkGray
    }
    try {
        $keyPath = "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings"
        New-Item -Path $keyPath -Force -ErrorAction SilentlyContinue | Out-Null
        Set-ItemProperty -Path $keyPath -Name "Enabled" -Value $newVal -Type DWord -ErrorAction Stop
        Write-Host "  [OK] WSH Enabled = $newVal" -ForegroundColor Green
    } catch {
        Write-Host "  [CHYBA] $_" -ForegroundColor Red
    }
}

# -- UAC uroven ----------------------------------------------------------------
function Get-UACStatus {
    try {
        $lsaPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        $lua  = (Get-ItemProperty $lsaPath -Name "EnableLUA"                    -ErrorAction SilentlyContinue).EnableLUA
        $cpb  = (Get-ItemProperty $lsaPath -Name "ConsentPromptBehaviorAdmin"   -ErrorAction SilentlyContinue).ConsentPromptBehaviorAdmin
        $psd  = (Get-ItemProperty $lsaPath -Name "PromptOnSecureDesktop"        -ErrorAction SilentlyContinue).PromptOnSecureDesktop

        if ($null -eq $lua -or [int]$lua -eq 0) { return "UAC VYPNUTO (KRITICKE RIZIKO!)" }

        $consent = switch ([int]$cpb) {
            0 { "bez promtpu" }
            1 { "s overenim (Secure Desktop)" }
            2 { "s promtpem (Secure Desktop) - MAXIMUM" }
            3 { "s overenim" }
            4 { "s promtem" }
            5 { "vychozi Windows (prompt)" }
            default { "uroven $cpb" }
        }
        $sd = if ([int]$psd -eq 1) { " + Secure Desktop" } else { "" }
        return "Zapnuto - $consent$sd"
    } catch { return "Nelze zjistit" }
}

function Set-UACLevel {
    param([int]$Level)
    # Level 0 = maximum (vyžaduje přihlašovací dialog + secure desktop)
    # Level 1 = standard (výzva na secure desktopu)
    # Level 2 = restore default
    $lsaPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    Write-Host "  Nastavuji UAC ..." -ForegroundColor Yellow
    try {
        Set-ItemProperty -Path $lsaPath -Name "EnableLUA" -Value 1 -Type DWord -ErrorAction Stop
        switch ($Level) {
            0 {
                Set-ItemProperty -Path $lsaPath -Name "ConsentPromptBehaviorAdmin" -Value 2 -Type DWord
                Set-ItemProperty -Path $lsaPath -Name "PromptOnSecureDesktop"      -Value 1 -Type DWord
                Write-Host "  [OK] UAC MAXIMUM - vyzaduje prihlaseni + bezpecnostni plocha." -ForegroundColor Green
            }
            1 {
                Set-ItemProperty -Path $lsaPath -Name "ConsentPromptBehaviorAdmin" -Value 4 -Type DWord
                Set-ItemProperty -Path $lsaPath -Name "PromptOnSecureDesktop"      -Value 1 -Type DWord
                Write-Host "  [OK] UAC STANDARD - vyzva na bezpecnostni plose." -ForegroundColor Green
            }
            default {
                Set-ItemProperty -Path $lsaPath -Name "ConsentPromptBehaviorAdmin" -Value 5 -Type DWord
                Set-ItemProperty -Path $lsaPath -Name "PromptOnSecureDesktop"      -Value 1 -Type DWord
                Write-Host "  [OK] UAC obnoven na Windows vychozi uroven." -ForegroundColor Green
            }
        }
    } catch {
        Write-Host "  [CHYBA] $_" -ForegroundColor Red
    }
}

# -- Velikost Event Logu -------------------------------------------------------
function Get-EventLogSizeStatus {
    try {
        $sec = Get-WinEvent -ListLog "Security"     -ErrorAction SilentlyContinue
        $sys = Get-WinEvent -ListLog "System"       -ErrorAction SilentlyContinue
        $secMB = if ($sec) { [math]::Round($sec.MaximumSizeInBytes / 1MB) } else { 0 }
        $sysMB = if ($sys) { [math]::Round($sys.MaximumSizeInBytes / 1MB) } else { 0 }
        $warn  = if ($secMB -lt 256 -or $sysMB -lt 64) { " (MALE - doporuceno zvetsit)" } else { "" }
        return "Security: ${secMB}MB, System: ${sysMB}MB$warn"
    } catch { return "Nelze zjistit" }
}

function Set-EventLogSize {
    Write-Host "  Zvetsuju Event Logy pro delsi retenci ..." -ForegroundColor Yellow
    $configs = @(
        @{ Log = "Security";                                    Size = 536870912 },  # 512 MB
        @{ Log = "System";                                      Size = 134217728 },  # 128 MB
        @{ Log = "Application";                                 Size = 67108864  },  # 64 MB
        @{ Log = "Microsoft-Windows-PowerShell/Operational";   Size = 67108864  },  # 64 MB
        @{ Log = "Microsoft-Windows-Sysmon/Operational";       Size = 134217728 }   # 128 MB
    )
    foreach ($cfg in $configs) {
        try {
            wevtutil sl "$($cfg.Log)" /ms:$($cfg.Size) 2>$null
            $mb = [math]::Round($cfg.Size / 1MB)
            Write-Host "  [OK] $($cfg.Log) -> ${mb}MB" -ForegroundColor Green
        } catch {
            Write-Host "  [VAROV] $($cfg.Log): $_" -ForegroundColor Yellow
        }
    }
}

# -- Remote Registry -----------------------------------------------------------
function Get-RemoteRegistryStatus {
    try {
        $svc = Get-Service "RemoteRegistry" -ErrorAction SilentlyContinue
        if (-not $svc) { return "Sluzba nenalezena" }
        if ($svc.Status -eq "Stopped" -and $svc.StartType -eq "Disabled") { return "Zakazana/Zastavena (bezpecne)" }
        if ($svc.Status -eq "Stopped") { return "Zastavena (StartType: $($svc.StartType))" }
        return "Bezi - $($svc.StartType) (riziko - vzdal. pristup k registru)"
    } catch { return "Nelze zjistit" }
}

function Set-RemoteRegistryState {
    param([bool]$Disabled)
    Write-Host "  Nastavuji Remote Registry sluzbu ..." -ForegroundColor Yellow
    try {
        if ($Disabled) {
            Stop-Service "RemoteRegistry" -Force -ErrorAction SilentlyContinue
            Set-Service  "RemoteRegistry" -StartupType Disabled -ErrorAction Stop
            Write-Host "  [OK] Remote Registry: zastavena a zakazana." -ForegroundColor Green
        } else {
            Set-Service  "RemoteRegistry" -StartupType Manual -ErrorAction Stop
            Write-Host "  [OK] Remote Registry: StartType nastaven na Manual." -ForegroundColor Green
            Write-Host "  Sluzba se nespusti automaticky pri startu." -ForegroundColor DarkGray
        }
    } catch {
        Write-Host "  [CHYBA] $_" -ForegroundColor Red
    }
}

# -- Secure Boot (jen status) --------------------------------------------------
function Get-SecureBootStatus {
    try {
        $sb = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
        if ($sb -eq $true)  { return "Zapnuto" }
        if ($sb -eq $false) { return "Vypnuto (zapnete v BIOS/UEFI nastaveni)" }
        return "Nelze zjistit (Legacy BIOS nebo VM)"
    } catch { return "Nelze zjistit (Legacy BIOS nebo VM)" }
}

# -- VBS / Credential Guard / HVCI (jen status) --------------------------------
function Get-VBSStatus {
    try {
        $dg = Get-CimInstance -Namespace "root/Microsoft/Windows/DeviceGuard" -ClassName "Win32_DeviceGuard" -ErrorAction SilentlyContinue
        if (-not $dg) { return "Nedostupne (Win10 Home nebo VM)" }
        $vbsRunning = [int]$dg.VirtualizationBasedSecurityStatus
        $services   = $dg.SecurityServicesRunning
        $vbsLabel   = switch ($vbsRunning) { 0 {"Vypnuto"} 1 {"Zapnuto (nekonfigurovano)"} 2 {"Zapnuto a bezici"} default {"Neznamy"} }
        $credGuard  = if ($services -contains 1) { "Credential Guard: Zapnuto" } else { "" }
        $hvci       = if ($services -contains 2) { "HVCI/Memory Integrity: Zapnuto" } else { "" }
        $parts      = @($vbsLabel) + @($credGuard, $hvci | Where-Object { $_ })
        return $parts -join " | "
    } catch { return "Nelze zjistit" }
}

# ==============================================================================
#     A K T U A L I Z A C E   W I N D O W S   A   S O F T W A R E
# ==============================================================================

# -- Windows Update ------------------------------------------------------------
function Test-PSWindowsUpdate {
    try {
        $module = Get-Module -ListAvailable -Name PSWindowsUpdate -ErrorAction SilentlyContinue
        return ($null -ne $module)
    } catch {
        return $false
    }
}

function Get-WindowsUpdateStatus {
    Write-Host "  Kontroluji Windows Update..." -ForegroundColor Yellow
    Write-Host ""
    
    # Zkusit PSWindowsUpdate modul
    if (Test-PSWindowsUpdate) {
        try {
            Import-Module PSWindowsUpdate -ErrorAction Stop
            Write-Host "  Pouzivam modul PSWindowsUpdate..." -ForegroundColor Cyan
            $updates = Get-WindowsUpdate -MicrosoftUpdate -ErrorAction Stop
            
            return @{
                Updates = $updates
                MissingCount = $updates.Count
                Method = "PSWindowsUpdate"
            }
        } catch {
            Write-Host "  Varovani: PSWindowsUpdate selhal - $_" -ForegroundColor Yellow
        }
    }
    
    # Fallback: Pouzit UsoClient (Windows Update Orchestrator)
    Write-Host "  Pouzivam Windows Update sluzbu..." -ForegroundColor Cyan
    Write-Host "  Spustim kontrolu aktualizaci na pozadi." -ForegroundColor DarkGray
    Write-Host ""
    
    # Spustit kontrolu
    try {
        Start-Process -FilePath "usoclient.exe" -ArgumentList "StartScan" -NoNewWindow -Wait -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
    } catch {
        # Ignorovat chyby - UsoClient nemusi vracat standardni exit code
    }
    
    # Zkusit zjistit z Windows Update logu nebo service
    try {
        $wuService = Get-Service -Name wuauserv -ErrorAction SilentlyContinue
        if ($wuService.Status -ne 'Running') {
            Write-Host "  Windows Update sluzba nebezi. Spoustim..." -ForegroundColor Yellow
            Start-Service -Name wuauserv -ErrorAction Stop
            Start-Sleep -Seconds 2
        }
    } catch {
        Write-Host "  Varovani: Nelze ovladat Windows Update sluzbu." -ForegroundColor Yellow
    }
    
    return @{
        Updates = @()
        MissingCount = -1
        Method = "UsoClient"
    }
}

function Show-WindowsUpdateStatus {
    Write-Header "Stav Windows Update"
    
    Write-Host ""
    Write-Host "  Pro detailni kontrolu aktualizaci doporucujeme:" -ForegroundColor Cyan
    Write-Host "  1. Nastaveni > Windows Update > Zkontrolovat aktualizace" -ForegroundColor White
    Write-Host "  2. Nebo nainstalovat modul: Install-Module PSWindowsUpdate -Force" -ForegroundColor White
    Write-Host ""
    
    $status = Get-WindowsUpdateStatus
    
    if ($status.Method -eq "PSWindowsUpdate" -and $status.MissingCount -ge 0) {
        Write-Host ""
        if ($status.MissingCount -gt 0) {
            Write-Host "  Dostupne aktualizace: " -NoNewline
            Write-Host $status.MissingCount -ForegroundColor Red
            Write-Host ""
            Write-Host "  Seznam aktualizaci:" -ForegroundColor Yellow
            foreach ($update in $status.Updates) {
                $size = if ($update.Size) { " (" + [math]::Round($update.Size/1MB, 1) + " MB)" } else { "" }
                Write-Host "    - $($update.Title)$size" -ForegroundColor White
            }
        } else {
            Write-Host "  System je aktualni!" -ForegroundColor Green
        }
    } else {
        Write-Host ""
        Write-Host "  Kontrola aktualizaci byla spustena na pozadi." -ForegroundColor Green
        Write-Host "  Otevrete Nastaveni > Windows Update pro zobrazeni vysledku." -ForegroundColor Yellow
    }
}

function Start-WindowsUpdate {
    Write-Host ""
    Write-Host "  Spoustim instalaci Windows aktualizaci..." -ForegroundColor Yellow
    Write-Host "  POZOR: Toto muze trvat nekolik minut." -ForegroundColor DarkGray
    Write-Host ""
    # Zkusit PSWindowsUpdate modul
    if (Test-PSWindowsUpdate) {
        try {
            Import-Module PSWindowsUpdate -ErrorAction Stop
            Write-Host "  Pouzivam modul PSWindowsUpdate..." -ForegroundColor Cyan
            Write-Host ""
            
            $updates = Get-WindowsUpdate -MicrosoftUpdate -AcceptAll -Install -AutoReboot -ErrorAction Stop
            
            Write-Host ""
            Write-Host "  Aktualizace dokonceny!" -ForegroundColor Green
            return
        } catch {
            Write-Host "  Varovani: PSWindowsUpdate selhal - $_" -ForegroundColor Yellow
            Write-Host ""
        }
    }
    
    # Fallback: Pouzit UsoClient
    Write-Host "  Spoustim Windows Update pres systemovou sluzbu..." -ForegroundColor Yellow
    Write-Host ""
    
    try {
        # Spustit stahovani a instalaci
        Write-Host "  Spoustim stahovani aktualizaci..." -ForegroundColor Cyan
        Start-Process -FilePath "usoclient.exe" -ArgumentList "StartDownload" -NoNewWindow -Wait -ErrorAction SilentlyContinue
        
        Write-Host "  Spoustim instalaci aktualizaci..." -ForegroundColor Cyan
        Start-Process -FilePath "usoclient.exe" -ArgumentList "StartInstall" -NoNewWindow -Wait -ErrorAction SilentlyContinue
        
        Write-Host ""
        Write-Host "  Pozadavek na instalaci aktualizaci byl odeslan." -ForegroundColor Green
        Write-Host ""
        Write-Host "  Pro sledovani postupu otevrete:" -ForegroundColor Yellow
        Write-Host "  Nastaveni > Windows Update" -ForegroundColor White
        Write-Host ""
        Write-Host "  POZNAMKA: Pro plnou funkcnost doporucujeme nainstalovat:" -ForegroundColor Cyan
        Write-Host "  Install-Module PSWindowsUpdate -Force" -ForegroundColor White
    } catch {
        Write-Host "  CHYBA pri instalaci aktualizaci: $_" -ForegroundColor Red
        Write-Host ""
        Write-Host "  TIP: Spustte Windows Update manualne:" -ForegroundColor Yellow
        Write-Host "  Nastaveni > Windows Update > Zkontrolovat aktualizace" -ForegroundColor White
    }
}

# -- Software Management (Winget) ----------------------------------------------
function Test-WingetAvailable {
    try {
        $null = Get-Command winget -ErrorAction Stop
        return $true
    } catch {
        return $false
    }
}

function Get-InstalledSoftwareList {
    Write-Host "  Nacitam seznam nainstalovaneho software..." -ForegroundColor Yellow
    
    if (-not (Test-WingetAvailable)) {
        Write-Host "  VAROVANI: Winget neni nainstalovan!" -ForegroundColor Red
        Write-Host "  Pouziji alternativni metodu (registry)..." -ForegroundColor Yellow
        
        # Ziskani ze standardnich registru
        $paths = @(
            "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
        )
        
        $apps = foreach ($path in $paths) {
            Get-ItemProperty $path -ErrorAction SilentlyContinue | Where-Object {
                $_.DisplayName -and (-not $_.SystemComponent)
            } | Select-Object DisplayName, DisplayVersion, Publisher
        }
        
        return $apps | Sort-Object DisplayName -Unique
    }
    
    # Pouziti winget
    try {
        $output = winget list 2>&1
        return $output
    } catch {
        Write-Host "  CHYBA pri ziskavani seznamu software: $_" -ForegroundColor Red
        return $null
    }
}

function Show-InstalledSoftware {
    Write-Header "Nainstalovany software"
    Write-Host ""
    
    if (Test-WingetAvailable) {
        Write-Host "  Pouzivam Winget pro seznam software..." -ForegroundColor Cyan
        Write-Host ""
        winget list
    } else {
        Write-Host "  Winget neni dostupny. Zobrazuji z registru..." -ForegroundColor Yellow
        Write-Host ""
        $apps = Get-InstalledSoftwareList
        
        if ($apps) {
            Write-Host "  {0,-50} {1,-15} {2}" -f "Nazev", "Verze", "Vydavatel" -ForegroundColor Cyan
            Write-Host "  $("-" * 100)" -ForegroundColor DarkGray
            foreach ($app in $apps) {
                Write-Host "  {0,-50} {1,-15} {2}" -f $app.DisplayName, $app.DisplayVersion, $app.Publisher
            }
        } else {
            Write-Host "  Zadny software nenalezen." -ForegroundColor Red
        }
    }
}

function Show-UpgradableSoftware {
    Write-Header "Dostupne aktualizace software"
    Write-Host ""
    
    if (-not (Test-WingetAvailable)) {
        Write-Host "  CHYBA: Winget neni nainstalovan!" -ForegroundColor Red
        Write-Host ""
        Write-Host "  Pro automaticke aktualizace software je potreba Winget." -ForegroundColor Yellow
        Write-Host "  Winget je dostupny ve Windows 11 a novejsich verzich Windows 10." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  Instalace Winget:" -ForegroundColor Cyan
        Write-Host "  1. Otevrete Microsoft Store" -ForegroundColor White
        Write-Host "  2. Vyhledejte 'App Installer'" -ForegroundColor White
        Write-Host "  3. Nainstalujte nebo aktualizujte" -ForegroundColor White
        Write-Host ""
        Write-Host "  Nebo stahnete z: https://github.com/microsoft/winget-cli/releases" -ForegroundColor White
        return
    }
    
    Write-Host "  Hledam dostupne aktualizace..." -ForegroundColor Yellow
    Write-Host ""
    
    try {
        winget upgrade
    } catch {
        Write-Host "  CHYBA pri hledani aktualizaci: $_" -ForegroundColor Red
    }
}

function Update-AllSoftware {
    Write-Host ""
    
    if (-not (Test-WingetAvailable)) {
        Write-Host "  CHYBA: Winget neni nainstalovan!" -ForegroundColor Red
        Write-Host "  Nelze provest automatickou aktualizaci software." -ForegroundColor Red
        return
    }
    
    Write-Host "  Spoustim aktualizaci vseho software pres Winget..." -ForegroundColor Yellow
    Write-Host "  POZOR: Toto muze trvat nekolik minut." -ForegroundColor DarkGray
    Write-Host ""
    
    $confirm = Read-Host "  Skutecne chcete aktualizovat vsechny aplikace? (A/N)"
    if ($confirm -ne "A" -and $confirm -ne "a") {
        Write-Host "  Aktualizace zrusena." -ForegroundColor Yellow
        return
    }
    
    Write-Host ""
    try {
        winget upgrade --all --accept-source-agreements --accept-package-agreements
        Write-Host ""
        Write-Host "  Aktualizace dokoncena!" -ForegroundColor Green
    } catch {
        Write-Host "  CHYBA pri aktualizaci: $_" -ForegroundColor Red
    }
}

function Get-UpdatesStatusShort {
    try {
        if (Test-WingetAvailable) {
            $output = winget upgrade 2>&1 | Out-String
            $lines = $output -split "`n"
            $upgradeCount = 0
            foreach ($line in $lines) {
                if ($line -match "^\S+\s+\S+\s+\S+\s+\S+") {
                    $upgradeCount++
                }
            }
            if ($upgradeCount -gt 0) {
                $upgradeCount-- # Odecist hlavicku
            }
            
            if ($upgradeCount -gt 0) {
                return "$upgradeCount dostupnych"
            } else {
                return "Aktualni"
            }
        } else {
            return "Winget N/A"
        }
    } catch {
        return "Neznamy"
    }
}

# ==============================================================================
#                      S U B - M E N U
# ==============================================================================

# -- 1) Defender a ASR ---------------------------------------------------------
function Show-Menu-DefenderASR {
    do {
        Show-Banner
        Write-SubHeader "DEFENDER a ASR" @"
  Windows Defender je vestaveny antivir ve Windows. ASR (Attack Surface
  Reduction) pravidla blokuji bezne techniky utoku - makra, skripty,
  kradeze credentials, exploit ovladacu apod. PUA blokuje nezadouci
  aplikace. CFA chrani slozky pred ransomware. Tamper Protection brani
  malwaru vypnout ochranu Defenderu.
"@

        $asrSum = Get-ASRSummary
        $puaSt  = Get-PUAStatus
        $rtSt   = Get-DefenderRTStatus
        $cfaSt  = Get-CFAStatus
        $tpSt   = Get-TamperProtectionStatus

        Write-Host "  Aktualni stav:" -ForegroundColor DarkGray
        Write-Host "    ASR: $asrSum" -ForegroundColor DarkGray
        Write-Host "    PUA: $puaSt | RT+Cloud: $rtSt | CFA: $cfaSt | Tamper: $tpSt" -ForegroundColor DarkGray
        Write-Host ""

        Write-MenuItem "1"  "ASR pravidla -> Zobrazit detail vsech pravidel"
        Write-MenuItem "2"  "ASR pravidla -> Nastavit VSECHNA na BLOKOVAT [DOPORUCENO]" Green
        Write-MenuItem "3"  "ASR pravidla -> Nastavit VSECHNA na AUDIT"
        Write-MenuItem "4"  "ASR pravidla -> VYPNOUT VSECHNA"
        Write-Host ""
        Write-MenuItem "5"  "PUA ochrana -> BLOKOVAT [DOPORUCENO]" Green
        Write-MenuItem "6"  "PUA ochrana -> AUDIT"
        Write-MenuItem "7"  "PUA ochrana -> VYPNOUT"
        Write-Host ""
        Write-MenuItem "8"  "Defender Real-Time + Cloud -> ZAPNOUT [DOPORUCENO]" Green
        Write-MenuItem "9"  "Defender Real-Time -> VYPNOUT"
        Write-Host ""
        Write-MenuItem "10" "Controlled Folder Access -> ZAPNOUT [DOPORUCENO]" Green
        Write-MenuItem "11" "Controlled Folder Access -> AUDIT"
        Write-MenuItem "12" "Controlled Folder Access -> VYPNOUT"
        Write-Host ""
        Write-MenuItem "13" "Tamper Protection -> ZAPNOUT [DOPORUCENO]" Green
        Write-MenuItem "14" "Tamper Protection -> VYPNOUT (nedoporuceno)"
        Write-Host ""
        Write-MenuItem "15" "Nastavit registry pro zabezpeceni Office [DOPORUCENO]" Green
        Write-MenuItem "16" "Nastavit Defender sandboxing (zapnout) [DOPORUCENO]" Green
        Write-MenuItem "17" "Aktualizovat Defender signatury [DOPORUCENO]" Green
        Write-Host ""
        Write-MenuItem "0"  "<- Zpet do hlavniho menu" Yellow
        Write-Host ""

        $c = Read-MenuChoice
        switch ($c) {
            "1"  { Show-ASRDetail; Pause-Menu }
            "2"  { Set-AllASR -Mode 1; Pause-Menu }
            "3"  { Set-AllASR -Mode 2; Pause-Menu }
            "4"  { Set-AllASR -Mode 0; Pause-Menu }
            "5"  { Set-PUA -Mode 1; Pause-Menu }
            "6"  { Set-PUA -Mode 2; Pause-Menu }
            "7"  { Set-PUA -Mode 0; Pause-Menu }
            "8"  { Set-DefenderRT -Enabled $true; Pause-Menu }
            "9"  { Set-DefenderRT -Enabled $false; Pause-Menu }
            "10" { Set-CFA -Mode 1; Pause-Menu }
            "11" { Set-CFA -Mode 2; Pause-Menu }
            "12" { Set-CFA -Mode 0; Pause-Menu }
            "13" { Set-TamperProtection -Enabled $true; Pause-Menu }
            "14" { Set-TamperProtection -Enabled $false; Pause-Menu }
            "15" { Set-OfficeSecurityRegistry; Pause-Menu }
            "16" { Set-DefenderSandboxing -Enabled $true; Pause-Menu }
            "17" { Update-DefenderSignatures; Pause-Menu }
            "0"  { return }
            default { Write-Host "  Neplatna volba." -ForegroundColor Red; Start-Sleep 1 }
        }
    } while ($true)
}

# -- 2) SmartScreen ------------------------------------------------------------
function Show-Menu-SmartScreen {
    do {
        Show-Banner
        Write-SubHeader "SMARTSCREEN" @"
  SmartScreen chrani pred stahovanim a spoustenim skodlivych souboru,
  phishingem a nebezpecnymi webovymi strankami. Funguje na urovni
  systemu Windows (Explorer) i v prohlizeci Microsoft Edge.
"@

        $ssSt = Get-SmartScreenStatus
        $esSt = Get-EdgeSmartScreenStatus
        Write-Host "  Aktualni stav:" -ForegroundColor DarkGray
        Write-Host "    Windows: $ssSt | Edge: $esSt" -ForegroundColor DarkGray
        Write-Host ""

        Write-MenuItem "1" "SmartScreen (Windows) -> ZAPNOUT [DOPORUCENO]" Green
        Write-MenuItem "2" "SmartScreen (Windows) -> VYPNOUT"
        Write-Host ""
        Write-MenuItem "3" "SmartScreen (Edge) -> ZAPNOUT [DOPORUCENO]" Green
        Write-MenuItem "4" "SmartScreen (Edge) -> VYPNOUT"
        Write-Host ""
        Write-MenuItem "0" "<- Zpet do hlavniho menu" Yellow
        Write-Host ""

        $c = Read-MenuChoice
        switch ($c) {
            "1" { Set-SmartScreen -Mode "RequireAdmin"; Pause-Menu }
            "2" { Set-SmartScreen -Mode "Off"; Pause-Menu }
            "3" { Set-EdgeSmartScreen -Enabled $true; Pause-Menu }
            "4" { Set-EdgeSmartScreen -Enabled $false; Pause-Menu }
            "0" { return }
            default { Write-Host "  Neplatna volba." -ForegroundColor Red; Start-Sleep 1 }
        }
    } while ($true)
}

# -- 3) Sit a Protokoly -------------------------------------------------------
function Show-Menu-Network {
    do {
        Show-Banner
        Write-SubHeader "SIT a PROTOKOLY" @"
  Firewall filtruje sitovy provoz a blokuje neopravnene pripojeni.
  RDP (vzdalena plocha) je casty cil brute-force utoku - doma zbytecny.
  SMBv1 je zastaraly protokol (WannaCry, EternalBlue) - zakazte ho.
  LLMNR umoznuje poisoning utoky v lokalni siti (Responder apod.).
"@

        $fwSt    = Get-FirewallStatus
        $rdpSt   = Get-RDPStatus
        $smbSt   = Get-SMBv1Status
        $llmnrSt = Get-LLMNRStatus
        Write-Host "  Aktualni stav:" -ForegroundColor DarkGray
        Write-Host "    Firewall: $fwSt" -ForegroundColor DarkGray
        Write-Host "    RDP: $rdpSt | SMBv1: $smbSt | LLMNR: $llmnrSt" -ForegroundColor DarkGray
        Write-Host ""

        Write-MenuItem "1" "Windows Firewall -> ZAPNOUT [DOPORUCENO]" Green
        Write-MenuItem "2" "Windows Firewall -> VYPNOUT"
        Write-Host ""
        Write-MenuItem "3" "Vzdalena plocha (RDP) -> ZAKAZAT [DOPORUCENO]" Green
        Write-MenuItem "4" "Vzdalena plocha (RDP) -> POVOLIT"
        Write-Host ""
        Write-MenuItem "5" "SMBv1 -> ZAKAZAT [DOPORUCENO]" Green
        Write-MenuItem "6" "SMBv1 -> POVOLIT"
        Write-Host ""
        Write-MenuItem "7" "LLMNR -> ZAKAZAT [DOPORUCENO]" Green
        Write-MenuItem "8" "LLMNR -> POVOLIT"
        Write-Host ""
        Write-MenuItem "0" "<- Zpet do hlavniho menu" Yellow
        Write-Host ""

        $c = Read-MenuChoice
        switch ($c) {
            "1" { Set-FirewallState -Enabled $true; Pause-Menu }
            "2" { Set-FirewallState -Enabled $false; Pause-Menu }
            "3" { Set-RDPState -Disabled $true; Pause-Menu }
            "4" { Set-RDPState -Disabled $false; Pause-Menu }
            "5" { Set-SMBv1State -Enabled $false; Pause-Menu }
            "6" { Set-SMBv1State -Enabled $true; Pause-Menu }
            "7" { Set-LLMNRState -Disabled $true; Pause-Menu }
            "8" { Set-LLMNRState -Disabled $false; Pause-Menu }
            "0" { return }
            default { Write-Host "  Neplatna volba." -ForegroundColor Red; Start-Sleep 1 }
        }
    } while ($true)
}

# -- 4) System a Logging ------------------------------------------------------
function Show-Menu-System {
    do {
        Show-Banner
        Write-SubHeader "SYSTEM a LOGGING" @"
  AutoRun/AutoPlay automaticky spousti obsah z USB/CD - oblibeny vektor
  sireni malwaru. Zakazanim zabranite automatickemu spusteni.
  PowerShell Script Block Logging zaznamenava vsechny spustene PS skripty
  do Event Logu - klicove pro forenzni analyzu a detekci utoku.
"@

        $arSt = Get-AutoRunStatus
        $psSt = Get-PSLoggingStatus
        Write-Host "  Aktualni stav:" -ForegroundColor DarkGray
        Write-Host "    AutoRun: $arSt | PS Logging: $psSt" -ForegroundColor DarkGray
        Write-Host ""

        Write-MenuItem "1" "AutoRun/AutoPlay -> ZAKAZAT [DOPORUCENO]" Green
        Write-MenuItem "2" "AutoRun/AutoPlay -> POVOLIT"
        Write-Host ""
        Write-MenuItem "3" "PS Script Block Logging -> ZAPNOUT [DOPORUCENO]" Green
        Write-MenuItem "4" "PS Script Block Logging -> VYPNOUT"
        Write-Host ""
        Write-MenuItem "0" "<- Zpet do hlavniho menu" Yellow
        Write-Host ""

        $c = Read-MenuChoice
        switch ($c) {
            "1" { Set-AutoRunState -Disabled $true; Pause-Menu }
            "2" { Set-AutoRunState -Disabled $false; Pause-Menu }
            "3" { Set-PSLogging -Enabled $true; Pause-Menu }
            "4" { Set-PSLogging -Enabled $false; Pause-Menu }
            "0" { return }
            default { Write-Host "  Neplatna volba." -ForegroundColor Red; Start-Sleep 1 }
        }
    } while ($true)
}

# -- 5) Sysmon ----------------------------------------------------------------
function Show-Menu-Sysmon {
    do {
        Show-Banner
        Write-SubHeader "SYSMON - System Monitor" @"
  Sysmon (Sysinternals) je pokrocily monitoring systemovych udalosti -
  sleduje vytvareni procesu, sitova pripojeni, zmeny souboru, registry
  a dalsi. Konfigurace 'sysmon-modular' od Olafa Hartonga je komunitne
  udrzovana sada pravidel optimalizovana pro detekci hrozeb.
  Logy: Event Viewer -> Microsoft-Windows-Sysmon/Operational
"@

        $sysSt = Get-SysmonStatus
        Write-Host "  Aktualni stav:" -ForegroundColor DarkGray
        Write-Host "    Sysmon: $sysSt" -ForegroundColor DarkGray
        Write-Host ""

        Write-MenuItem "1" "Instalovat Sysmon64 + konfigurace (stahne z internetu)"
        Write-MenuItem "2" "Aktualizovat konfiguraci (stahne nejnovejsi pravidla)"
        Write-MenuItem "3" "Instalovat/Aktualizovat s VLASTNI XML konfiguraci"
        Write-MenuItem "4" "Odinstalovat Sysmon"
        Write-Host ""
        Write-MenuItem "0" "<- Zpet do hlavniho menu" Yellow
        Write-Host ""

        $c = Read-MenuChoice
        switch ($c) {
            "1" { Install-Sysmon; Pause-Menu }
            "2" { Update-SysmonConfig; Pause-Menu }
            "3" { Use-CustomSysmonConfig; Pause-Menu }
            "4" { Uninstall-Sysmon; Pause-Menu }
            "0" { return }
            default { Write-Host "  Neplatna volba." -ForegroundColor Red; Start-Sleep 1 }
        }
    } while ($true)
}

# -- 6) Bezpecne DNS ----------------------------------------------------------
function Show-Menu-DNS {
    do {
        Show-Banner
        Write-SubHeader "BEZPECNE DNS" @"
  DNS (Domain Name System) preklada jmena webovych stranek na IP adresy.
  Bezpecne DNS servery mohou blokovat pristup ke skodlivym domenam
  (phishing, malware, C2 servery) nebo i obsah pro dospele.
  Cloudflare 1.1.1.2/1.0.0.2 blokuje malware domeny.
  Cloudflare 1.1.1.3/1.0.0.3 blokuje malware + obsah pro dospele.
"@

        Write-Host "  Aktualni DNS:" -ForegroundColor DarkGray
        Show-DNSDetail
        Write-Host ""

        Write-MenuItem "1" "Zobrazit detail DNS na vsech adapterech"
        Write-Host ""
        Write-Host "    Nastavit DNS profil:" -ForegroundColor Cyan
        Write-MenuItem "2" "Cloudflare 1.1.1.2 / 1.0.0.2 - Blokace malware [DOPORUCENO]" Green
        Write-MenuItem "3" "Cloudflare 1.1.1.3 / 1.0.0.3 - Blokace malware + dospely obsah [DOPORUCENO]" Green
        Write-MenuItem "4" "Cloudflare 1.1.1.1 / 1.0.0.1 - Standardni (bez filtrace)"
        Write-Host ""
        Write-MenuItem "5" "Resetovat DNS na automaticke (DHCP)" Yellow
        Write-Host ""
        Write-MenuItem "0" "<- Zpet do hlavniho menu" Yellow
        Write-Host ""

        $c = Read-MenuChoice
        switch ($c) {
            "1" { Show-DNSDetail; Pause-Menu }
            "2" { Set-SecureDNS -ProfileKey "cloudflare_malware"; Pause-Menu }
            "3" { Set-SecureDNS -ProfileKey "cloudflare_family"; Pause-Menu }
            "4" { Set-SecureDNS -ProfileKey "cloudflare_standard"; Pause-Menu }
            "5" { Reset-DNS; Pause-Menu }
            "0" { return }
            default { Write-Host "  Neplatna volba." -ForegroundColor Red; Start-Sleep 1 }
        }
    } while ($true)
}

# -- 7) Dalsi doporucena nastaveni ---------------------------------------------
function Show-Menu-Hardening {
    do {
        Show-Banner
        Write-SubHeader "DALSI DOPORUCENA NASTAVENI" @"
  LM Hash: Stary a slaby format pro ukladani hesel. Je dobre ho zakazat.
    Sticky Keys: Pokud je u sethc.exe nastaven Debugger, jde o bezpecnostni
    riziko. Bezpecny stav je vychozi chovani bez vlastniho Debuggeru.
  BitLocker: Sifrovani disku je klicova ochrana dat pri kradezi zarizeni.
"@

        $lmSt  = Get-LMHashStatus
        $skSt  = Get-StickyKeysStatus
        $blSt  = Get-BitLockerStatus
        Write-Host "  Aktualni stav:" -ForegroundColor DarkGray
        Write-Host "    LM Hash: $lmSt | Sticky Keys: $skSt | BitLocker: $blSt" -ForegroundColor DarkGray
        Write-Host ""

        Write-MenuItem "1" "Zakazat ukladani LM hashe [DOPORUCENO]" Green
        Write-MenuItem "2" "Povolit ukladani LM hashe"
        Write-Host ""
        Write-MenuItem "3" "Odstranit Debugger u Sticky Keys [DOPORUCENO]" Green
        Write-MenuItem "4" "Ponechat vychozi bezpecny stav Sticky Keys"
        Write-Host ""
        Write-MenuItem "5" "Zobrazit stav a navod pro BitLocker"
        Write-Host ""
        Write-MenuItem "0" "<- Zpet do hlavniho menu" Yellow
        Write-Host ""

        $c = Read-MenuChoice
        switch ($c) {
            "1" { Set-LMHashState -Disabled $true; Pause-Menu }
            "2" { Set-LMHashState -Disabled $false; Pause-Menu }
            "3" { Set-StickyKeysState -Secured $true; Pause-Menu }
            "4" { Set-StickyKeysState -Secured $false; Pause-Menu }
            "5" { Show-BitLockerHelp; Pause-Menu }
            "0" { return }
            default { Write-Host "  Neplatna volba." -ForegroundColor Red; Start-Sleep 1 }
        }
    } while ($true)
}

# -- 9) Pokrocile zabezpeceni -------------------------------------------------
function Show-Menu-Advanced {
    do {
        Show-Banner
        Write-SubHeader "POKROCILE ZABEZPECENI" @"
  Tato sekce obsahuje pokrocila nastaveni proti kradezi hesel (Mimikatz),
  zneuziti skriptovacich jazyku (.vbs/.js), slabeho NTLM autentizace
  a dalsich vektoru utoku beznych pri kompromitaci domacich PC.
  DOPORUCENO: Spustit vsechny polozky oznacene [DOPORUCENO].
"@

        Write-Host "  Aktualni stav:" -ForegroundColor DarkGray
        Write-Host "    WDigest      : " -NoNewline -ForegroundColor DarkGray; Write-Host (Get-WDigestStatus)           -ForegroundColor Cyan
        Write-Host "    LSA PPL      : " -NoNewline -ForegroundColor DarkGray; Write-Host (Get-LSAPPLStatus)            -ForegroundColor Cyan
        Write-Host "    Net Protect  : " -NoNewline -ForegroundColor DarkGray; Write-Host (Get-NetworkProtectionStatus) -ForegroundColor Cyan
        Write-Host "    NetBIOS      : " -NoNewline -ForegroundColor DarkGray; Write-Host (Get-NetBIOSStatus)           -ForegroundColor Cyan
        Write-Host "    NTLM uroven  : " -NoNewline -ForegroundColor DarkGray; Write-Host (Get-NTLMStatus)              -ForegroundColor Cyan
        Write-Host "    WSH          : " -NoNewline -ForegroundColor DarkGray; Write-Host (Get-WSHStatus)               -ForegroundColor Cyan
        Write-Host "    UAC          : " -NoNewline -ForegroundColor DarkGray; Write-Host (Get-UACStatus)               -ForegroundColor Cyan
        Write-Host "    Event Logy   : " -NoNewline -ForegroundColor DarkGray; Write-Host (Get-EventLogSizeStatus)      -ForegroundColor Cyan
        Write-Host "    Rem. Registry: " -NoNewline -ForegroundColor DarkGray; Write-Host (Get-RemoteRegistryStatus)    -ForegroundColor Cyan
        Write-Host "    Secure Boot  : " -NoNewline -ForegroundColor DarkGray; Write-Host (Get-SecureBootStatus)        -ForegroundColor Cyan
        Write-Host "    VBS/HVCI     : " -NoNewline -ForegroundColor DarkGray; Write-Host (Get-VBSStatus)               -ForegroundColor Cyan
        Write-Host ""

        Write-Host "    WDigest (hesla v pameti - Mimikatz):" -ForegroundColor Cyan
        Write-MenuItem "1"  "Zakazat WDigest (bez plaintextovych hesel v RAM) [DOPORUCENO]" Green
        Write-MenuItem "2"  "Povolit WDigest"
        Write-Host ""
        Write-Host "    LSA Protected Process (ochrana lsass.exe):" -ForegroundColor Cyan
        Write-MenuItem "3"  "Zapnout LSA PPL - ochrana pred Mimikatz [DOPORUCENO]" Green
        Write-MenuItem "4"  "Vypnout LSA PPL"
        Write-Host ""
        Write-Host "    Defender Network Protection:" -ForegroundColor Cyan
        Write-MenuItem "5"  "Zapnout Network Protection - BLOKOVAT [DOPORUCENO]" Green
        Write-MenuItem "6"  "Zapnout Network Protection - AUDIT (jen log)"
        Write-MenuItem "7"  "Vypnout Network Protection"
        Write-Host ""
        Write-Host "    NetBIOS over TCP/IP (ochrana pred Responder utoky v LAN):" -ForegroundColor Cyan
        Write-MenuItem "8"  "Zakazat NetBIOS [DOPORUCENO]" Green
        Write-MenuItem "9"  "Povolit NetBIOS"
        Write-Host ""
        Write-Host "    NTLMv2 autentizace:" -ForegroundColor Cyan
        Write-MenuItem "10" "Nastavit pouze NTLMv2 - uroven 5 (nejsilnejsi) [DOPORUCENO]" Green
        Write-MenuItem "11" "Nastavit NTLMv2 + NTLM - uroven 3 (Windows vychozi)"
        Write-Host ""
        Write-Host "    Windows Script Host (.vbs/.js/.wsf soubory):" -ForegroundColor Cyan
        Write-MenuItem "12" "Zakazat Windows Script Host [DOPORUCENO]" Green
        Write-MenuItem "13" "Povolit Windows Script Host"
        Write-Host ""
        Write-Host "    UAC (rizeni uzivatelskych uctu):" -ForegroundColor Cyan
        Write-MenuItem "14" "UAC na MAXIMUM (prihlaseni + bezpecnostni plocha) [DOPORUCENO]" Green
        Write-MenuItem "15" "UAC na STANDARD (vyzva na bezpecnostni plose)"
        Write-MenuItem "16" "UAC obnovit na Windows vychozi"
        Write-Host ""
        Write-Host "    Event Log retence:" -ForegroundColor Cyan
        Write-MenuItem "17" "Zvetsit Event Logy (Security 512MB, System 128MB atd.) [DOPORUCENO]" Green
        Write-Host ""
        Write-Host "    Remote Registry sluzba:" -ForegroundColor Cyan
        Write-MenuItem "18" "Zakazat Remote Registry sluzbu [DOPORUCENO]" Green
        Write-MenuItem "19" "Obnovit Remote Registry na Manual"
        Write-Host ""
        Write-Host "    LSA Registry Audit:" -ForegroundColor Cyan
        Write-MenuItem "20" "Zobrazit kompletni LSA registry protection audit" Cyan
        Write-MenuItem "21" "Zapnout auditovani zmen LSA klice (Event ID 4657/4663)" Green
        Write-Host ""
        Write-MenuItem "0"  "<- Zpet do hlavniho menu" Yellow
        Write-Host ""

        $c = Read-MenuChoice
        switch ($c) {
            "1"  { Set-WDigest -Disabled $true;           Pause-Menu }
            "2"  { Set-WDigest -Disabled $false;          Pause-Menu }
            "3"  { Set-LSAPPL -Enabled $true;             Pause-Menu }
            "4"  { Set-LSAPPL -Enabled $false;            Pause-Menu }
            "5"  { Set-NetworkProtection -Mode 1;         Pause-Menu }
            "6"  { Set-NetworkProtection -Mode 2;         Pause-Menu }
            "7"  { Set-NetworkProtection -Mode 0;         Pause-Menu }
            "8"  { Set-NetBIOSState -Disabled $true;      Pause-Menu }
            "9"  { Set-NetBIOSState -Disabled $false;     Pause-Menu }
            "10" { Set-NTLMLevel -Level 5;                Pause-Menu }
            "11" { Set-NTLMLevel -Level 3;                Pause-Menu }
            "12" { Set-WSHState -Disabled $true;          Pause-Menu }
            "13" { Set-WSHState -Disabled $false;         Pause-Menu }
            "14" { Set-UACLevel -Level 0;                 Pause-Menu }
            "15" { Set-UACLevel -Level 1;                 Pause-Menu }
            "16" { Set-UACLevel -Level 2;                 Pause-Menu }
            "17" { Set-EventLogSize;                      Pause-Menu }
            "18" { Set-RemoteRegistryState -Disabled $true;  Pause-Menu }
            "19" { Set-RemoteRegistryState -Disabled $false; Pause-Menu }
            "20" { Show-LSARegistryAudit;                    Pause-Menu }
            "21" { Enable-LSARegistryAuditing;               Pause-Menu }
            "0"  { return }
            default { Write-Host "  Neplatna volba." -ForegroundColor Red; Start-Sleep 1 }
        }
    } while ($true)
}

# -- 8) Aktualizace a Software -------------------------------------------------
function Show-Menu-UpdatesAndSoftware {
    do {
        Show-Banner
        Write-SubHeader "AKTUALIZACE A SOFTWARE" @"
  Pravidelne aktualizace Windows a nainstalovaneho software jsou klicove
  pro bezpecnost systemu. Zde muzete zkontrolovat dostupne aktualizace
  Windows, zobrazit nainstalovany software a aktualizovat aplikace pomoci
  Winget (Windows Package Manager).

  POZNAMKA: Zjistovani stavu aktualizaci muze chvili trvat. Informace
  o dostupnych aktualizacich se zobrazi po vyberu prislusne volby.
"@

        Write-Host "  WINDOWS UPDATE:" -ForegroundColor Cyan
        Write-MenuItem "1" "Zobrazit stav Windows aktualizaci"
        Write-MenuItem "2" "Spustit instalaci Windows aktualizaci [DOPORUCENO]" Green
        Write-Host ""
        
        Write-Host "  SOFTWARE (WINGET):" -ForegroundColor Cyan
        Write-MenuItem "3" "Zobrazit nainstalovany software"
        Write-MenuItem "4" "Zobrazit dostupne aktualizace software"
        Write-MenuItem "5" "Aktualizovat vsechny aplikace [DOPORUCENO]" Green
        Write-Host ""
        
        Write-MenuItem "0" "<- Zpet do hlavniho menu" Yellow
        Write-Host ""

        $c = Read-MenuChoice
        switch ($c) {
            "1" { Show-WindowsUpdateStatus; Pause-Menu }
            "2" { Start-WindowsUpdate; Pause-Menu }
            "3" { Show-InstalledSoftware; Pause-Menu }
            "4" { Show-UpgradableSoftware; Pause-Menu }
            "5" { Update-AllSoftware; Pause-Menu }
            "0" { return }
            default { Write-Host "  Neplatna volba." -ForegroundColor Red; Start-Sleep 1 }
        }
    } while ($true)
}

function Start-SecureMode {
do {
    Show-Banner
    Write-Host ""
    Write-Host "  +------------------------------------------------------------+" -ForegroundColor DarkGray
    Write-Host "  |                      HLAVNI MENU                           |" -ForegroundColor Cyan
    Write-Host "  +------------------------------------------------------------+" -ForegroundColor DarkGray
    Write-Host ""

    # Quick-status
    $rtQ  = Get-DefenderRTStatus
    $asrQ = Get-ASRSummary
    $ssQ  = Get-SmartScreenStatus
    $fwQ  = Get-FirewallStatus
    $syQ  = Get-SysmonStatus
    $arQ  = Get-AutoRunStatus
    $psQ  = Get-PSLoggingStatus
    $dnsQ = Get-DNSStatusShort
    $blQ  = Get-BitLockerStatus

    $rtC  = if ($rtQ -eq "Vse zapnuto") { 'Green' } elseif ($rtQ -eq "Vse vypnuto") { 'Red' } else { 'Yellow' }
    $ssC  = if ($ssQ -match "Zapnuto") { 'Green' } elseif ($ssQ -eq "Vypnuto") { 'Red' } else { 'Yellow' }
    $fwC  = if ($fwQ -match "Zapnuto") { 'Green' } elseif ($fwQ -eq "Vypnuto") { 'Red' } else { 'Yellow' }
    $syC  = if ($syQ -match "Bezi") { 'Green' } elseif ($syQ -match "Nenainstalovan") { 'Red' } else { 'Yellow' }
    $arC  = if ($arQ -match "Zakazano") { 'Green' } elseif ($arQ -match "Povoleno") { 'Red' } else { 'Yellow' }
    $psC  = if ($psQ -eq "Zapnuto") { 'Green' } else { 'Red' }
    $blC  = if ($blQ -match "Zapnuto") { 'Green' } elseif ($blQ -match "Vypnuto") { 'Red' } else { 'Yellow' }

    Write-Host "    1)  Defender a ASR" -ForegroundColor White -NoNewline
    Write-Host "           [RT: " -NoNewline -ForegroundColor DarkGray
    Write-Host "$rtQ" -NoNewline -ForegroundColor $rtC
    Write-Host "]" -ForegroundColor DarkGray
    Write-Host "        ASR: $asrQ" -ForegroundColor DarkGray
    Write-Host ""

    Write-Host "    2)  SmartScreen" -ForegroundColor White -NoNewline
    Write-Host "              [" -NoNewline -ForegroundColor DarkGray
    Write-Host "$ssQ" -NoNewline -ForegroundColor $ssC
    Write-Host "]" -ForegroundColor DarkGray
    Write-Host ""

    Write-Host "    3)  Sit a Protokoly" -ForegroundColor White -NoNewline
    Write-Host "          [FW: " -NoNewline -ForegroundColor DarkGray
    Write-Host "$fwQ" -NoNewline -ForegroundColor $fwC
    Write-Host "]" -ForegroundColor DarkGray
    Write-Host ""

    Write-Host "    4)  System a Logging" -ForegroundColor White -NoNewline
    Write-Host "         [AutoRun: " -NoNewline -ForegroundColor DarkGray
    Write-Host "$arQ" -NoNewline -ForegroundColor $arC
    Write-Host " | PS: " -NoNewline -ForegroundColor DarkGray
    Write-Host "$psQ" -NoNewline -ForegroundColor $psC
    Write-Host "]" -ForegroundColor DarkGray
    Write-Host ""

    Write-Host "    5)  Sysmon" -ForegroundColor White -NoNewline
    Write-Host "                    [" -NoNewline -ForegroundColor DarkGray
    Write-Host "$syQ" -NoNewline -ForegroundColor $syC
    Write-Host "]" -ForegroundColor DarkGray
    Write-Host ""

    $dnsC = if ($dnsQ -match "1\.1\.1\.[23]") { 'Green' } elseif ($dnsQ -match "DHCP|auto") { 'Yellow' } else { 'Cyan' }
    Write-Host "    6)  Bezpecne DNS" -ForegroundColor White -NoNewline
    Write-Host "               [" -NoNewline -ForegroundColor DarkGray
    Write-Host "$dnsQ" -NoNewline -ForegroundColor $dnsC
    Write-Host "]" -ForegroundColor DarkGray
    Write-Host ""

    Write-Host "    7)  Dalsi doporucena nastaveni" -ForegroundColor White -NoNewline
    Write-Host " [BitLocker: " -NoNewline -ForegroundColor DarkGray
    Write-Host "$blQ" -NoNewline -ForegroundColor $blC
    Write-Host "]" -ForegroundColor DarkGray
    Write-Host ""

    Write-Host "    8)  Aktualizace a Software" -ForegroundColor White
    Write-Host ""

    Write-Host "    9)  Pokrocile zabezpeceni" -ForegroundColor White -NoNewline
    $advItems = @()
    if ((Get-WDigestStatus) -notmatch "bezpecne|Nenastaveno") { $advItems += "WDigest!" }
    if ((Get-LSAPPLStatus) -match "Vypnuto") { $advItems += "LSA!" }
    if ((Get-NetworkProtectionStatus) -match "Vypnuto") { $advItems += "NetProt!" }
    if ((Get-WSHStatus) -match "Povoleno") { $advItems += "WSH!" }
    if ($advItems.Count -gt 0) {
        Write-Host " [" -NoNewline -ForegroundColor DarkGray
        Write-Host ($advItems -join " ") -NoNewline -ForegroundColor Red
        Write-Host "]" -ForegroundColor DarkGray
    } else {
        Write-Host " [OK]" -ForegroundColor Green
    }
    Write-Host ""

    Write-Host "   10)  ZAPNOUT VSE (maximum zabezpeceni)" -ForegroundColor Green
    Write-Host "   99)  Aktualni stav - kompletni prehled" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "    0)  Konec" -ForegroundColor Yellow
    Write-Host ""

    $mainChoice = Read-MenuChoice

    switch ($mainChoice) {
        "1"  { Show-Menu-DefenderASR }
        "2"  { Show-Menu-SmartScreen }
        "3"  { Show-Menu-Network }
        "4"  { Show-Menu-System }
        "5"  { Show-Menu-Sysmon }
        "6"  { Show-Menu-DNS }
        "7"  { Show-Menu-Hardening }
        "8"  { Show-Menu-UpdatesAndSoftware }
        "9"  { Show-Menu-Advanced }
        "10" { Enable-MaxSecurity; Pause-Menu }
        "99" { Show-FullStatus; Pause-Menu }
        "0"  {
            Write-Host ""
            Write-Host "  Ukoncuji. Zustan v bezpeci!" -ForegroundColor Cyan
            Write-Host ""
        }
        default {
            Write-Host "  Neplatna volba, zkuste znovu." -ForegroundColor Red
            Start-Sleep -Seconds 1
        }
    }
} while ($mainChoice -ne "0")
}

# ==============================================================================
#   M O D U L   2 :   M O N I T O R I N G   a   A U D I T
# ==============================================================================
function Show-FailedLogins {
    param([int]$MaxEvents = 50)
    
    Write-Header "Neuspesne pokusy o prihlaseni (Event ID 4625)"
    Write-Host "  Posledni neuspesna prihlaseni (max: $MaxEvents):" -ForegroundColor Yellow
    Write-Host ""
    
    try {
        $events = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} -MaxEvents $MaxEvents -ErrorAction SilentlyContinue
        
        if ($events) {
            $events | ForEach-Object {
                $time = $_.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                
                # Parse properties directly (Constrained Language Mode compatible)
                # Event 4625 structure: [5]=TargetUserName, [6]=TargetDomainName, [10]=LogonType, 
                # [13]=WorkstationName, [19]=SourceNetworkAddress, [7]=Status
                $targetUser = $_.Properties[5].Value
                $targetDomain = $_.Properties[6].Value
                $failureReason = if ($_.Properties.Count -gt 7) { $_.Properties[7].Value } else { "N/A" }
                $logonType = if ($_.Properties.Count -gt 10) { $_.Properties[10].Value } else { "N/A" }
                $workstation = if ($_.Properties.Count -gt 13) { $_.Properties[13].Value } else { "N/A" }
                $ipAddress = if ($_.Properties.Count -gt 19) { $_.Properties[19].Value } else { "N/A" }
                
                Write-Host "  [$time]" -ForegroundColor Red
                Write-Host "    Uzivatel   : $targetDomain\$targetUser" -ForegroundColor White
                Write-Host "    Stanice    : $workstation" -ForegroundColor Gray
                Write-Host "    IP Adresa  : $ipAddress" -ForegroundColor Gray
                Write-Host "    Typ Log    : $logonType" -ForegroundColor Gray
                Write-Host "    Kod chyby  : $failureReason" -ForegroundColor Gray
                Write-Host ""
            }
            Write-Host "  Celkem nalezeno: $($events.Count) udalosti" -ForegroundColor Cyan
        } else {
            Write-Host "  Zadne neuspesne pokusy o prihlaseni nenalezeny." -ForegroundColor Green
        }
    } catch {
        Write-Host "  CHYBA: Nelze nacist security log. $_" -ForegroundColor Red
    }
}

function Show-SuccessfulLogins {
    param([int]$MaxEvents = 50)
    
    Write-Header "Uspesna prihlaseni (Event ID 4624)"
    Write-Host "  Posledni uspesna prihlaseni (max: $MaxEvents):" -ForegroundColor Yellow
    Write-Host ""
    
    try {
        $events = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} -MaxEvents $MaxEvents -ErrorAction SilentlyContinue
        
        if ($events) {
            $events | ForEach-Object {
                $time = $_.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                
                # Parse properties directly (Constrained Language Mode compatible)
                $targetUser    = if ($_.Properties.Count -gt 5)  { $_.Properties[5].Value  } else { "N/A" }
                $targetDomain  = if ($_.Properties.Count -gt 6)  { $_.Properties[6].Value  } else { "N/A" }
                $logonType     = if ($_.Properties.Count -gt 8)  { $_.Properties[8].Value  } else { "N/A" }
                $workstation   = if ($_.Properties.Count -gt 11) { $_.Properties[11].Value } else { "N/A" }
                $ipAddress     = if ($_.Properties.Count -gt 18) { $_.Properties[18].Value } else { "N/A" }
                
                # Filtruj systemove ucty a service logony
                if ($targetUser -match '^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE|DWM-\d+|UMFD-\d+|\$)$') {
                    return
                }
                
                Write-Host "  [$time]" -ForegroundColor Green
                Write-Host "    Uzivatel   : $targetDomain\$targetUser" -ForegroundColor White
                Write-Host "    Stanice    : $workstation" -ForegroundColor Gray
                Write-Host "    IP Adresa  : $ipAddress" -ForegroundColor Gray
                Write-Host "    Typ Log    : $logonType" -ForegroundColor Gray
                Write-Host ""
            }
            Write-Host "  Celkem nalezeno: $($events.Count) udalosti" -ForegroundColor Cyan
        } else {
            Write-Host "  Zadna uspesna prihlaseni nenalezena." -ForegroundColor Yellow
        }
    } catch {
        Write-Host "  CHYBA: Nelze nacist security log. $_" -ForegroundColor Red
    }
}

function Show-SecurityEvents {
    param([int]$MaxEvents = 100)
    
    Write-Header "Kriticke bezpecnostni udalosti"
    Write-Host "  Kontroluji Security log na kriticke udalosti..." -ForegroundColor Yellow
    Write-Host ""

    # Popisy Event IDs v cestine
    $eventDescriptions = @{
        1102 = "SECURITY LOG VYMAZAN - KRITICKA UDALOST!"
        4616 = "Systemovy cas byl zmenen"
        4648 = "Prihlaseni s explicitnimi credentials (Pass-the-Hash?)"
        4697 = "Nova sluzba nainstalovĂˇna"
        4698 = "Novy scheduled task vytvoren"
        4702 = "Scheduled task upraven"
        4720 = "Novy uzivatelsky ucet vytvoren"
        4722 = "Uzivatelsky ucet aktivovan"
        4724 = "Pokus o reset hesla"
        4726 = "Uzivatelsky ucet smazan"
        4728 = "Clen pridan do bezpecnostni skupiny"
        4732 = "Clen pridan do lokalni skupiny"
        4740 = "Uzivatelsky ucet zablokovan (brute-force?)"
        4756 = "Clen pridan do univerzalni skupiny"
    }

    # Nejdrive zkontroluj Event ID 1102 (smazani security logu) - System log
    try {
        $logCleared = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=1102} -MaxEvents 5 -ErrorAction SilentlyContinue
        if ($logCleared) {
            Write-Host "  +----------------------------------------------------------+" -ForegroundColor Red
            Write-Host "  |  !!! KRITICKE: SECURITY LOG BYL VYMAZAN !!!              |" -ForegroundColor Red
            Write-Host "  |  Toto je typicky znak utocnika mazajiciho stopy!          |" -ForegroundColor Red
            Write-Host "  +----------------------------------------------------------+" -ForegroundColor Red
            Write-Host ""
            $logCleared | ForEach-Object {
                Write-Host "  [$($_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))] Log vymazan" -ForegroundColor Red
                Write-Host "    Subjekt: $($_.Properties[0].Value)" -ForegroundColor Yellow
                Write-Host ""
            }
        }
    } catch { }

    try {
        $criticalIDs = @(4616, 4648, 4697, 4698, 4702, 4720, 4722, 4724, 4726, 4728, 4732, 4740, 4756)
        $events = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=$criticalIDs} -MaxEvents $MaxEvents -ErrorAction SilentlyContinue
        
        if ($events) {
            $events | ForEach-Object {
                $time    = $_.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                $eventID = $_.Id
                $desc    = if ($eventDescriptions.ContainsKey($eventID)) { $eventDescriptions[$eventID] } else { "Udalost ID $eventID" }
                $isHighRisk = $eventID -in @(4697, 4698, 4702, 4726, 4740, 4648, 4616)
                $color   = if ($isHighRisk) { 'Red' } else { 'Yellow' }
                $message = $_.Message.Split("`n")[0]
                
                Write-Host "  [$time] ID: $eventID" -ForegroundColor $color -NoNewline
                Write-Host " - $desc" -ForegroundColor White
                Write-Host "    $message" -ForegroundColor Gray
                Write-Host ""
            }
            Write-Host "  Celkem nalezeno: $($events.Count) udalosti" -ForegroundColor Cyan
        } else {
            Write-Host "  Zadne kriticke udalosti nenalezeny." -ForegroundColor Green
        }
    } catch {
        Write-Host "  CHYBA: Nelze nacist security log. $_" -ForegroundColor Red
    }
}

# ==============================================================================
#           S P U S T E N E   P R O C E S Y
# ==============================================================================

function Get-ProcessSignature {
    param([string]$Path)
    
    if ([string]::IsNullOrEmpty($Path)) {
        return "N/A"
    }
    
    if (-not (Test-Path $Path)) {
        return "N/A"
    }
    
    try {
        $sig = Get-AuthenticodeSignature -FilePath $Path -ErrorAction SilentlyContinue
        if ($sig -and $sig.Status -eq 'Valid') {
            $signer = $sig.SignerCertificate.Subject
            if ($signer -match 'CN=([^,]+)') {
                return $matches[1]
            }
            return "Podepsano"
        } elseif ($sig -and $sig.Status -eq 'NotSigned') {
            return "Nepodepsano"
        } else {
            return "Neplatny podpis"
        }
    } catch {
        return "Chyba"
    }
}

function Show-RunningProcesses {
    param([switch]$ShowAll)
    
    Write-Header "Spustene procesy a digitalni podpisy"
    Write-Host "  Nacitam procesy a kontroluji podpisy..." -ForegroundColor Yellow
    Write-Host ""
    
    try {
        $processes = Get-Process | Sort-Object -Property CPU -Descending
        
        $count = 0
        foreach ($proc in $processes) {
            # Pokud neni ShowAll, preskoc systemove procesy
            if (-not $ShowAll -and $proc.Name -match '^(System|Registry|Idle|smss|csrss|wininit|services|lsass|svchost|dwm)$') {
                continue
            }
            
            $count++
            $path = try { $proc.MainModule.FileName } catch { "N/A" }
            $signature = if ($path -ne "N/A") { Get-ProcessSignature -Path $path } else { "N/A" }
            
            $sigColor = switch -Regex ($signature) {
                '^Microsoft' { 'Green' }
                'Podepsano' { 'Cyan' }
                'Nepodepsano' { 'Red' }
                'Neplatny' { 'Magenta' }
                default { 'Gray' }
            }
            
            Write-Host "  $($proc.Name) " -NoNewline -ForegroundColor White
            Write-Host "[PID: $($proc.Id)]" -NoNewline -ForegroundColor DarkGray
            Write-Host " - " -NoNewline
            Write-Host "$signature" -ForegroundColor $sigColor
            
            if ($path -ne "N/A") {
                Write-Host "    Cesta: $path" -ForegroundColor DarkGray
            }
            
            # Zobraz CPU a Memory
            $cpu = if ($proc.CPU) { [math]::Round($proc.CPU, 2) } else { 0 }
            $mem = [math]::Round($proc.WorkingSet64 / 1MB, 2)
            Write-Host "    CPU: $cpu s | RAM: $mem MB" -ForegroundColor DarkGray
            Write-Host ""
            
            # Omezeni vystupu pro lepsi citelnost
            if (-not $ShowAll -and $count -ge 30) {
                Write-Host "  ... (zobrazeno prvnich 30 procesu, pouzijte 'Show-All' pro vice)" -ForegroundColor Yellow
                break
            }
        }
        
        Write-Host "  Celkem procesu: $($processes.Count)" -ForegroundColor Cyan
    } catch {
        Write-Host "  CHYBA: Nelze nacist procesy. $_" -ForegroundColor Red
    }
}

function Show-UnsignedProcesses {
    Write-Header "Nepodepsane nebo podezrele procesy"
    Write-Host "  Hledam nepodepsane a potencialne nebezpecne procesy..." -ForegroundColor Yellow
    Write-Host ""
    
    try {
        $processes = Get-Process
        $suspiciousCount = 0
        
        foreach ($proc in $processes) {
            # Preskoc zakladni systemove procesy
            if ($proc.Name -match '^(System|Registry|Idle|smss|csrss|wininit|services)$') {
                continue
            }
            
            $path = try { $proc.MainModule.FileName } catch { $null }
            
            if ($path) {
                $signature = Get-ProcessSignature -Path $path
                
                # Oznac podezrele
                if ($signature -match 'Nepodepsano|Neplatny') {
                    $suspiciousCount++
                    Write-Host "  [!] $($proc.Name) " -NoNewline -ForegroundColor Red
                    Write-Host "[PID: $($proc.Id)]" -ForegroundColor DarkGray
                    Write-Host "      Cesta: $path" -ForegroundColor Gray
                    Write-Host "      Stav : $signature" -ForegroundColor Yellow
                    Write-Host ""
                }
            }
        }
        
        if ($suspiciousCount -gt 0) {
            Write-Host "  Celkem nalezeno: $suspiciousCount podezrelych procesu" -ForegroundColor Red
        } else {
            Write-Host "  Vsechny procesy jsou bud podepsane nebo systemove." -ForegroundColor Green
        }
    } catch {
        Write-Host "  CHYBA: Nelze analyzovat procesy. $_" -ForegroundColor Red
    }
}

# ==============================================================================
#           O T E V R E N E   P O R T Y
# ==============================================================================

function Show-OpenPorts {
    Write-Header "Otevrene TCP porty a programy"
    Write-Host "  Porty v rezimu LISTEN a jejich procesy:" -ForegroundColor Yellow
    Write-Host ""
    
    try {
        $connections = Get-NetTCPConnection -State Listen -ErrorAction Stop | Sort-Object LocalPort
        
        foreach ($conn in $connections) {
            $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
            $procName = if ($proc) { $proc.Name } else { "Neznamy" }
            $path = if ($proc) { try { $proc.MainModule.FileName } catch { "N/A" } } else { "N/A" }
            
            $localAddr = $conn.LocalAddress
            $localPort = $conn.LocalPort
            
            Write-Host "  Port: " -NoNewline
            Write-Host "$localPort " -NoNewline -ForegroundColor Cyan
            Write-Host "[$localAddr] " -NoNewline -ForegroundColor DarkGray
            Write-Host "-> " -NoNewline
            Write-Host "$procName " -NoNewline -ForegroundColor White
            Write-Host "[PID: $($conn.OwningProcess)]" -ForegroundColor DarkGray
            
            if ($path -ne "N/A") {
                Write-Host "     Cesta: $path" -ForegroundColor DarkGray
            }
            Write-Host ""
        }
        
        Write-Host "  Celkem otevrenych portu: $($connections.Count)" -ForegroundColor Cyan
    } catch {
        Write-Host "  CHYBA: Nelze ziskat informace o portech. $_" -ForegroundColor Red
    }
}

function Show-EstablishedConnections {
    param([int]$MaxConnections = 50)
    
    Write-Header "Aktivni TCP spojeni (ESTABLISHED)"
    Write-Host "  Aktualni navazana spojeni (max: $MaxConnections):" -ForegroundColor Yellow
    Write-Host ""
    
    try {
        $connections = Get-NetTCPConnection -State Established -ErrorAction Stop | 
            Select-Object -First $MaxConnections | 
            Sort-Object OwningProcess
        
        foreach ($conn in $connections) {
            $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
            $procName = if ($proc) { $proc.Name } else { "Neznamy" }
            
            $local = "$($conn.LocalAddress):$($conn.LocalPort)"
            $remote = "$($conn.RemoteAddress):$($conn.RemotePort)"
            
            Write-Host "  $procName " -NoNewline -ForegroundColor White
            Write-Host "[PID: $($conn.OwningProcess)]" -ForegroundColor DarkGray
            Write-Host "    $local " -NoNewline -ForegroundColor Cyan
            Write-Host "<-> " -NoNewline -ForegroundColor Gray
            Write-Host "$remote" -ForegroundColor Yellow
            Write-Host ""
        }
        
        $totalEstablished = (Get-NetTCPConnection -State Established -ErrorAction Stop).Count
        Write-Host "  Celkem ESTABLISHED: $totalEstablished (zobrazeno: $($connections.Count))" -ForegroundColor Cyan
    } catch {
        Write-Host "  CHYBA: Nelze ziskat informace o spojenich. $_" -ForegroundColor Red
    }
}

# ==============================================================================
#      M O N I T O R I N G   P S / C M D / W M I
# ==============================================================================

function Show-PowerShellProcesses {
    Write-Header "Spustene PowerShell procesy"
    Write-Host ""
    
    try {
        $psProcesses = Get-Process | Where-Object { $_.Name -match 'powershell|pwsh' }
        
        if ($psProcesses) {
            foreach ($proc in $psProcesses) {
                $path = try { $proc.MainModule.FileName } catch { "N/A" }
                $startTime = try { $proc.StartTime.ToString("yyyy-MM-dd HH:mm:ss") } catch { "N/A" }
                $cmdLine = (Get-CimInstance Win32_Process -Filter "ProcessId = $($proc.Id)" -ErrorAction SilentlyContinue).CommandLine
                
                Write-Host "  $($proc.Name) " -NoNewline -ForegroundColor Cyan
                Write-Host "[PID: $($proc.Id)]" -ForegroundColor DarkGray
                Write-Host "    Spusteno: $startTime" -ForegroundColor Gray
                Write-Host "    Cesta   : $path" -ForegroundColor Gray
                
                if ($cmdLine) {
                    $cmdLineShort = if ($cmdLine.Length -gt 100) { $cmdLine.Substring(0, 100) + "..." } else { $cmdLine }
                    Write-Host "    Prikaz  : $cmdLineShort" -ForegroundColor Yellow
                }
                Write-Host ""
            }
            Write-Host "  Celkem PowerShell procesu: $($psProcesses.Count)" -ForegroundColor Cyan
        } else {
            Write-Host "  Zadne PowerShell procesy nenalezeny." -ForegroundColor Green
        }
    } catch {
        Write-Host "  CHYBA: Nelze nacist PowerShell procesy. $_" -ForegroundColor Red
    }
}

function Show-CmdProcesses {
    Write-Header "Spustene CMD procesy"
    Write-Host ""
    
    try {
        $cmdProcesses = Get-Process | Where-Object { $_.Name -match '^cmd$' }
        
        if ($cmdProcesses) {
            foreach ($proc in $cmdProcesses) {
                $path = try { $proc.MainModule.FileName } catch { "N/A" }
                $startTime = try { $proc.StartTime.ToString("yyyy-MM-dd HH:mm:ss") } catch { "N/A" }
                $cmdLine = (Get-CimInstance Win32_Process -Filter "ProcessId = $($proc.Id)" -ErrorAction SilentlyContinue).CommandLine
                
                Write-Host "  $($proc.Name) " -NoNewline -ForegroundColor Cyan
                Write-Host "[PID: $($proc.Id)]" -ForegroundColor DarkGray
                Write-Host "    Spusteno: $startTime" -ForegroundColor Gray
                Write-Host "    Cesta   : $path" -ForegroundColor Gray
                
                if ($cmdLine) {
                    $cmdLineShort = if ($cmdLine.Length -gt 100) { $cmdLine.Substring(0, 100) + "..." } else { $cmdLine }
                    Write-Host "    Prikaz  : $cmdLineShort" -ForegroundColor Yellow
                }
                Write-Host ""
            }
            Write-Host "  Celkem CMD procesu: $($cmdProcesses.Count)" -ForegroundColor Cyan
        } else {
            Write-Host "  Zadne CMD procesy nenalezeny." -ForegroundColor Green
        }
    } catch {
        Write-Host "  CHYBA: Nelze nacist CMD procesy. $_" -ForegroundColor Red
    }
}

function Show-WMIProcesses {
    Write-Header "Spustene WMI procesy"
    Write-Host ""
    
    try {
        $wmiProcesses = Get-Process | Where-Object { $_.Name -match 'wmi|wmiprvse' }
        
        if ($wmiProcesses) {
            foreach ($proc in $wmiProcesses) {
                $path = try { $proc.MainModule.FileName } catch { "N/A" }
                $startTime = try { $proc.StartTime.ToString("yyyy-MM-dd HH:mm:ss") } catch { "N/A" }
                
                Write-Host "  $($proc.Name) " -NoNewline -ForegroundColor Cyan
                Write-Host "[PID: $($proc.Id)]" -ForegroundColor DarkGray
                Write-Host "    Spusteno: $startTime" -ForegroundColor Gray
                Write-Host "    Cesta   : $path" -ForegroundColor Gray
                Write-Host ""
            }
            Write-Host "  Celkem WMI procesu: $($wmiProcesses.Count)" -ForegroundColor Cyan
        } else {
            Write-Host "  Zadne WMI procesy nenalezeny (bezne)." -ForegroundColor Green
        }
    } catch {
        Write-Host "  CHYBA: Nelze nacist WMI procesy. $_" -ForegroundColor Red
    }
}

function Show-AllScriptingProcesses {
    Write-Header "Vsechny spustene skriptovaci procesy"
    Write-Host ""
    
    Show-PowerShellProcesses
    Pause-Menu
    Show-CmdProcesses
    Pause-Menu
    Show-WMIProcesses
}

# ==============================================================================
#      H I S T O R I E   P R I K A Z U   A   D E T E K C E
# ==============================================================================

function Test-SuspiciousCommand {
    param([string]$Command)
    
    # Detekci vzory - konstruovany za behu pro obchazeni staticke detekce antivirem
    $suspiciousPatterns = @(
        @{ Pattern = '-ExecutionPolicy\s+(Bypass|Unrestricted)'; Description = 'Execution Policy Bypass'; Severity = 'High' }
        @{ Pattern = '-[Ee]nc(odedCommand)?'; Description = 'Encoded Command'; Severity = 'High' }
        @{ Pattern = '-[Ww](indowStyle)?\s+Hidden'; Description = 'Hidden Window'; Severity = 'High' }
        @{ Pattern = '-[Nn]o[Pp](rofile)?'; Description = 'No Profile'; Severity = 'Medium' }
        @{ Pattern = '-[Nn]on[Ii](nteractive)?'; Description = 'Non-Interactive'; Severity = 'Medium' }
        @{ Pattern = 'IEX|Invoke-Expression'; Description = 'Invoke-Expression (IEX)'; Severity = 'High' }
        @{ Pattern = 'Invoke-WebRequest|iwr|wget|curl.*http'; Description = 'Download Cradle'; Severity = 'High' }
        @{ Pattern = 'Net\.WebClient|DownloadString|DownloadFile'; Description = 'Web Download'; Severity = 'High' }
        @{ Pattern = 'Start-Process.*-Verb\s+RunAs'; Description = 'RunAs Elevation'; Severity = 'Medium' }
        @{ Pattern = 'powershell\.exe.*powershell\.exe'; Description = 'Nested PowerShell'; Severity = 'Medium' }
        @{ Pattern = '\$env:TEMP|\$env:TMP|AppData.*Temp'; Description = 'Temp Directory Usage'; Severity = 'Medium' }
        @{ Pattern = 'FromBase64String|FromBase64'; Description = 'Base64 Decode'; Severity = 'High' }
        @{ Pattern = 'Add-MpPreference.*ExclusionPath'; Description = 'Defender Exclusion'; Severity = 'Critical' }
        @{ Pattern = 'DisableRealtimeMonitoring|TamperProtection.*0'; Description = 'Disable Defender'; Severity = 'Critical' }
        @{ Pattern = 'Reflection.*Assembly'; Description = 'Reflective Load'; Severity = 'High' }
        @{ Pattern = 'WScript'; Description = 'WScript Usage'; Severity = 'Medium' }
        @{ Pattern = 'mshta|regsvr32'; Description = 'LOLBin Usage'; Severity = 'High' }
        @{ Pattern = 'cmd.*\/c'; Description = 'CMD Execution'; Severity = 'Low' }
        @{ Pattern = 'Out-Null'; Description = 'Output Suppression'; Severity = 'Low' }
        @{ Pattern = 'Mimikatz|PowerDump|Invoke-[A-Z]\w+Dump'; Description = 'Known Offensive Tool'; Severity = 'Critical' }
    )
    
    $findings = @()
    foreach ($item in $suspiciousPatterns) {
        if ($Command -match $item.Pattern) {
            $findings += @{
                Description = $item.Description
                Severity = $item.Severity
            }
        }
    }
    
    return $findings
}

function Get-SeverityColor {
    param([string]$Severity)
    
    switch ($Severity) {
        'Critical' { 'Magenta' }
        'High' { 'Red' }
        'Medium' { 'Yellow' }
        'Low' { 'Cyan' }
        default { 'Gray' }
    }
}

function Show-PowerShellHistory {
    param([int]$MaxEvents = 100)
    
    Write-Header "PowerShell Script Block Logging Historie"
    Write-Host "  Analyza PowerShell prikazu z Event Logu (Event ID 4104)..." -ForegroundColor Yellow
    Write-Host ""
    
    try {
        # Zkontroluj, zda je Script Block Logging zapnuty
        $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
        $loggingEnabled = $false
        
        if (Test-Path $regPath) {
            $val = Get-ItemProperty -Path $regPath -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue
            if ($val -and $val.EnableScriptBlockLogging -eq 1) {
                $loggingEnabled = $true
            }
        }
        
        if (-not $loggingEnabled) {
            Write-Host "  [!] VAROVANI: PowerShell Script Block Logging NENI zapnuto!" -ForegroundColor Red
            Write-Host "      Pro zapnuti pouzijte skript secure-pc.ps1" -ForegroundColor Yellow
            Write-Host ""
        }
        
        # Nacti PowerShell Script Block udalosti
        $events = Get-WinEvent -FilterHashtable @{
            LogName='Microsoft-Windows-PowerShell/Operational'
            ID=4104
        } -MaxEvents $MaxEvents -ErrorAction SilentlyContinue
        
        if ($events) {
            $suspiciousCount = 0
            
            foreach ($event in $events) {
                $time = $event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                $message = $event.Message
                
                # Extrahuj ScriptBlock text
                # Pouzij strukturovany atribut - spolehlivejsi nez parsovani textu zpravy
                $scriptBlock = if ($event.Properties.Count -gt 2 -and $event.Properties[2].Value) {
                    $event.Properties[2].Value.ToString()
                } else {
                    $message
                }
                
                # Zkrat velmi dlouhe prikazy
                $displayScript = if ($scriptBlock.Length -gt 200) {
                    $scriptBlock.Substring(0, 200) + "..."
                } else {
                    $scriptBlock
                }
                
                # Test na podezĹ™elĂ© vzory
                $findings = Test-SuspiciousCommand -Command $scriptBlock
                
                if ($findings.Count -gt 0) {
                    $suspiciousCount++
                    Write-Host "  [!] PODEZRELY PRIKAZ" -ForegroundColor Red
                    Write-Host "      Cas: $time" -ForegroundColor Gray
                    Write-Host "      Prikaz: $displayScript" -ForegroundColor White
                    Write-Host "      Detekce:" -ForegroundColor Yellow
                    
                    foreach ($finding in $findings) {
                        $color = Get-SeverityColor -Severity $finding['Severity']
                        Write-Host "        - [$($finding['Severity'])] $($finding['Description'])" -ForegroundColor $color
                    }
                    Write-Host ""
                } else {
                    # Normalni prikaz - zobraz jen zkracene
                    Write-Host "  [$time]" -ForegroundColor Green
                    Write-Host "    $displayScript" -ForegroundColor Gray
                    Write-Host ""
                }
            }
            
            Write-Host "  =====================================" -ForegroundColor Cyan
            Write-Host "  Celkem analyzovano: $($events.Count) prikazu" -ForegroundColor Cyan
            Write-Host "  Podezrelych prikazu: $suspiciousCount" -ForegroundColor $(if ($suspiciousCount -gt 0) { 'Red' } else { 'Green' })
        } else {
            Write-Host "  Zadne PowerShell Script Block udalosti nenalezeny." -ForegroundColor Yellow
            Write-Host "  Zkontrolujte, zda je Script Block Logging zapnuto." -ForegroundColor Yellow
        }
    } catch {
        Write-Host "  CHYBA: Nelze nacist PowerShell log. $_" -ForegroundColor Red
        Write-Host "  Ujistete se, ze mate administratorska opravneni." -ForegroundColor Yellow
    }
}

function Show-ProcessCreationHistory {
    param([int]$MaxEvents = 100)
    
    Write-Header "Historie vytvoreni procesu (Process Creation)"
    Write-Host "  Analyza Event ID 4688 (Process Creation Audit)..." -ForegroundColor Yellow
    Write-Host ""
    
    try {
        # Zkontroluj, zda je Process Creation Audit zapnuty
        $auditCheck = auditpol /get /category:* | Select-String "Process Creation|Vytvareni procesu"
        $auditEnabled = $auditCheck -and ($auditCheck | Select-String "Success|Uspech")
        
        if (-not $auditEnabled) {
            Write-Host "  [!] VAROVANI: Process Creation Auditing NENI zapnuto!" -ForegroundColor Red
            Write-Host "      Pro zapnuti (cesky Windows):" -ForegroundColor Yellow
            Write-Host "        auditpol /set /subcategory:`"Vytvareni procesu`" /success:enable" -ForegroundColor Yellow
            Write-Host "      Pro zapnuti (anglicky Windows):" -ForegroundColor Yellow
            Write-Host "        auditpol /set /subcategory:`"Process Creation`" /success:enable" -ForegroundColor Yellow
            Write-Host ""
        }
        
        # Nacti Process Creation udalosti
        $events = Get-WinEvent -FilterHashtable @{
            LogName='Security'
            ID=4688
        } -MaxEvents $MaxEvents -ErrorAction SilentlyContinue
        
        if ($events) {
            $suspiciousCount = 0
            
            foreach ($event in $events) {
                $time = $event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                
                # Parse properties directly (Constrained Language Mode compatible)
                $creator = $event.Properties[1].Value
                $newProcessName = $event.Properties[5].Value
                $commandLine = if ($event.Properties.Count -gt 8) { $event.Properties[8].Value } else { "" }
                
                # Filtruj pouze PowerShell, CMD, WMI a dalsi zajimave procesy
                if ($newProcessName -notmatch '(powershell|pwsh|cmd\.exe|wmic\.exe|mshta\.exe|regsvr32\.exe|rundll32\.exe|cscript\.exe|wscript\.exe)') {
                    continue
                }
                
                # Test na podezĹ™elĂ© vzory
                $findings = if ($commandLine) { Test-SuspiciousCommand -Command $commandLine } else { @() }
                
                if ($findings.Count -gt 0) {
                    $suspiciousCount++
                    Write-Host "  [!] PODEZRELY PROCES" -ForegroundColor Red
                } else {
                    Write-Host "  [$time]" -ForegroundColor Green
                }
                
                Write-Host "      Uzivatel: $creator" -ForegroundColor Gray
                Write-Host "      Proces  : $newProcessName" -ForegroundColor White
                
                if ($commandLine) {
                    $displayCmd = if ($commandLine.Length -gt 150) {
                        $commandLine.Substring(0, 150) + "..."
                    } else {
                        $commandLine
                    }
                    Write-Host "      Prikaz  : $displayCmd" -ForegroundColor Cyan
                }
                
                if ($findings.Count -gt 0) {
                    Write-Host "      Detekce:" -ForegroundColor Yellow
                    foreach ($finding in $findings) {
                        $color = Get-SeverityColor -Severity $finding['Severity']
                        Write-Host "        - [$($finding['Severity'])] $($finding['Description'])" -ForegroundColor $color
                    }
                }
                
                Write-Host ""
            }
            
            Write-Host "  =====================================" -ForegroundColor Cyan
            Write-Host "  Celkem analyzovano: $($events.Count) procesu" -ForegroundColor Cyan
            Write-Host "  Podezrelych procesu: $suspiciousCount" -ForegroundColor $(if ($suspiciousCount -gt 0) { 'Red' } else { 'Green' })
        } else {
            Write-Host "  Zadne Process Creation udalosti nenalezeny." -ForegroundColor Yellow
            Write-Host "  Zkontrolujte, zda je Process Creation Audit zapnuto." -ForegroundColor Yellow
        }
    } catch {
        Write-Host "  CHYBA: Nelze nacist Security log. $_" -ForegroundColor Red
    }
}

function Show-SysmonHistory {
    param([int]$MaxEvents = 100)
    
    Write-Header "Sysmon Process Creation (Event ID 1)"
    Write-Host "  Analyza Sysmon logu pro vytvoreni procesu..." -ForegroundColor Yellow
    Write-Host ""
    
    try {
        # Zjisti, zda je Sysmon nainstalovan
        $sysmonRunning = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
        if (-not $sysmonRunning) {
            $sysmonRunning = Get-Service -Name "Sysmon" -ErrorAction SilentlyContinue
        }
        
        if (-not $sysmonRunning) {
            Write-Host "  [!] Sysmon NENI nainstalovan!" -ForegroundColor Red
            Write-Host "      Pro instalaci pouzijte skript secure-pc.ps1" -ForegroundColor Yellow
            Write-Host ""
            return
        }
        
        # Nacti Sysmon Process Creation udalosti
        $events = Get-WinEvent -FilterHashtable @{
            LogName='Microsoft-Windows-Sysmon/Operational'
            ID=1
        } -MaxEvents $MaxEvents -ErrorAction SilentlyContinue
        
        if ($events) {
            $suspiciousCount = 0
            
            foreach ($event in $events) {
                $time = $event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                
                # Parse properties directly (Constrained Language Mode compatible)
                $image = $event.Properties[4].Value
                $commandLine = $event.Properties[10].Value
                $user = $event.Properties[12].Value
                $parentImage = $event.Properties[20].Value
                $hashes = if ($event.Properties.Count -gt 24) { $event.Properties[24].Value } else { "" }
                
                # Filtruj pouze zajimave procesy
                if ($image -notmatch '(powershell|pwsh|cmd\.exe|wmic\.exe|mshta\.exe|regsvr32\.exe|rundll32\.exe|cscript\.exe|wscript\.exe)') {
                    continue
                }
                
                # Test na podezĹ™elĂ© vzory
                $findings = if ($commandLine) { Test-SuspiciousCommand -Command $commandLine } else { @() }
                
                if ($findings.Count -gt 0) {
                    $suspiciousCount++
                    Write-Host "  [!] PODEZRELY PROCES" -ForegroundColor Red
                } else {
                    Write-Host "  [$time]" -ForegroundColor Green
                }
                
                Write-Host "      Uzivatel : $user" -ForegroundColor Gray
                Write-Host "      Proces   : $image" -ForegroundColor White
                Write-Host "      Rodic    : $parentImage" -ForegroundColor Gray
                
                if ($commandLine) {
                    $displayCmd = if ($commandLine.Length -gt 150) {
                        $commandLine.Substring(0, 150) + "..."
                    } else {
                        $commandLine
                    }
                    Write-Host "      Prikaz   : $displayCmd" -ForegroundColor Cyan
                }
                
                if ($hashes) {
                    Write-Host "      Hash     : $($hashes.Split(',')[0])" -ForegroundColor DarkGray
                }
                
                if ($findings.Count -gt 0) {
                    Write-Host "      Detekce:" -ForegroundColor Yellow
                    foreach ($finding in $findings) {
                        $color = Get-SeverityColor -Severity $finding['Severity']
                        Write-Host "        - [$($finding['Severity'])] $($finding['Description'])" -ForegroundColor $color
                    }
                }
                
                Write-Host ""
            }
            
            Write-Host "  =====================================" -ForegroundColor Cyan
            Write-Host "  Celkem analyzovano: $($events.Count) procesu" -ForegroundColor Cyan
            Write-Host "  Podezrelych procesu: $suspiciousCount" -ForegroundColor $(if ($suspiciousCount -gt 0) { 'Red' } else { 'Green' })
        } else {
            Write-Host "  Zadne Sysmon udalosti nenalezeny." -ForegroundColor Yellow
        }
    } catch {
        Write-Host "  CHYBA: Nelze nacist Sysmon log. $_" -ForegroundColor Red
        Write-Host "  Chyba: $_" -ForegroundColor Red
    }
}

function Show-WMIPersistence {
    Write-Header "WMI Event Subscription (Persistence)"
    Write-Host "  Kontrola WMI persistentnich mechanismu..." -ForegroundColor Yellow
    Write-Host ""
    
    try {
        # Event Filters
        Write-Host "  WMI Event Filters:" -ForegroundColor Cyan
        $filters = Get-WmiObject -Namespace root\subscription -Class __EventFilter -ErrorAction SilentlyContinue
        
        if ($filters) {
            foreach ($filter in $filters) {
                Write-Host "    Nazev: $($filter.Name)" -ForegroundColor White
                Write-Host "    Query: $($filter.Query)" -ForegroundColor Yellow
                Write-Host ""
            }
        } else {
            Write-Host "    Zadne Event Filters nenalezeny." -ForegroundColor Green
        }
        
        # Event Consumers
        Write-Host "  WMI Event Consumers:" -ForegroundColor Cyan
        $consumers = Get-WmiObject -Namespace root\subscription -Class __EventConsumer -ErrorAction SilentlyContinue
        
        if ($consumers) {
            foreach ($consumer in $consumers) {
                Write-Host "    Nazev: $($consumer.Name)" -ForegroundColor White
                Write-Host "    Typ  : $($consumer.__CLASS)" -ForegroundColor Gray
                
                if ($consumer.CommandLineTemplate) {
                    Write-Host "    Prikaz: $($consumer.CommandLineTemplate)" -ForegroundColor Yellow
                }
                
                if ($consumer.ScriptText) {
                    $scriptPreview = if ($consumer.ScriptText.Length -gt 100) {
                        $consumer.ScriptText.Substring(0, 100) + "..."
                    } else {
                        $consumer.ScriptText
                    }
                    Write-Host "    Script: $scriptPreview" -ForegroundColor Yellow
                }
                Write-Host ""
            }
        } else {
            Write-Host "    Zadne Event Consumers nenalezeny." -ForegroundColor Green
        }
        
        # Filter to Consumer Bindings
        Write-Host "  WMI Filter-Consumer Bindings:" -ForegroundColor Cyan
        $bindings = Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue
        
        if ($bindings) {
            foreach ($binding in $bindings) {
                Write-Host "    [!] AKTIVNI BINDING NALEZEN!" -ForegroundColor Red
                Write-Host "        Filter  : $($binding.Filter)" -ForegroundColor Yellow
                Write-Host "        Consumer: $($binding.Consumer)" -ForegroundColor Yellow
                Write-Host ""
            }
        } else {
            Write-Host "    Zadne aktivni bindings nenalezeny." -ForegroundColor Green
        }
        
    } catch {
        Write-Host "  CHYBA: Nelze zkontrolovat WMI subscription. $_" -ForegroundColor Red
    }
}

# ==============================================================================
#      D A L S I   M O N I T O R I N G
# ==============================================================================

function Show-ScheduledTasks {
    Write-Header "Naplanovane ulohy (Scheduled Tasks) - uzivatelske a neznamy"
    Write-Host "  Zobrazuji pouze NON-MICROSOFT ulohy (vasi a neznamy)..." -ForegroundColor Yellow
    Write-Host "  (Systemove ulohy Microsoftu jsou skryty)" -ForegroundColor DarkGray
    Write-Host ""

    try {
        $tasks = Get-ScheduledTask | Where-Object {
            $_.State -ne 'Disabled' -and
            $_.TaskPath -notmatch '^\\Microsoft\\' -and
            $_.TaskPath -notmatch '^\\Windows\\'
        } | Sort-Object TaskPath, TaskName

        if (-not $tasks) {
            Write-Host "  Zadne uzivatelske/neznamy ulohy nenalezeny." -ForegroundColor Green
            return
        }

        foreach ($task in $tasks) {
            $info = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue

            $state = $task.State
            $stateColor = switch ($state) {
                'Ready'   { 'Green' }
                'Running' { 'Cyan' }
                default   { 'Yellow' }
            }

            # Zjisti spustitelny soubor/akci
            $actions = $task.Actions | ForEach-Object {
                if ($_.Execute) { $_.Execute + " " + $_.Arguments }
            }
            $actionStr = ($actions | Where-Object { $_ }) -join "; "

            # Podezrele: spusti z Temp/AppData/Downloads
            $isSuspicious = $actionStr -match 'Temp|AppData|Downloads|Public|PerfLogs|\\Users\\.*\.exe' -and
                            $actionStr -notmatch 'Microsoft|Windows'

            $nameColor = if ($isSuspicious) { 'Red' } else { 'White' }
            Write-Host "  $($task.TaskPath)$($task.TaskName)" -ForegroundColor $nameColor -NoNewline
            Write-Host " [$state]" -ForegroundColor $stateColor
            if ($task.Author) { Write-Host "    Autor:  $($task.Author)" -ForegroundColor Gray }
            if ($actionStr)   { Write-Host "    Akce:   $actionStr" -ForegroundColor $(if ($isSuspicious) {'Red'} else {'DarkGray'}) }
            if ($isSuspicious) { Write-Host "    [!!!] PODEZRELE: akce spustena z docasne/uzivatelske slozky!" -ForegroundColor Red }

            if ($info) {
                $lastRun = "Nikdy"
                try { if ($info.LastRunTime -and $info.LastRunTime.Year -gt 1900) { $lastRun = $info.LastRunTime.ToString('yyyy-MM-dd HH:mm') } } catch { }
                Write-Host "    Posl. spusteni: $lastRun" -ForegroundColor DarkGray
            }
            Write-Host ""
        }

        Write-Host "  Celkem uzivatelskych/neznamy uloh: $($tasks.Count)" -ForegroundColor Cyan
        Write-Host "  TIP: Pro zobrazeni VSECH uloh pouzijte Task Scheduler (taskschd.msc)" -ForegroundColor DarkGray
    } catch {
        Write-Host "  CHYBA: Nelze nacist naplanovane ulohy. $_" -ForegroundColor Red
    }
}

function Show-Services {
    Write-Header "Sluzby (Services)"
    Write-Host "  Bezici sluzby:" -ForegroundColor Yellow
    Write-Host ""
    
    try {
        $services = Get-Service | Where-Object { $_.Status -eq 'Running' } | Sort-Object DisplayName
        
        foreach ($svc in $services) {
            Write-Host "  $($svc.DisplayName) " -NoNewline -ForegroundColor White
            Write-Host "[$($svc.Name)]" -ForegroundColor DarkGray
            Write-Host "    Stav: $($svc.Status) | Start: $($svc.StartType)" -ForegroundColor Gray
            Write-Host ""
        }
        
        $totalServices = (Get-Service).Count
        Write-Host "  Bezici sluzby: $($services.Count) z $totalServices celkem" -ForegroundColor Cyan
    } catch {
        Write-Host "  CHYBA: Nelze nacist sluzby. $_" -ForegroundColor Red
    }
}

function Show-StoppedServices {
    Write-Header "Zastavene sluzby"
    Write-Host "  Sluzby, ktere nejsou spusteny:" -ForegroundColor Yellow
    Write-Host ""
    
    try {
        $services = Get-Service | Where-Object { $_.Status -eq 'Stopped' -and $_.StartType -eq 'Automatic' } | Sort-Object DisplayName
        
        if ($services) {
            foreach ($svc in $services) {
                Write-Host "  [!] $($svc.DisplayName) " -NoNewline -ForegroundColor Red
                Write-Host "[$($svc.Name)]" -ForegroundColor DarkGray
                Write-Host "      Stav: $($svc.Status) | Start: $($svc.StartType)" -ForegroundColor Gray
                Write-Host ""
            }
            Write-Host "  Automaticke sluzby, ktere NEBEZI: $($services.Count)" -ForegroundColor Red
        } else {
            Write-Host "  Vsechny automaticke sluzby bezi." -ForegroundColor Green
        }
    } catch {
        Write-Host "  CHYBA: Nelze nacist sluzby. $_" -ForegroundColor Red
    }
}

function Show-Users {
    Write-Header "Lokalni uzivatele"
    Write-Host "  Seznam lokalniŃh uzivatelu:" -ForegroundColor Yellow
    Write-Host ""
    
    try {
        $users = Get-LocalUser | Sort-Object Name
        
        foreach ($user in $users) {
            $enabled = if ($user.Enabled) { "Aktivni" } else { "Deaktivovan" }
            $enabledColor = if ($user.Enabled) { 'Green' } else { 'Red' }
            
            $lastLogon = if ($user.LastLogon) { $user.LastLogon.ToString("yyyy-MM-dd HH:mm:ss") } else { "Nikdy" }
            
            Write-Host "  $($user.Name) " -NoNewline -ForegroundColor White
            Write-Host "[$enabled]" -NoNewline -ForegroundColor $enabledColor
            Write-Host " - $($user.Description)" -ForegroundColor Gray
            Write-Host "    Posledni prihlaseni: $lastLogon" -ForegroundColor DarkGray
            Write-Host ""
        }
        
        Write-Host "  Celkem uzivatelu: $($users.Count)" -ForegroundColor Cyan
    } catch {
        Write-Host "  CHYBA: Nelze nacist uzivatele. $_" -ForegroundColor Red
    }
}

function Show-LocalGroups {
    Write-Header "Lokalni skupiny a jejich clenove"
    Write-Host "  Klicove lokalni skupiny:" -ForegroundColor Yellow
    Write-Host ""
    
    try {
        $groups = @('Administrators', 'Users', 'Remote Desktop Users', 'Power Users')
        
        foreach ($groupName in $groups) {
            try {
                $group = Get-LocalGroup -Name $groupName -ErrorAction Stop
                $members = Get-LocalGroupMember -Group $groupName -ErrorAction Stop
                
                Write-Host "  $($group.Name)" -ForegroundColor Cyan
                Write-Host "    Popis: $($group.Description)" -ForegroundColor Gray
                
                if ($members) {
                    Write-Host "    Clenove:" -ForegroundColor Yellow
                    foreach ($member in $members) {
                        Write-Host "      - $($member.Name) [$($member.ObjectClass)]" -ForegroundColor White
                    }
                } else {
                    Write-Host "    Zadni clenove" -ForegroundColor DarkGray
                }
                Write-Host ""
            } catch {
                Write-Host "  Skupina '$groupName' nenalezena nebo nedostupna." -ForegroundColor DarkGray
                Write-Host ""
            }
        }
    } catch {
        Write-Host "  CHYBA: Nelze nacist skupiny. $_" -ForegroundColor Red
    }
}

function Show-StartupPrograms {
    Write-Header "Programy spoustene pri startu"
    Write-Host "  Aplikace v autostartu:" -ForegroundColor Yellow
    Write-Host ""
    
    try {
        # Zkontroluj bezne lokace autostartu
        $locations = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
        )
        
        foreach ($location in $locations) {
            if (Test-Path $location) {
                $items = Get-ItemProperty -Path $location -ErrorAction SilentlyContinue
                
                if ($items) {
                    Write-Host "  [$location]" -ForegroundColor Cyan
                    
                    $items.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
                        Write-Host "    $($_.Name) = " -NoNewline -ForegroundColor White
                        Write-Host "$($_.Value)" -ForegroundColor Gray
                    }
                    Write-Host ""
                }
            }
        }
        
        # Startup slozka
        $startupFolder = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
        if (Test-Path $startupFolder) {
            $files = Get-ChildItem -Path $startupFolder -ErrorAction SilentlyContinue
            if ($files) {
                Write-Host "  [Startup Folder: $startupFolder]" -ForegroundColor Cyan
                foreach ($file in $files) {
                    Write-Host "    $($file.Name)" -ForegroundColor White
                }
                Write-Host ""
            }
        }
        
    } catch {
        Write-Host "  CHYBA: Nelze nacist startovaci programy. $_" -ForegroundColor Red
    }
}

# ==============================================================================
#   P E R S I S T E N C E   A   P O D E Z R E L E   P R O C E S Y
# ==============================================================================

function Show-PersistenceEvents {
    Write-Header "Persistence - Mechanismy pretrvavani v systemu"
    Write-Host "  Kontroluji vsechna mista, kde se malware muze usadit..." -ForegroundColor Yellow
    Write-Host ""

    # 1) Registry Run klice
    Write-Host "  [1] REGISTRY AUTOSTART KLICE:" -ForegroundColor Cyan
    $runKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    )
    foreach ($key in $runKeys) {
        if (Test-Path $key) {
            $items = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
            $items.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
                $suspicious = $_.Value -match 'Temp|AppData|Downloads|Public|PerfLogs' -and $_.Value -notmatch 'Microsoft|Windows'
                $color = if ($suspicious) { 'Red' } else { 'White' }
                Write-Host "    $($key.Split('\')[-1]): " -NoNewline -ForegroundColor DarkGray
                Write-Host "$($_.Name) = $($_.Value)" -ForegroundColor $color
                if ($suspicious) { Write-Host "    [!] PODEZRELE: exe z docasne/uzivatelske slozky!" -ForegroundColor Red }
            }
        }
    }
    Write-Host ""

    # 2) Startup slozky (user + all users)
    Write-Host "  [2] STARTUP SLOZKY:" -ForegroundColor Cyan
    $startupDirs = @(
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
    )
    $foundStartup = $false
    foreach ($dir in $startupDirs) {
        if (Test-Path $dir) {
            $files = Get-ChildItem -Path $dir -ErrorAction SilentlyContinue | Where-Object { -not $_.PSIsContainer }
            if ($files) {
                $foundStartup = $true
                Write-Host "    $dir" -ForegroundColor DarkGray
                foreach ($f in $files) {
                    Write-Host "    [!] $($f.Name)" -ForegroundColor Yellow
                }
            }
        }
    }
    if (-not $foundStartup) { Write-Host "    Zadne soubory v startup slozce." -ForegroundColor Green }
    Write-Host ""

    # 3) Winlogon hijack check
    Write-Host "  [3] WINLOGON HODNOTY:" -ForegroundColor Cyan
    try {
        $wl = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ErrorAction SilentlyContinue
        $userinit = $wl.Userinit
        $shell    = $wl.Shell
        $uiOk = $userinit -match '^C:\\Windows\\[Ss]ystem32\\userinit\.exe,?$'
        $shOk = $shell    -match '^explorer\.exe$'
        $uiColor = if ($uiOk) { 'Green' } else { 'Red' }
        $shColor = if ($shOk) { 'Green' } else { 'Red' }
        Write-Host "    Userinit: $userinit" -ForegroundColor $uiColor
        Write-Host "    Shell:    $shell"    -ForegroundColor $shColor
        if (-not $uiOk) { Write-Host "    [!!!] NEOBVYKLA HODNOTA Userinit - mozny hijack!" -ForegroundColor Red }
        if (-not $shOk) { Write-Host "    [!!!] NEOBVYKLA HODNOTA Shell - mozny hijack!"    -ForegroundColor Red }
    } catch { Write-Host "    Nelze nacist." -ForegroundColor DarkGray }
    Write-Host ""

    # 4) IFEO Debugger hijack
    Write-Host "  [4] IMAGE FILE EXECUTION OPTIONS (Debugger hijack):" -ForegroundColor Cyan
    try {
        $ifeoPaths = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" -ErrorAction SilentlyContinue
        $foundIFEO = $false
        foreach ($item in $ifeoPaths) {
            $dbg = (Get-ItemProperty $item.PSPath -ErrorAction SilentlyContinue).Debugger
            if ($dbg) {
                $foundIFEO = $true
                Write-Host "    [!!!] $($item.PSChildName) -> Debugger: $dbg" -ForegroundColor Red
                Write-Host "          Mozny IFEO hijack pro ziskani SYSTEM privilegii!" -ForegroundColor Yellow
            }
        }
        if (-not $foundIFEO) { Write-Host "    Zadne Debugger hodnoty nenalezeny. (bezpecne)" -ForegroundColor Green }
    } catch { Write-Host "    Nelze overit." -ForegroundColor DarkGray }
    Write-Host ""

    # 5) AppInit_DLLs
    Write-Host "  [5] APPINIT_DLLS:" -ForegroundColor Cyan
    try {
        $ai = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" -Name "AppInit_DLLs" -ErrorAction SilentlyContinue
        if ($ai -and $ai.AppInit_DLLs -ne "") {
            Write-Host "    [!!!] AppInit_DLLs: $($ai.AppInit_DLLs)" -ForegroundColor Red
            Write-Host "          Toto pole by melo byt prazdne!" -ForegroundColor Yellow
        } else {
            Write-Host "    AppInit_DLLs je prazdna. (bezpecne)" -ForegroundColor Green
        }
    } catch { Write-Host "    Nelze overit." -ForegroundColor DarkGray }
    Write-Host ""

    # 6) Nove scheduled tasky z Event logu (posled. 30 dni)
    Write-Host "  [6] NOVE SCHEDULED TASKY Z EVENT LOGU (posl. 30 dni):" -ForegroundColor Cyan
    try {
        $since = (Get-Date).AddDays(-30)
        $taskEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=@(4698,4702); StartTime=$since} -MaxEvents 20 -ErrorAction SilentlyContinue
        if ($taskEvents) {
            foreach ($ev in $taskEvents) {
                $action = if ($ev.Id -eq 4698) { "VYTVOREN" } else { "UPRAVEN" }
                Write-Host "    [$($ev.TimeCreated.ToString('yyyy-MM-dd HH:mm'))] Task $action" -ForegroundColor Yellow
                $name = if ($ev.Properties.Count -gt 0) { $ev.Properties[0].Value } else { "N/A" }
                Write-Host "    Nazev: $name" -ForegroundColor White
                Write-Host ""
            }
        } else {
            Write-Host "    Zadne nove scheduled tasky v poslednim mesici." -ForegroundColor Green
        }
    } catch { Write-Host "    Nelze nacist security log (potreba opravneni)." -ForegroundColor DarkGray }
}

function Show-SuspiciousParentChild {
    Write-Header "Podezrele parent-child procesy (Sysmon Event ID 1)"
    Write-Host "  Kontroluji Sysmon logy na nebezpecne kombinace parent -> child..." -ForegroundColor Yellow
    Write-Host ""

    # Overit zda Sysmon bezi
    $sysmonSvc = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
    if (-not $sysmonSvc) { $sysmonSvc = Get-Service -Name "Sysmon" -ErrorAction SilentlyContinue }
    if (-not $sysmonSvc -or $sysmonSvc.Status -ne "Running") {
        Write-Host "  [!] Sysmon NENI nainstalovan nebo nebezi." -ForegroundColor Red
        Write-Host "  Nainstalujte Sysmon v secure-pc.ps1 > menu 5 pro tuto detekci." -ForegroundColor Yellow
        return
    }

    # Nebezpecne kombinace: parent -> child
    $suspiciousCombos = @(
        @{ Parent="winword.exe";  Child="powershell|cmd|wscript|mshta|cscript"; Risk="Kriticke" }
        @{ Parent="excel.exe";    Child="powershell|cmd|wscript|mshta|cscript"; Risk="Kriticke" }
        @{ Parent="outlook.exe";  Child="powershell|cmd|wscript|mshta|cscript"; Risk="Kriticke" }
        @{ Parent="msedge.exe";   Child="powershell|cmd|wscript";               Risk="Vysoke" }
        @{ Parent="chrome.exe";   Child="powershell|cmd|wscript";               Risk="Vysoke" }
        @{ Parent="mshta.exe";    Child="powershell|cmd|wscript|cscript";       Risk="Kriticke" }
        @{ Parent="wscript.exe";  Child="powershell|cmd";                       Risk="Kriticke" }
        @{ Parent="cscript.exe";  Child="powershell|cmd";                       Risk="Vysoke" }
        @{ Parent="regsvr32.exe"; Child="powershell|cmd|rundll32";              Risk="Kriticke" }
    )

    try {
        $events = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[EventID=1]]" -MaxEvents 1000 -ErrorAction SilentlyContinue
        if (-not $events) {
            Write-Host "  Zadne Sysmon udalosti nenalezeny." -ForegroundColor DarkGray
            return
        }

        $found = 0
        foreach ($ev in $events) {
            # Properties[4]=Image (child), Properties[13]=ParentImage
            $childPath  = if ($ev.Properties.Count -gt 4)  { $ev.Properties[4].Value }  else { "" }
            $parentPath = if ($ev.Properties.Count -gt 13) { $ev.Properties[13].Value } else { "" }
            $childName  = if ($childPath)  { [System.IO.Path]::GetFileName($childPath).ToLower()  } else { "" }
            $parentName = if ($parentPath) { [System.IO.Path]::GetFileName($parentPath).ToLower() } else { "" }

            foreach ($combo in $suspiciousCombos) {
                if ($parentName -eq $combo.Parent.ToLower() -and $childName -match $combo.Child) {
                    $found++
                    $color = if ($combo.Risk -eq "Kriticke") { 'Red' } else { 'Yellow' }
                    Write-Host "  [!!!] $($combo.Risk.ToUpper()): $parentName -> $childName" -ForegroundColor $color
                    Write-Host "    Cas: $($ev.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Gray
                    Write-Host "    Child:  $childPath"  -ForegroundColor White
                    Write-Host "    Parent: $parentPath" -ForegroundColor Gray
                    Write-Host "    CmdLine: $(if ($ev.Properties.Count -gt 10) { $ev.Properties[10].Value })" -ForegroundColor DarkGray
                    Write-Host ""
                }
            }
        }
        if ($found -eq 0) {
            Write-Host "  Zadne podezrele kombinace parent->child nenalezeny v poslednih 1000 zaznamech." -ForegroundColor Green
        } else {
            Write-Host "  Celkem podezrelych udalosti: $found" -ForegroundColor Red
        }
    } catch {
        Write-Host "  CHYBA: Nelze nacist Sysmon log. $_" -ForegroundColor Red
    }
}

function Show-SuspiciousPathProcesses {
    Write-Header "Procesy ze Podezrelych Umisteni"
    Write-Host "  Kontroluji bezici procesy z Temp/AppData/Downloads/Public..." -ForegroundColor Yellow
    Write-Host ""

    $suspiciousPaths = @(
        [System.IO.Path]::GetTempPath().TrimEnd('\'),
        "$env:APPDATA",
        "$env:LOCALAPPDATA",
        "$env:USERPROFILE\Downloads",
        "C:\Users\Public",
        "C:\PerfLogs"
    )

    try {
        $processes = Get-Process -ErrorAction SilentlyContinue
        $found = 0
        foreach ($proc in $processes) {
            try {
                $path = $proc.MainModule.FileName
                if (-not $path) { continue }
                foreach ($suspPath in $suspiciousPaths) {
                    if ($path.StartsWith($suspPath, [System.StringComparison]::OrdinalIgnoreCase)) {
                        $found++
                        Write-Host "  [!!!] $($proc.Name) (PID: $($proc.Id))" -ForegroundColor Red
                        Write-Host "    Cesta: $path" -ForegroundColor Yellow
                        try {
                            $parent = Get-CimInstance Win32_Process -Filter "ProcessId=$($proc.Id)" -ErrorAction SilentlyContinue
                            if ($parent) {
                                $parentProc = Get-Process -Id $parent.ParentProcessId -ErrorAction SilentlyContinue
                                Write-Host "    Parent: $($parentProc.Name) (PID: $($parent.ParentProcessId))" -ForegroundColor Gray
                            }
                        } catch { }
                        Write-Host ""
                        break
                    }
                }
            } catch { }
        }
        if ($found -eq 0) {
            Write-Host "  Zadne procesy z podezrelych umisteni nenalezeny." -ForegroundColor Green
        } else {
            Write-Host "  Celkem podezrelych procesu: $found" -ForegroundColor Red
        }
    } catch {
        Write-Host "  CHYBA: Nelze nacist procesy. $_" -ForegroundColor Red
    }
}

function Show-DNSCache {
    Write-Header "DNS Cache - Kontrola podezrelych domen"
    Write-Host "  Nacitam DNS cache..." -ForegroundColor Yellow
    Write-Host ""

    try {
        $cache = Get-DnsClientCache -ErrorAction SilentlyContinue
        if (-not $cache) {
            Write-Host "  DNS cache je prazdna nebo nedostupna." -ForegroundColor Yellow
            return
        }

        # Zname bezpecne domeny (filtrovani sumu)
        $knownSafe = @('microsoft\.com','windows\.com','windowsupdate\.com','office\.com',
                       'live\.com','azure\.com','googleapis\.com','gstatic\.com',
                       'google\.com','youtube\.com','akamai','cloudfront','amazonaws')
        $knownSafePattern = $knownSafe -join '|'

        $suspicious = $cache | Where-Object {
            $_.Entry -notmatch $knownSafePattern -and
            $_.TimeToLive -lt 300 -and
            $_.Entry -notmatch '^\.' -and
            $_.Data -and $_.Data -ne "0.0.0.0"
        }

        $all = $cache | Where-Object { $_.Entry -notmatch $knownSafePattern -and $_.Entry -notmatch '^\.' }

        if ($suspicious) {
            Write-Host "  [!] PODEZRELE: Kratke TTL (< 300s) - mozna C2 / fast-flux domeny:" -ForegroundColor Red
            Write-Host ""
            $suspicious | Sort-Object Entry | ForEach-Object {
                Write-Host "    TTL:$($_.TimeToLive.ToString().PadLeft(6))s  $($_.Entry.PadRight(45)) -> $($_.Data)" -ForegroundColor Red
            }
            Write-Host ""
        }

        Write-Host "  Ostatni neznama domena v cache:" -ForegroundColor Cyan
        if ($all) {
            $all | Sort-Object Entry | Select-Object -First 50 | ForEach-Object {
                $color = if ($_.TimeToLive -lt 300) { 'Yellow' } else { 'Gray' }
                Write-Host "    TTL:$($_.TimeToLive.ToString().PadLeft(6))s  $($_.Entry.PadRight(45)) -> $($_.Data)" -ForegroundColor $color
            }
        } else {
            Write-Host "    (zadne nezname domeny)" -ForegroundColor DarkGray
        }
        Write-Host ""
        Write-Host "  Celkem zaznamu v cache: $($cache.Count)" -ForegroundColor Cyan
    } catch {
        Write-Host "  CHYBA: Nelze nacist DNS cache. $_" -ForegroundColor Red
    }
}

function Export-MonitorResults {
    $timestamp  = Get-Date -Format "yyyyMMdd_HHmmss"
    $exportPath = "$env:USERPROFILE\Desktop\MonitorReport_$timestamp.txt"

    Write-Host ""
    Write-Host "  Exportuji vsechna data do souboru..." -ForegroundColor Yellow
    Write-Host "  Cesta: $exportPath" -ForegroundColor Cyan
    Write-Host "  Toto muze trvat 1-2 minuty." -ForegroundColor DarkGray
    Write-Host ""

    try {
        $header = @"
================================================================================
  MONITORING REPORT - $env:COMPUTERNAME
  Datum: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
  Uziatel: $env:USERNAME
================================================================================

"@
        $header | Out-File -FilePath $exportPath -Encoding UTF8

        $sections = @(
            @{ Name = "RYCHLY PREHLED";              Func = { Show-QuickOverview } }
            @{ Name = "NEUSPESNE LOGINY";            Func = { Show-FailedLogins -MaxEvents 100 } }
            @{ Name = "KRITICKE UDALOSTI";           Func = { Show-SecurityEvents } }
            @{ Name = "PERSISTENCE MECHANISMY";      Func = { Show-PersistenceEvents } }
            @{ Name = "NEPODEPSANE PROCESY";         Func = { Show-UnsignedProcesses } }
            @{ Name = "PROCESY Z PODEZRELYCH CEST";  Func = { Show-SuspiciousPathProcesses } }
            @{ Name = "OTEVRENE PORTY";              Func = { Show-OpenPorts } }
            @{ Name = "AKTIVNI SPOJENI";             Func = { Show-EstablishedConnections } }
            @{ Name = "DNS CACHE";                   Func = { Show-DNSCache } }
            @{ Name = "SCHEDULED TASKS (non-MS)";   Func = { Show-ScheduledTasks } }
            @{ Name = "WMI PERSISTENCE";             Func = { Show-WMIPersistence } }
            @{ Name = "STARTUP PROGRAMY";            Func = { Show-StartupPrograms } }
        )

        foreach ($section in $sections) {
            Write-Host "    Exportuji: $($section.Name) ..." -ForegroundColor DarkGray
            "=== $($section.Name) ===" | Out-File -FilePath $exportPath -Encoding UTF8 -Append
            try {
                & $section.Func *>&1 | Out-File -FilePath $exportPath -Encoding UTF8 -Append
            } catch {
                "CHYBA: $_" | Out-File -FilePath $exportPath -Encoding UTF8 -Append
            }
            "" | Out-File -FilePath $exportPath -Encoding UTF8 -Append
        }

        Write-Host "  [OK] Export dokoncen!" -ForegroundColor Green
        Write-Host "  Soubor: $exportPath" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  TIP: Ulozte tento soubor pro porovnani s budoucimi skeny." -ForegroundColor Yellow
    } catch {
        Write-Host "  CHYBA pri exportu: $_" -ForegroundColor Red
    }
}

# ==============================================================================
#                      M E N U   F U N K C E
# ==============================================================================

function Show-Menu-SecurityEvents {
    do {
        Show-Banner
        Write-Header "Bezpecnostni Udalosti"
        
        Write-MenuItem "1" "Neuspesne pokusy o prihlaseni (Failed Logons)"
        Write-MenuItem "2" "Uspesna prihlaseni (Successful Logons)"
        Write-MenuItem "3" "Kriticke bezpecnostni udalosti (vcetne log cleared!)"
        Write-MenuItem "4" "Persistence Events (nove tasky/sluzby/IFEO/Winlogon)" Red
        Write-Host ""
        Write-MenuItem "0" "Zpet do hlavniho menu" -Color Yellow
        Write-Host ""
        
        $choice = Read-MenuChoice
        
        switch ($choice) {
            "1" { Show-FailedLogins; Pause-Menu }
            "2" { Show-SuccessfulLogins; Pause-Menu }
            "3" { Show-SecurityEvents; Pause-Menu }
            "4" { Show-PersistenceEvents; Pause-Menu }
            "0" { return }
            default {
                Write-Host "  Neplatna volba, zkuste znovu." -ForegroundColor Red
                Start-Sleep -Seconds 1
            }
        }
    } while ($true)
}

function Show-Menu-Processes {
    do {
        Show-Banner
        Write-Header "Spustene Procesy"
        
        Write-MenuItem "1" "Vsechny procesy (top 30)"
        Write-MenuItem "2" "Vsechny procesy (kompletni)"
        Write-MenuItem "3" "Nepodepsane a podezrele procesy"
        Write-MenuItem "4" "Procesy ze podezrelych cest (Temp/AppData/Downloads)" Red
        Write-Host ""
        Write-MenuItem "0" "Zpet do hlavniho menu" -Color Yellow
        Write-Host ""
        
        $choice = Read-MenuChoice
        
        switch ($choice) {
            "1" { Show-RunningProcesses; Pause-Menu }
            "2" { Show-RunningProcesses -ShowAll; Pause-Menu }
            "3" { Show-UnsignedProcesses; Pause-Menu }
            "4" { Show-SuspiciousPathProcesses; Pause-Menu }
            "0" { return }
            default {
                Write-Host "  Neplatna volba, zkuste znovu." -ForegroundColor Red
                Start-Sleep -Seconds 1
            }
        }
    } while ($true)
}

function Show-Menu-Network {
    do {
        Show-Banner
        Write-Header "Sitove Pripojeni"
        
        Write-MenuItem "1" "Otevrene porty (LISTENING)"
        Write-MenuItem "2" "Aktivni spojeni (ESTABLISHED)"
        Write-MenuItem "3" "DNS cache (podezrele/nezname domeny, kratke TTL)" Yellow
        Write-Host ""
        Write-MenuItem "0" "Zpet do hlavniho menu" -Color Yellow
        Write-Host ""
        
        $choice = Read-MenuChoice
        
        switch ($choice) {
            "1" { Show-OpenPorts; Pause-Menu }
            "2" { Show-EstablishedConnections; Pause-Menu }
            "3" { Show-DNSCache; Pause-Menu }
            "0" { return }
            default {
                Write-Host "  Neplatna volba, zkuste znovu." -ForegroundColor Red
                Start-Sleep -Seconds 1
            }
        }
    } while ($true)
}

function Show-Menu-Scripting {
    do {
        Show-Banner
        Write-Header "Skriptovaci Procesy"
        
        Write-MenuItem "1" "PowerShell procesy"
        Write-MenuItem "2" "CMD procesy"
        Write-MenuItem "3" "WMI procesy"
        Write-MenuItem "4" "Vsechny (PS + CMD + WMI)"
        Write-Host ""
        Write-MenuItem "0" "Zpet do hlavniho menu" -Color Yellow
        Write-Host ""
        
        $choice = Read-MenuChoice
        
        switch ($choice) {
            "1" { Show-PowerShellProcesses; Pause-Menu }
            "2" { Show-CmdProcesses; Pause-Menu }
            "3" { Show-WMIProcesses; Pause-Menu }
            "4" { Show-AllScriptingProcesses; Pause-Menu }
            "0" { return }
            default {
                Write-Host "  Neplatna volba, zkuste znovu." -ForegroundColor Red
                Start-Sleep -Seconds 1
            }
        }
    } while ($true)
}

function Show-Menu-System {
    do {
        Show-Banner
        Write-Header "System a Sprava"
        
        Write-MenuItem "1" "Naplanovane ulohy (Scheduled Tasks)"
        Write-MenuItem "2" "Bezici sluzby (Running Services)"
        Write-MenuItem "3" "Zastavene automaticke sluzby"
        Write-MenuItem "4" "Lokalni uzivatele"
        Write-MenuItem "5" "Lokalni skupiny a clenove"
        Write-MenuItem "6" "Programy spoustene pri startu"
        Write-Host ""
        Write-MenuItem "0" "Zpet do hlavniho menu" -Color Yellow
        Write-Host ""
        
        $choice = Read-MenuChoice
        
        switch ($choice) {
            "1" { Show-ScheduledTasks; Pause-Menu }
            "2" { Show-Services; Pause-Menu }
            "3" { Show-StoppedServices; Pause-Menu }
            "4" { Show-Users; Pause-Menu }
            "5" { Show-LocalGroups; Pause-Menu }
            "6" { Show-StartupPrograms; Pause-Menu }
            "0" { return }
            default {
                Write-Host "  Neplatna volba, zkuste znovu." -ForegroundColor Red
                Start-Sleep -Seconds 1
            }
        }
    } while ($true)
}

function Show-Menu-CommandHistory {
    do {
        Show-Banner
        Write-Header "Historie Prikazu a Detekce Hrozeb"
        
        Write-Host "  Analyza historie s detekcĂ­ podezrelych vzoru:" -ForegroundColor Yellow
        Write-Host "    - ExecutionPolicy Bypass, EncodedCommand" -ForegroundColor DarkGray
        Write-Host "    - Download cradles, Base64 encoding" -ForegroundColor DarkGray
        Write-Host "    - Defender modifications, LOLBins" -ForegroundColor DarkGray
        Write-Host ""
        
        Write-MenuItem "1" "PowerShell Script Block Logging historie"
        Write-MenuItem "2" "Process Creation historie (Event ID 4688)"
        Write-MenuItem "3" "Sysmon Process Creation (Event ID 1)"
        Write-MenuItem "4" "WMI Event Subscription (Persistence)"
        Write-MenuItem "5" "Podezrele parent-child procesy (Sysmon ID 1)" Red
        Write-MenuItem "6" "Kompletni analyza (vse najednou)"
        Write-Host ""
        Write-MenuItem "0" "Zpet do hlavniho menu" -Color Yellow
        Write-Host ""
        
        $choice = Read-MenuChoice
        
        switch ($choice) {
            "1" { Show-PowerShellHistory; Pause-Menu }
            "2" { Show-ProcessCreationHistory; Pause-Menu }
            "3" { Show-SysmonHistory; Pause-Menu }
            "4" { Show-WMIPersistence; Pause-Menu }
            "5" { Show-SuspiciousParentChild; Pause-Menu }
            "6" { 
                Show-PowerShellHistory; Pause-Menu
                Show-ProcessCreationHistory; Pause-Menu
                Show-SysmonHistory; Pause-Menu
                Show-WMIPersistence; Pause-Menu
                Show-SuspiciousParentChild; Pause-Menu
            }
            "0" { return }
            default {
                Write-Host "  Neplatna volba, zkuste znovu." -ForegroundColor Red
                Start-Sleep -Seconds 1
            }
        }
    } while ($true)
}

function Show-QuickOverview {
    Write-Header "RYCHLY PREHLED SYSTEMU"
    Write-Host "  Nacitam data..." -ForegroundColor Yellow
    Write-Host ""

    # System
    Write-Host "  SYSTEM:" -ForegroundColor Cyan
    $os = Get-CimInstance Win32_OperatingSystem
    Write-Host "    OS:       $($os.Caption) $($os.Version)" -ForegroundColor White
    Write-Host "    Hostname: $env:COMPUTERNAME" -ForegroundColor White
    $uptime = (Get-Date) - $os.LastBootUpTime
    $uptimeHours = [math]::Round($uptime.Days * 24 + $uptime.Hours + $uptime.Minutes / 60.0, 1)
    Write-Host "    Uptime:   $uptimeHours hodin" -ForegroundColor White

    # Secure Boot
    try {
        $sb = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
        $sbLabel = if ($sb -eq $true) { "Zapnuto" } elseif ($sb -eq $false) { "VYPNUTO" } else { "Nelze zjistit" }
        $sbColor = if ($sb -eq $true) { 'Green' } else { 'Yellow' }
        Write-Host "    Secure Boot: $sbLabel" -ForegroundColor $sbColor
    } catch { }
    Write-Host ""

    # Bezpecnost
    Write-Host "  BEZPECNOST:" -ForegroundColor Cyan

    # Sysmon
    $sysmonSvc = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
    if (-not $sysmonSvc) { $sysmonSvc = Get-Service -Name "Sysmon" -ErrorAction SilentlyContinue }
    $sysmonLabel = if ($sysmonSvc -and $sysmonSvc.Status -eq "Running") { "Bezi" } else { "NENAINSTALOVAN" }
    $sysmonColor = if ($sysmonSvc -and $sysmonSvc.Status -eq "Running") { 'Green' } else { 'Red' }
    Write-Host "    Sysmon:         $sysmonLabel" -ForegroundColor $sysmonColor

    # Defender RT
    try {
        $mpStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
        $rtLabel  = if ($mpStatus -and $mpStatus.RealTimeProtectionEnabled) { "Zapnuto" } else { "VYPNUTO" }
        $rtColor  = if ($mpStatus -and $mpStatus.RealTimeProtectionEnabled) { 'Green' } else { 'Red' }
        Write-Host "    Defender RT:    $rtLabel" -ForegroundColor $rtColor
    } catch { }

    # Neuspesne loginy za posl. 24 hodin
    $since24h = (Get-Date).AddHours(-24)
    $failedLogins = (Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625; StartTime=$since24h} -ErrorAction SilentlyContinue).Count
    $flColor = if ($failedLogins -gt 10) { 'Red' } elseif ($failedLogins -gt 0) { 'Yellow' } else { 'Green' }
    Write-Host "    Neuspesne loginy (24h): $failedLogins" -ForegroundColor $flColor

    # Security log cleared?
    $logCleared = (Get-WinEvent -FilterHashtable @{LogName='Security'; ID=1102} -MaxEvents 1 -ErrorAction SilentlyContinue).Count
    if ($logCleared -gt 0) {
        Write-Host "    [!!!] SECURITY LOG BYL VYMAZAN!" -ForegroundColor Red
    }
    Write-Host ""

    # Procesy
    Write-Host "  PROCESY:" -ForegroundColor Cyan
    $totalProc = (Get-Process).Count
    $psProc    = (Get-Process | Where-Object { $_.Name -match 'powershell|pwsh' }).Count
    $cmdProc   = (Get-Process | Where-Object { $_.Name -match '^cmd$' }).Count
    Write-Host "    Celkem: $totalProc  |  PowerShell: $psProc  |  CMD: $cmdProc" -ForegroundColor White
    Write-Host ""

    # Sit
    Write-Host "  SIT:" -ForegroundColor Cyan
    $listenPorts = (Get-NetTCPConnection -State Listen    -ErrorAction SilentlyContinue).Count
    $established = (Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue).Count
    Write-Host "    Naslouchajici porty: $listenPorts  |  Aktivni spojeni: $established" -ForegroundColor White
    Write-Host ""

    # Sluzby
    Write-Host "  SLUZBY:" -ForegroundColor Cyan
    $runningServices = (Get-Service | Where-Object { $_.Status -eq 'Running' }).Count
    $stoppedAuto     = (Get-Service | Where-Object { $_.Status -eq 'Stopped' -and $_.StartType -eq 'Automatic' }).Count
    Write-Host "    Bezici: $runningServices" -ForegroundColor White
    Write-Host "    Zastavene automaticke: $stoppedAuto" -ForegroundColor $(if ($stoppedAuto -gt 0) { 'Yellow' } else { 'Green' })
    Write-Host ""

    # Uzivatele
    Write-Host "  UZIVATELE:" -ForegroundColor Cyan
    $activeUsers = (Get-LocalUser | Where-Object { $_.Enabled }).Count
    $totalUsers  = (Get-LocalUser).Count
    Write-Host "    Aktivni: $activeUsers z $totalUsers" -ForegroundColor White
    Write-Host ""
}

# ==============================================================================
#                   H L A V N I   M E N U
# ==============================================================================


function Start-MonitorMode {
do {
    Show-Banner
    Write-Header "Hlavni Menu - Vyberte oblast monitoringu"
    
    Write-MenuItem "1" "Bezpecnostni Udalosti (Security Events)"
    Write-MenuItem "2" "Spustene Procesy (Running Processes)"
    Write-MenuItem "3" "Sitove Pripojeni (Network Connections)"
    Write-MenuItem "4" "Skriptovaci Procesy (PowerShell/CMD/WMI)"
    Write-MenuItem "5" "System a Sprava (Services/Tasks/Users)"
    Write-MenuItem "6" "Historie Prikazu a Detekce Hrozeb" -Color Red
    Write-Host ""
    Write-MenuItem "9" "Rychly prehled systemu" -Color Cyan
    Write-MenuItem "E" "Export vsech dat do souboru (Desktop)" -Color Magenta
    Write-MenuItem "0" "Konec" -Color Yellow
    Write-Host ""
    
    $mainChoice = Read-MenuChoice
    
    switch ($mainChoice) {
        "1" { Show-Menu-SecurityEvents }
        "2" { Show-Menu-Processes }
        "3" { Show-Menu-Network }
        "4" { Show-Menu-Scripting }
        "5" { Show-Menu-System }
        "6" { Show-Menu-CommandHistory }
        "9" { Show-QuickOverview; Pause-Menu }
        { $_ -in @("E","e") } { Export-MonitorResults; Pause-Menu }
        "0" {
            Write-Host ""
            Write-Host "  Ukoncuji monitoring. Zustan v bezpeci!" -ForegroundColor Cyan
            Write-Host ""
        }
        default {
            Write-Host "  Neplatna volba, zkuste znovu." -ForegroundColor Red
            Start-Sleep -Seconds 1
        }
    }
} while ($mainChoice -ne "0")
}

# ==============================================================================
#   M O D U L   3 :   A P P L O C K E R   ( W D A C   +   M A K R A )
# ==============================================================================
$WDACPolicyDir      = "$env:ProgramData\WDACPolicies"
$WDACDefaultXml     = "$WDACPolicyDir\DefaultPolicy.xml"
$WDACCustomXml      = "$WDACPolicyDir\CustomRules.xml"
$WDACMergedXml      = "$WDACPolicyDir\MergedPolicy.xml"
$WDACCompiledBin    = "$WDACPolicyDir\MergedPolicy.bin"
$WDACDeployedPath   = "$env:windir\System32\CodeIntegrity\SIPolicy.p7b"

# WDAC Wizard - oficialni Microsoft GUI nastroj pro tvorbu WDAC politik
$WDACWizardUrl      = "https://aka.ms/wdacwizard"
$WDACWizardInstaller = "$WDACPolicyDir\WDACWizard_Setup.msix"

# ==============================================================================
#        W D A C   -   S T A V   a   I N F O R M A C E
# ==============================================================================
function Get-WDACStatus {
    try {
        $ci = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace "root\Microsoft\Windows\DeviceGuard" -ErrorAction Stop
        $status = $ci.CodeIntegrityPolicyEnforcementStatus
        # 0 = Off, 1 = Audit, 2 = Enforced
        switch ($status) {
            0 { "Vypnuto" }
            1 { "Audit mod" }
            2 { "Enforce mod (aktivni!)" }
            default { "Neznamy ($status)" }
        }
    } catch {
        # Alternativni detekce - existuje soubor politiky?
        if (Test-Path $WDACDeployedPath) {
            "Nasazeno (nelze zjistit mod)"
        } else {
            "Vypnuto"
        }
    }
}

function Get-WDACStatusShort {
    try {
        $ci = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace "root\Microsoft\Windows\DeviceGuard" -ErrorAction SilentlyContinue
        if ($ci) {
            switch ($ci.CodeIntegrityPolicyEnforcementStatus) {
                0 { "Vypnuto" }
                1 { "Audit" }
                2 { "Enforce" }
                default { "?" }
            }
        } else {
            if (Test-Path $WDACDeployedPath) { "Nasazeno" } else { "Vypnuto" }
        }
    } catch { "Neznamy" }
}

function Show-WDACDetail {
    Write-Header "WDAC - Detailni stav"

    $st = Get-WDACStatus
    $color = if ($st -match "Enforce") { 'Green' } elseif ($st -match "Audit") { 'Yellow' } else { 'Red' }
    Write-Status "WDAC stav" $st $color

    # Policy soubory
    Write-Host ""
    Write-Host "  Soubory politik:" -ForegroundColor White
    $files = @(
        @{ Path = $WDACDefaultXml;   Label = "Vychozi politika (XML)" }
        @{ Path = $WDACCustomXml;    Label = "Vlastni pravidla (XML)" }
        @{ Path = $WDACMergedXml;    Label = "Sloupcena politika (XML)" }
        @{ Path = $WDACCompiledBin;  Label = "Kompilovan politika (BIN)" }
        @{ Path = $WDACDeployedPath; Label = "Nasazena politika (system)" }
    )
    foreach ($f in $files) {
        $exists = Test-Path $f.Path
        $eColor = if ($exists) { 'Green' } else { 'DarkGray' }
        $eText  = if ($exists) { "ANO" } else { "NE" }
        Write-Status $f.Label $eText $eColor
    }

    # WDAC eventy z Event Logu
    Write-Host ""
    Write-Host "  Posledni WDAC udalosti (CodeIntegrity log):" -ForegroundColor White
    try {
        $events = Get-WinEvent -LogName "Microsoft-Windows-CodeIntegrity/Operational" -MaxEvents 10 -ErrorAction Stop |
            Select-Object TimeCreated, Id, LevelDisplayName, Message
        if ($events) {
            foreach ($ev in $events) {
                $msgShort = if ($ev.Message.Length -gt 70) { $ev.Message.Substring(0,67) + "..." } else { $ev.Message }
                $lvlColor = switch ($ev.LevelDisplayName) {
                    "Error"       { 'Red' }
                    "Warning"     { 'Yellow' }
                    "Information" { 'Gray' }
                    default       { 'White' }
                }
                Write-Host "    [$($ev.TimeCreated.ToString('dd.MM HH:mm'))] " -NoNewline -ForegroundColor DarkGray
                Write-Host "ID:$($ev.Id)" -NoNewline -ForegroundColor $lvlColor
                Write-Host " $msgShort" -ForegroundColor White
            }
        } else {
            Write-Host "    Zadne udalosti." -ForegroundColor DarkGray
        }
    } catch {
        Write-Host "    Nelze cist Event Log: $_" -ForegroundColor DarkGray
    }

    # VBS / HVCI / Credential Guard stav
    Write-Host ""
    Write-Host "  Virtualizacni bezpecnost (VBS/HVCI):" -ForegroundColor White
    try {
        $dg = Get-CimInstance -Namespace "root/Microsoft/Windows/DeviceGuard" -ClassName Win32_DeviceGuard -ErrorAction Stop
        $vbsEnabled = $dg.VirtualizationBasedSecurityStatus
        $services   = $dg.SecurityServicesRunning

        $vbsText  = switch ($vbsEnabled) { 0 { "Vypnuto" } 1 { "Aktivovano, ale sluzby nebezi" } 2 { "Plne aktivni" } default { "Neznamy ($vbsEnabled)" } }
        $vbsColor = if ($vbsEnabled -eq 2) { 'Green' } elseif ($vbsEnabled -eq 1) { 'Yellow' } else { 'Red' }
        Write-Status "VBS (Virtualization Based Security)" $vbsText $vbsColor

        $hvciRunning  = $services -contains 2
        $credgRunning = $services -contains 1
        Write-Status "HVCI (Memory Integrity)" $(if ($hvciRunning) { "Aktivni" } else { "Neaktivni" }) $(if ($hvciRunning) { 'Green' } else { 'DarkGray' })
        Write-Status "Credential Guard" $(if ($credgRunning) { "Aktivni" } else { "Neaktivni" }) $(if ($credgRunning) { 'Green' } else { 'DarkGray' })
    } catch {
        Write-Host "    VBS/HVCI: Nelze zjistit (pravdepodobne Home edice nebo WMI chyba)" -ForegroundColor DarkGray
    }
}

function Show-WDACBlockedEvents {
    Write-Host ""
    Write-Header "WDAC - Zablokovane a Auditovane Aplikace (Event Log)"
    Write-Host "  Prohledavam Microsoft-Windows-CodeIntegrity/Operational ..." -ForegroundColor DarkGray
    Write-Host "  ID 3076 = Audit (bylo by zablokovano)  |  ID 3077 = Enforce - ZABLOKOVANO" -ForegroundColor DarkGray
    Write-Host ""
    try {
        $events = Get-WinEvent -LogName "Microsoft-Windows-CodeIntegrity/Operational" `
            -FilterXPath "*[System[(EventID=3076 or EventID=3077)]]" -MaxEvents 50 -ErrorAction Stop

        if (-not $events -or $events.Count -eq 0) {
            Write-Host "  Zadne WDAC blocking/audit udalosti nalezeny." -ForegroundColor Green
            Write-Host "  (To je dobry znak - zadna aplikace nebyla blokovana/auditovana)" -ForegroundColor DarkGray
        } else {
            Write-Host "  Nalezeno $($events.Count) udalosti:" -ForegroundColor White
            Write-Host ""
            foreach ($ev in $events) {
                $isEnforce = ($ev.Id -eq 3077)
                $typeText  = if ($isEnforce) { "ENFORCE - ZABLOKOVANO!" } else { "AUDIT (bylo by zablokovano)" }
                $evColor   = if ($isEnforce) { 'Red' } else { 'Yellow' }

                Write-Host "  [$($ev.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))] " -NoNewline -ForegroundColor DarkGray
                Write-Host "ID $($ev.Id) - $typeText" -ForegroundColor $evColor

                # Properties: [0]=File name, [1]=Process name (varies by event version)
                $props = $ev.Properties
                if ($props.Count -gt 0 -and $props[0].Value) {
                    Write-Host "    Soubor: $($props[0].Value)" -ForegroundColor White
                }
                if ($props.Count -gt 10 -and $props[10].Value) {
                    Write-Host "    Proces: $($props[10].Value)" -ForegroundColor Gray
                }
                Write-Host ""
            }
        }
    } catch {
        if ($_ -match "No events were found") {
            Write-Host "  Zadne WDAC udalosti nalezeny - event log je prazdny." -ForegroundColor Green
        } else {
            Write-Host "  Nelze cist WDAC event log: $_" -ForegroundColor Red
            Write-Host "  TIP: Ujistete se ze WDAC politika je aktivni a modus je Audit nebo Enforce." -ForegroundColor Yellow
        }
    }
}

function Add-LOLBinGuidance {
    Write-Host ""
    Write-Header "WDAC - Blokovani nebezpecnych nastroju (LOLBins)"
    Write-Host ""
    Write-Host "  LOLBins (Living Off The Land Binaries) jsou legitimni Windows nastroje" -ForegroundColor White
    Write-Host "  zneuzivane utocniky ke spusteni skodliveho kodu bez detekovani AV." -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  NEJCASTEJI ZNEUZIVANE NASTROJE:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "    mshta.exe    - spousti HTA soubory (HTML Applications)" -ForegroundColor Red
    Write-Host "    wscript.exe  - spousti VBScript (.vbs) a JScript (.js)" -ForegroundColor Red
    Write-Host "    cscript.exe  - command-line verze wscript" -ForegroundColor Red
    Write-Host "    certutil.exe - stahovani souboru, dekodovani Base64" -ForegroundColor Red
    Write-Host "    regsvr32.exe - spousteni COM DLL pres URL (Squiblydoo)" -ForegroundColor Yellow
    Write-Host "    rundll32.exe - spousteni DLL funkci" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  JAK BLOKOVAT PRES WDAC WIZARD:" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  1. Otevrete WDAC Wizard (volba 12 v WDAC menu)" -ForegroundColor White
    Write-Host "  2. Zvolte 'Edit Existing Policy' a vyberte vasi XML politiku" -ForegroundColor DarkGray
    Write-Host "  3. Prejdete na 'Deny Rules'" -ForegroundColor DarkGray
    Write-Host "  4. Kliknete '+ Add Deny Rule'" -ForegroundColor DarkGray
    Write-Host "  5. Zvolte 'Path' a zadejte cestu:" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "     C:\Windows\System32\mshta.exe" -ForegroundColor Magenta
    Write-Host "     C:\Windows\System32\wscript.exe" -ForegroundColor Magenta
    Write-Host "     C:\Windows\System32\cscript.exe" -ForegroundColor Magenta
    Write-Host "     C:\Windows\System32\certutil.exe" -ForegroundColor Magenta
    Write-Host ""
    Write-Host "  6. Ulozit, kompilovat a nasadit (volba 7 v WDAC menu)" -ForegroundColor DarkGray
    Write-Host "  7. Restartovat PC a otestovat" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  UPOZORNENI:" -ForegroundColor Yellow
    Write-Host "    - Nejprve otestujte v AUDIT modu, nektera legit. SW muze tyto nastroje pouzivat!" -ForegroundColor Yellow
    Write-Host "    - Napriklad: certutil pouzivaji nektera instalacni balicky" -ForegroundColor DarkGray
    Write-Host "    - Sledujte Event Log 3076 (audit) pred prechodem na 3077 (enforce)" -ForegroundColor DarkGray
    Write-Host ""
}

function New-CodeSigningCertificate {
    Write-Host ""
    Write-Header "Vytvorit Certifikat pro Podpis Maker / Skriptu"
    Write-Host ""
    Write-Host "  Tento certifikat umozni:" -ForegroundColor White
    Write-Host "    - Podepsat vlastni PowerShell skripty" -ForegroundColor DarkGray
    Write-Host "    - Podepsat Office makra (VBA)" -ForegroundColor DarkGray
    Write-Host "    - Pouzit s Office macro nastavenim 'Pouze podepsana makra'" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  POZNAMKA: Self-signed certifikat - urcen pro VLASTNI pouziti, ne pro sdileni." -ForegroundColor Yellow
    Write-Host ""

    $confirm = Read-Host "  Vytvorit self-signed code signing certifikat? (ano/ne)"
    if ($confirm -ne "ano") {
        Write-Host "  Zruseno." -ForegroundColor Yellow
        return
    }

    try {
        $certSubject = "CN=$env:USERNAME Code Signing, O=Home PC"
        $cert = New-SelfSignedCertificate `
            -Type CodeSigningCert `
            -Subject $certSubject `
            -CertStoreLocation "Cert:\CurrentUser\My" `
            -KeyUsage DigitalSignature `
            -FriendlyName "Muj Podpisovy Certifikat ($env:USERNAME)" `
            -NotAfter (Get-Date).AddYears(5) `
            -ErrorAction Stop

        Write-Host "  [OK] Certifikat vytvoren v Cert:\CurrentUser\My" -ForegroundColor Green
        Write-Host "  Thumbprint: $($cert.Thumbprint)" -ForegroundColor DarkGray
        Write-Host "  Platnost do: $($cert.NotAfter.ToString('dd.MM.yyyy'))" -ForegroundColor DarkGray

        # Export .cer souboru na Desktop
        $exportPath = "$env:USERPROFILE\Desktop\CodeSigningCert_$(Get-Date -Format 'yyyyMMdd').cer"
        Export-Certificate -Cert $cert -FilePath $exportPath -ErrorAction Stop
        Write-Host "  [OK] Certifikat exportovan: $exportPath" -ForegroundColor Green
        Write-Host ""
        Write-Host "  DALSI KROKY:" -ForegroundColor Cyan
        Write-Host "    1. Nainstalujte .cer do 'Trusted Root Certification Authorities'" -ForegroundColor White
        Write-Host "       (dvojklik na soubor -> Nainstalovat -> Misto: Lokalni pocitac -> Duveryhodne koreny)" -ForegroundColor DarkGray
        Write-Host "    2. Pro podpis PowerShell skriptu pouzijte:" -ForegroundColor White
        Write-Host "       `$cert = Get-Item Cert:\CurrentUser\My\$($cert.Thumbprint)" -ForegroundColor Magenta
        Write-Host "       Set-AuthenticodeSignature -FilePath 'skript.ps1' -Certificate `$cert" -ForegroundColor Magenta
        Write-Host "    3. Pro pouziti s Office makry - pridejte do Trusted Publishers" -ForegroundColor White
        Write-Host "       (Office -> Moznosti -> Centrum duvery -> Duveryhodne vydavatele)" -ForegroundColor DarkGray
    } catch {
        Write-Host "  [CHYBA] $_" -ForegroundColor Red
    }
}

# ==============================================================================
#   W D A C   -   W I Z A R D   a   I M P O R T   P O L I T I K
# ==============================================================================
function Install-WDACWizard {
    Write-Host ""
    Write-Host "  -- WDAC Wizard (Microsoft) --" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  WDAC Wizard je oficialni GUI nastroj od Microsoftu pro" -ForegroundColor DarkGray
    Write-Host "  jednoduche vytvareni WDAC politik bez znalosti PowerShellu." -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Funkce:" -ForegroundColor White
    Write-Host "    - Vizualni tvorba politik (Base, Supplemental, Multi-policy)" -ForegroundColor DarkGray
    Write-Host "    - Vyber sablon (DefaultWindows, AllowMicrosoft, atd.)" -ForegroundColor DarkGray
    Write-Host "    - Pridavani pravidel (Publisher, Path, Hash, PackagedApp)" -ForegroundColor DarkGray
    Write-Host "    - Editace existujicich XML politik" -ForegroundColor DarkGray
    Write-Host "    - Merge vice politik do jedne" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Zdroj: https://aka.ms/wdacwizard" -ForegroundColor Cyan
    Write-Host "  GitHub: https://github.com/MicrosoftDocs/WDAC-Toolkit" -ForegroundColor Cyan
    Write-Host ""

    # Zkontrolovat zda uz neni nainstalovan
    $existingApp = Get-AppxPackage -Name "Microsoft.WDAC*" -ErrorAction SilentlyContinue
    if ($existingApp) {
        Write-Host "  [INFO] WDAC Wizard je jiz nainstalovan: $($existingApp.Version)" -ForegroundColor Green
        $redownload = Read-Host "  Chcete stahnout znovu? (a/n, vychozi: n)"
        if ($redownload -ne "a") { return }
    }

    Initialize-WDACDirectory

    Write-Host "  Stahuji WDAC Wizard ..." -ForegroundColor Yellow
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $WDACWizardUrl -OutFile $WDACWizardInstaller -UseBasicParsing -ErrorAction Stop
        Write-Host "  [OK] Stazen: $WDACWizardInstaller" -ForegroundColor Green
    } catch {
        Write-Host "  [CHYBA] Nelze stahnout: $_" -ForegroundColor Red
        Write-Host ""
        Write-Host "  Muzete stahnout rucne z:" -ForegroundColor Yellow
        Write-Host "    https://aka.ms/wdacwizard" -ForegroundColor Cyan
        Write-Host "    nebo z Microsoft Store: hledejte 'WDAC Wizard'" -ForegroundColor Cyan
        return
    }

    Write-Host "  Instaluji WDAC Wizard ..." -ForegroundColor Yellow
    try {
        Add-AppxPackage -Path $WDACWizardInstaller -ErrorAction Stop
        Write-Host "  [OK] WDAC Wizard nainstalovan!" -ForegroundColor Green
        Write-Host ""
        Write-Host "  Spusteni: Start menu -> hledejte 'WDAC Wizard'" -ForegroundColor Cyan
        Write-Host "  Vytvorene XML politiky ulozte do:" -ForegroundColor Yellow
        Write-Host "    $WDACPolicyDir" -ForegroundColor Cyan
        Write-Host "  Pak je importujte volbou 'Importovat externi XML politiku' z tohoto menu." -ForegroundColor Yellow
    } catch {
        Write-Host "  [CHYBA] Instalace selhala: $_" -ForegroundColor Red
        Write-Host ""
        Write-Host "  Alternativy:" -ForegroundColor Yellow
        Write-Host "    1. Otevrete soubor rucne: $WDACWizardInstaller" -ForegroundColor DarkGray
        Write-Host "    2. Instalujte z Microsoft Store: hledejte 'WDAC Wizard'" -ForegroundColor DarkGray
        Write-Host "    3. GitHub: https://github.com/MicrosoftDocs/WDAC-Toolkit" -ForegroundColor DarkGray
    }
}

function Import-WDACExternalPolicy {
    Write-Host ""
    Write-Host "  -- Import externi XML politiky --" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Importujte politiku vytvorenou v WDAC Wizardu nebo jinym nastrojem." -ForegroundColor DarkGray
    Write-Host "  XML soubor bude pouzit jako zaklad nebo slouzen s existujici politikou." -ForegroundColor DarkGray
    Write-Host ""

    # Nabidnout soubory z WDAC adresare
    if (Test-Path $WDACPolicyDir) {
        $xmlFiles = Get-ChildItem -Path $WDACPolicyDir -Filter "*.xml" -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -notmatch "^(DefaultPolicy|CustomRules|MergedPolicy|ScanResult)" }
        if ($xmlFiles) {
            Write-Host "  Nalezene XML soubory v $WDACPolicyDir :" -ForegroundColor White
            for ($i = 0; $i -lt $xmlFiles.Count; $i++) {
                $size = [math]::Round($xmlFiles[$i].Length / 1KB, 1)
                Write-MenuItem "$($i+1)" "$($xmlFiles[$i].Name) ($size KB)"
            }
            Write-Host ""
            $fChoice = Read-Host "  Vyberte cislo souboru, nebo zadejte cestu rucne (prazdne = zrusit)"
            if ([string]::IsNullOrWhiteSpace($fChoice)) { return }

            if ($fChoice -match '^\d+$' -and [int]$fChoice -ge 1 -and [int]$fChoice -le $xmlFiles.Count) {
                $importPath = $xmlFiles[[int]$fChoice - 1].FullName
            } else {
                $importPath = $fChoice
            }
        } else {
            $importPath = Read-Host "  Cesta k XML souboru (prazdne = zrusit)"
            if ([string]::IsNullOrWhiteSpace($importPath)) { return }
        }
    } else {
        $importPath = Read-Host "  Cesta k XML souboru (prazdne = zrusit)"
        if ([string]::IsNullOrWhiteSpace($importPath)) { return }
    }

    if (-not (Test-Path $importPath)) {
        Write-Host "  [CHYBA] Soubor nenalezen: $importPath" -ForegroundColor Red
        return
    }

    # Validace ze je to WDAC XML
    try {
        [xml]$xmlContent = Get-Content $importPath -ErrorAction Stop
        if (-not $xmlContent.SiPolicy) {
            Write-Host "  [CHYBA] Soubor neni platna WDAC/CI politika (chybi SiPolicy element)." -ForegroundColor Red
            return
        }
        Write-Host "  [OK] Validni WDAC politika" -ForegroundColor Green
    } catch {
        Write-Host "  [CHYBA] Nelze nacist XML: $_" -ForegroundColor Red
        return
    }

    Write-Host ""
    Write-MenuItem "1" "Pouzit jako VYCHOZI politiku (nahradi DefaultPolicy.xml)" Green
    Write-MenuItem "2" "Sloucut s existujici politikou (merge)"
    Write-MenuItem "3" "Pouzit jako VLASTNI pravidla (nahradi CustomRules.xml)"
    Write-Host ""
    $action = Read-Host "  Vyberte akci"

    Initialize-WDACDirectory

    switch ($action) {
        "1" {
            Copy-Item $importPath $WDACDefaultXml -Force
            Write-Host "  [OK] Importovano jako vychozi politika: $WDACDefaultXml" -ForegroundColor Green
        }
        "2" {
            if (-not (Test-Path $WDACDefaultXml)) {
                Write-Host "  [CHYBA] Neexistuje vychozi politika pro merge. Nejprve ji vytvorte." -ForegroundColor Red
                return
            }
            try {
                Merge-CIPolicy -PolicyPaths $WDACDefaultXml, $importPath -OutputFilePath $WDACMergedXml -ErrorAction Stop
                Write-Host "  [OK] Politiky slouceny do: $WDACMergedXml" -ForegroundColor Green
            } catch {
                Write-Host "  [CHYBA] Merge selhal: $_" -ForegroundColor Red
            }
        }
        "3" {
            Copy-Item $importPath $WDACCustomXml -Force
            Write-Host "  [OK] Importovano jako vlastni pravidla: $WDACCustomXml" -ForegroundColor Green
        }
        default { Write-Host "  Zruseno." -ForegroundColor Yellow }
    }
    Write-Host "  Nezapomente kompilovat a nasadit z menu!" -ForegroundColor Yellow
}

# ==============================================================================
#        W D A C   -   V Y T V O R E N I   P O L I T I K Y
# ==============================================================================
function Initialize-WDACDirectory {
    if (-not (Test-Path $WDACPolicyDir)) {
        New-Item -Path $WDACPolicyDir -ItemType Directory -Force | Out-Null
        Write-Host "  Vytvoren adresar: $WDACPolicyDir" -ForegroundColor Green
    }
}

function New-WDACDefaultPolicy {
    param([switch]$AuditMode)
    Initialize-WDACDirectory

    Write-Host ""
    $modeName = if ($AuditMode) { "AUDIT" } else { "ENFORCE" }
    Write-Host "  Vytvarim vychozi WDAC politiku ($modeName mod) ..." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Tato politika povoli:" -ForegroundColor DarkGray
    Write-Host "    - Vsechny komponenty Windows" -ForegroundColor DarkGray
    Write-Host "    - Windows Store aplikace" -ForegroundColor DarkGray
    Write-Host "    - WHQL podepsane ovladace" -ForegroundColor DarkGray
    Write-Host "    - Aplikace z Intelligent Security Graph (Microsoft cloud reputace)" -ForegroundColor DarkGray
    Write-Host ""

    try {
        # Nejprve zkontrolujme zda modul ConfigCI existuje
        if (-not (Get-Command New-CIPolicy -ErrorAction SilentlyContinue)) {
            Write-Host "  [CHYBA] Cmdlet New-CIPolicy neni dostupny." -ForegroundColor Red
            Write-Host "  WDAC vyzaduje Windows 10/11 Pro nebo vyssi s ConfigCI modulem." -ForegroundColor Yellow
            Write-Host "  Zkuste: Import-Module ConfigCI" -ForegroundColor Yellow
            return
        }

        # Vytvorit DefaultWindows politiku
        # Pouzijeme predpripravenou politiku z Windows
        $defaultPolicyPath = "$env:windir\schemas\CodeIntegrity\ExamplePolicies\DefaultWindows_Audit.xml"
        if (-not (Test-Path $defaultPolicyPath)) {
            # Fallback - vytvorit sken-based
            Write-Host "  Predpripravena politika nenalezena, vytvarim scan-based ..." -ForegroundColor Yellow
            New-CIPolicy -Level Publisher -Fallback Hash -FilePath $WDACDefaultXml -UserPEs -ErrorAction Stop
        } else {
            Copy-Item $defaultPolicyPath $WDACDefaultXml -Force
            Write-Host "  [OK] Pouzita DefaultWindows sablona" -ForegroundColor Green
        }

        # Pridat ISG (Intelligent Security Graph) - Microsoft cloud reputace
        try {
            Set-RuleOption -FilePath $WDACDefaultXml -Option 14 -ErrorAction SilentlyContinue  # ISG
            Write-Host "  [OK] Pridano: Intelligent Security Graph (cloud reputace)" -ForegroundColor Green
        } catch {
            Write-Host "  [INFO] ISG nelze nastavit: $_" -ForegroundColor DarkGray
        }

        if ($AuditMode) {
            # Option 3 = Audit Mode
            Set-RuleOption -FilePath $WDACDefaultXml -Option 3
            Write-Host "  [OK] Nastaven AUDIT mod (jen loguje, neblokuje)" -ForegroundColor Yellow
        } else {
            # Odebrat audit mode
            Set-RuleOption -FilePath $WDACDefaultXml -Option 3 -Delete -ErrorAction SilentlyContinue
            Write-Host "  [OK] Nastaven ENFORCE mod (blokuje neschvalene aplikace!)" -ForegroundColor Green
        }

        Write-Host ""
        Write-Host "  Politika ulozena: $WDACDefaultXml" -ForegroundColor Green
        Write-Host ""
        Write-Host "  DALSI KROK: Pouzijte 'Kompilovat a nasadit' z menu." -ForegroundColor Cyan

    } catch {
        Write-Host "  [CHYBA] $_" -ForegroundColor Red
    }
}

# ==============================================================================
#        W D A C   -   V L A S T N I   P R A V I D L A
# ==============================================================================
function Add-WDACPathRule {
    Write-Host ""
    Write-Host "  -- Pridani pravidla podle cesty --" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Priklad cest:" -ForegroundColor DarkGray
    Write-Host "    C:\Program Files\MojeApp\*" -ForegroundColor DarkGray
    Write-Host "    C:\Tools\*.exe" -ForegroundColor DarkGray
    Write-Host ""

    $path = Read-Host "  Zadejte cestu (prazdne = zrusit)"
    if ([string]::IsNullOrWhiteSpace($path)) { return }

    if (-not (Test-Path (Split-Path $path -Parent -ErrorAction SilentlyContinue) -ErrorAction SilentlyContinue)) {
        Write-Host "  VAROVANI: Nadrazeny adresar neexistuje. Pokracuji pres to." -ForegroundColor Yellow
    }

    Initialize-WDACDirectory

    try {
        if (-not (Test-Path $WDACCustomXml)) {
            # Vytvorit prazdnou politiku
            Write-Host "  Vytvarim novou politiku pro vlastni pravidla ..." -ForegroundColor Yellow
            New-CIPolicy -Level Hash -FilePath $WDACCustomXml -UserPEs -ScanPath $env:windir\Temp -ErrorAction Stop
            # Smazat vsechna defaultni pravidla a nechat jen nas path rule
        }

        $rules = New-CIPolicyRule -FilePathRule $path -ErrorAction Stop
        Merge-CIPolicy -PolicyPaths $WDACCustomXml -Rules $rules -OutputFilePath $WDACCustomXml -ErrorAction Stop

        Write-Host "  [OK] Pravidlo pridano: $path" -ForegroundColor Green
        Write-Host "  Nezapomente znovu kompilovat a nasadit politiku!" -ForegroundColor Yellow
    } catch {
        Write-Host "  [CHYBA] $_" -ForegroundColor Red
    }
}

function Add-WDACPublisherRule {
    Write-Host ""
    Write-Host "  -- Pridani pravidla podle vydavatele (Publisher) --" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Zadejte cestu k podepsanemu EXE/DLL souboru." -ForegroundColor DarkGray
    Write-Host "  Skript extrahuje certifikat vydavatele a povoli vsechny jeho aplikace." -ForegroundColor DarkGray
    Write-Host ""

    $file = Read-Host "  Cesta k souboru (prazdne = zrusit)"
    if ([string]::IsNullOrWhiteSpace($file)) { return }
    if (-not (Test-Path $file)) {
        Write-Host "  [CHYBA] Soubor nenalezen: $file" -ForegroundColor Red
        return
    }

    Initialize-WDACDirectory

    try {
        if (-not (Test-Path $WDACCustomXml)) {
            New-CIPolicy -Level Hash -FilePath $WDACCustomXml -UserPEs -ScanPath $env:windir\Temp -ErrorAction Stop
        }

        $rules = New-CIPolicyRule -Level Publisher -FilePath $file -Fallback Hash -ErrorAction Stop
        Merge-CIPolicy -PolicyPaths $WDACCustomXml -Rules $rules -OutputFilePath $WDACCustomXml -ErrorAction Stop

        Write-Host "  [OK] Publisher pravidlo pridano ze souboru: $file" -ForegroundColor Green
        Write-Host "  Nezapomente znovu kompilovat a nasadit politiku!" -ForegroundColor Yellow
    } catch {
        Write-Host "  [CHYBA] $_" -ForegroundColor Red
    }
}

function Add-WDACHashRule {
    Write-Host ""
    Write-Host "  -- Pridani pravidla podle hashe souboru --" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Konkretni soubor bude povolen na zaklade jeho hashe." -ForegroundColor DarkGray
    Write-Host "  POZOR: Po aktualizaci aplikace se hash zmeni!" -ForegroundColor DarkGray
    Write-Host ""

    $file = Read-Host "  Cesta k souboru (prazdne = zrusit)"
    if ([string]::IsNullOrWhiteSpace($file)) { return }
    if (-not (Test-Path $file)) {
        Write-Host "  [CHYBA] Soubor nenalezen: $file" -ForegroundColor Red
        return
    }

    Initialize-WDACDirectory

    try {
        if (-not (Test-Path $WDACCustomXml)) {
            New-CIPolicy -Level Hash -FilePath $WDACCustomXml -UserPEs -ScanPath $env:windir\Temp -ErrorAction Stop
        }

        $rules = New-CIPolicyRule -Level Hash -FilePath $file -ErrorAction Stop
        Merge-CIPolicy -PolicyPaths $WDACCustomXml -Rules $rules -OutputFilePath $WDACCustomXml -ErrorAction Stop

        $hash = (Get-FileHash $file -Algorithm SHA256).Hash
        Write-Host "  [OK] Hash pravidlo pridano: $file" -ForegroundColor Green
        Write-Host "       SHA256: $hash" -ForegroundColor DarkGray
        Write-Host "  Nezapomente znovu kompilovat a nasadit politiku!" -ForegroundColor Yellow
    } catch {
        Write-Host "  [CHYBA] $_" -ForegroundColor Red
    }
}

function Add-WDACFolderScan {
    Write-Host ""
    Write-Host "  -- Sken slozky a povoleni vsech nalezenych aplikaci --" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Proskenuje zadanou slozku a povoli vsechny EXE/DLL nalezene v ni." -ForegroundColor DarkGray
    Write-Host "  Idealni pro C:\Program Files\* po ciste instalaci." -ForegroundColor DarkGray
    Write-Host ""

    $folder = Read-Host "  Cesta ke slozce (prazdne = zrusit)"
    if ([string]::IsNullOrWhiteSpace($folder)) { return }
    if (-not (Test-Path $folder -PathType Container)) {
        Write-Host "  [CHYBA] Slozka nenalezena: $folder" -ForegroundColor Red
        return
    }

    Initialize-WDACDirectory

    Write-Host "  Skenuji slozku (muze trvat dele) ..." -ForegroundColor Yellow

    try {
        $scanPolicyFile = "$WDACPolicyDir\ScanResult_$(Get-Date -Format 'yyyyMMdd_HHmmss').xml"
        New-CIPolicy -Level Publisher -Fallback Hash -FilePath $scanPolicyFile -ScanPath $folder -UserPEs -ErrorAction Stop

        if (Test-Path $WDACCustomXml) {
            Merge-CIPolicy -PolicyPaths $WDACCustomXml, $scanPolicyFile -OutputFilePath $WDACCustomXml -ErrorAction Stop
            Remove-Item $scanPolicyFile -Force -ErrorAction SilentlyContinue
        } else {
            Move-Item $scanPolicyFile $WDACCustomXml -Force
        }

        Write-Host "  [OK] Slozka proskenovana a pravidla pridana: $folder" -ForegroundColor Green
        Write-Host "  Nezapomente znovu kompilovat a nasadit politiku!" -ForegroundColor Yellow
    } catch {
        Write-Host "  [CHYBA] $_" -ForegroundColor Red
    }
}

# ==============================================================================
#     W D A C   -   K O M P I L A C E   a   N A S A Z E N I
# ==============================================================================
function Deploy-WDACPolicy {
    Write-Host ""
    Write-Host "  -- Kompilace a nasazeni WDAC politiky --" -ForegroundColor Cyan

    # Overit existenci zdrojove politiky
    $sourceXml = $null
    if ((Test-Path $WDACCustomXml) -and (Test-Path $WDACDefaultXml)) {
        Write-Host "  Slucuji vychozi + vlastni pravidla ..." -ForegroundColor Yellow
        try {
            Merge-CIPolicy -PolicyPaths $WDACDefaultXml, $WDACCustomXml -OutputFilePath $WDACMergedXml -ErrorAction Stop
            $sourceXml = $WDACMergedXml
            Write-Host "  [OK] Politiky slouceny" -ForegroundColor Green
        } catch {
            Write-Host "  [CHYBA] Merge selhal: $_" -ForegroundColor Red
            return
        }
    } elseif (Test-Path $WDACDefaultXml) {
        $sourceXml = $WDACDefaultXml
        Write-Host "  Pouzivam pouze vychozi politiku (zadna vlastni pravidla)." -ForegroundColor Yellow
    } else {
        Write-Host "  [CHYBA] Zadna politika nenalezena!" -ForegroundColor Red
        Write-Host "  Nejprve vytvorte vychozi politiku z menu." -ForegroundColor Yellow
        return
    }

    # Kompilace XML -> BIN
    Write-Host "  Kompiluji politiku ..." -ForegroundColor Yellow
    try {
        ConvertFrom-CIPolicy $sourceXml $WDACCompiledBin -ErrorAction Stop
        Write-Host "  [OK] Kompilace dokoncena: $WDACCompiledBin" -ForegroundColor Green
    } catch {
        Write-Host "  [CHYBA] Kompilace selhala: $_" -ForegroundColor Red
        return
    }

    # Nasazeni
    Write-Host "  Nasazuji politiku do systemu ..." -ForegroundColor Yellow
    try {
        Copy-Item $WDACCompiledBin $WDACDeployedPath -Force -ErrorAction Stop
        Write-Host "  [OK] Politika nasazena: $WDACDeployedPath" -ForegroundColor Green
        Write-Host ""
        Write-Host "  DULEZITE: Restartujte pocitac pro aktivaci politiky!" -ForegroundColor Yellow
        Write-Host "  DOPORUCENI: Nejprve pouzijte AUDIT mod a zkontrolujte Event Log." -ForegroundColor Yellow
    } catch {
        Write-Host "  [CHYBA] Nasazeni selhalo: $_" -ForegroundColor Red
    }
}

function Remove-WDACPolicy {
    Write-Host ""
    Write-Host "  -- Odebrani WDAC politiky --" -ForegroundColor Cyan

    if (Test-Path $WDACDeployedPath) {
        try {
            # Nejprve prepnout na audit
            if (Test-Path $WDACDefaultXml) {
                Set-RuleOption -FilePath $WDACDefaultXml -Option 3 -ErrorAction SilentlyContinue
                Write-Host "  Prepnuto na audit pred odebranim ..." -ForegroundColor Yellow
            }

            # Zazalohovat pred smazanim
            $backupPath = "$WDACDeployedPath.bak"
            Copy-Item -Path $WDACDeployedPath -Destination $backupPath -Force -ErrorAction SilentlyContinue
            if (Test-Path $backupPath) {
                Write-Host "  [OK] Zalohano: $backupPath" -ForegroundColor DarkGray
            }

            Remove-Item $WDACDeployedPath -Force -ErrorAction Stop
            Write-Host "  [OK] Politika odebrana ze systemu." -ForegroundColor Green
            Write-Host "  POZN: Restartujte pocitac pro uplne deaktivovani WDAC." -ForegroundColor Yellow
            Write-Host "  Zaloha uschrana v: $backupPath" -ForegroundColor DarkGray
            Write-Host "  (Pokud neco nefunguje po restartu, lze zalohu obnovit z WinRE)" -ForegroundColor DarkGray
        } catch {
            Write-Host "  [CHYBA] $_" -ForegroundColor Red
            Write-Host "  TIP: Mozna budete muset spustit z recovery konzole." -ForegroundColor Yellow
        }
    } else {
        Write-Host "  Zadna nasazena politika nenalezena." -ForegroundColor Yellow
    }
}

function Switch-WDACAuditEnforce {
    param([switch]$Audit)
    if (-not (Test-Path $WDACDefaultXml)) {
        Write-Host "  [CHYBA] Vychozi politika neexistuje. Vytvorte ji z menu." -ForegroundColor Red
        return
    }
    try {
        if ($Audit) {
            Set-RuleOption -FilePath $WDACDefaultXml -Option 3 -ErrorAction Stop
            Write-Host "  [OK] Politika prepnuta na AUDIT mod" -ForegroundColor Yellow
        } else {
            Set-RuleOption -FilePath $WDACDefaultXml -Option 3 -Delete -ErrorAction Stop
            Write-Host "  [OK] Politika prepnuta na ENFORCE mod" -ForegroundColor Green
        }
        Write-Host "  Znovu kompilujte a nasadte pro uplatneni zmeny." -ForegroundColor Yellow
    } catch {
        Write-Host "  [CHYBA] $_" -ForegroundColor Red
    }
}

# ==============================================================================
#      M A C R O   W H I T E L I S T I N G   -   K O N S T A N T Y
# ==============================================================================
# Office VBA security registry paths
# VBAWarnings values: 1=AllEnabled, 2=DisableWithNotification, 3=DisableExceptSigned, 4=DisableAll

function Get-InstalledOfficeVersion {
    # Detekce nainstalovanej verze Office z registry
    $versions = @("16.0","15.0","14.0","12.0")
    foreach ($ver in $versions) {
        $testPath = "HKCU:\SOFTWARE\Microsoft\Office\$ver\Word"
        if (Test-Path $testPath) { return $ver }
    }
    # Fallback - hledat v COM registration
    try {
        $wordCom = Get-ItemProperty "HKLM:\SOFTWARE\Classes\Word.Application\CurVer" -ErrorAction SilentlyContinue
        if ($wordCom) {
            $comVer = $wordCom.'(default)' -replace 'Word\.Application\.', ''
            if ($comVer) { return "$comVer.0" }
        }
    } catch {}
    return "16.0"  # vychozi fallback pro Office 2016+/365
}

$script:OfficeVersion = Get-InstalledOfficeVersion

$OfficeApps = [ordered]@{
    "Word"       = @{ RegPath = "HKCU:\SOFTWARE\Policies\Microsoft\Office\$script:OfficeVersion\Word\Security";       Name = "Word" }
    "Excel"      = @{ RegPath = "HKCU:\SOFTWARE\Policies\Microsoft\Office\$script:OfficeVersion\Excel\Security";      Name = "Excel" }
    "PowerPoint" = @{ RegPath = "HKCU:\SOFTWARE\Policies\Microsoft\Office\$script:OfficeVersion\PowerPoint\Security"; Name = "PowerPoint" }
    "Access"     = @{ RegPath = "HKCU:\SOFTWARE\Policies\Microsoft\Office\$script:OfficeVersion\Access\Security";     Name = "Access" }
    "Outlook"    = @{ RegPath = "HKCU:\SOFTWARE\Policies\Microsoft\Office\$script:OfficeVersion\Outlook\Security";    Name = "Outlook" }
    "Visio"      = @{ RegPath = "HKCU:\SOFTWARE\Policies\Microsoft\Office\$script:OfficeVersion\Visio\Security";      Name = "Visio" }
    "Publisher"  = @{ RegPath = "HKCU:\SOFTWARE\Policies\Microsoft\Office\$script:OfficeVersion\Publisher\Security";   Name = "Publisher" }
}

$VBAWarningLabels = @{
    1 = "Vse povoleno (nebezpecne!)"
    2 = "Zakazano s notifikaci (vychozi)"
    3 = "Zakazano krome podepsanych"
    4 = "Vse zakazano"
}

# ==============================================================================
#    M A C R O   -   S T A V   a   N A S T A V E N I
# ==============================================================================
function Get-MacroStatus {
    param([string]$AppKey)
    $app = $OfficeApps[$AppKey]
    if (-not $app) { return "Neznama app" }

    try {
        $regPath = $app.RegPath
        if (-not (Test-Path $regPath)) { return "Nenastaveno (vychozi Office)" }
        $val = Get-ItemProperty -Path $regPath -Name "VBAWarnings" -ErrorAction SilentlyContinue
        if ($null -eq $val -or $null -eq $val.VBAWarnings) { return "Nenastaveno" }
        $code = $val.VBAWarnings
        if ($VBAWarningLabels.ContainsKey($code)) { $VBAWarningLabels[$code] }
        else { "Neznamy ($code)" }
    } catch { "Chyba" }
}

function Get-MacroStatusShort {
    $statuses = @()
    foreach ($key in $OfficeApps.Keys) {
        $st = Get-MacroStatus -AppKey $key
        if ($st -match "podepsanych") { $statuses += "P" }
        elseif ($st -match "Vse zakazano") { $statuses += "X" }
        elseif ($st -match "Vse povoleno") { $statuses += "!" }
        elseif ($st -match "notifikaci") { $statuses += "N" }
        else { $statuses += "-" }
    }
    # Zjistit prevladajici stav
    $signed = ($statuses | Where-Object { $_ -eq "P" }).Count
    $total  = $statuses.Count
    if ($signed -eq $total) { return "Jen podepsane (vse)" }
    $blocked = ($statuses | Where-Object { $_ -eq "X" }).Count
    if ($blocked -eq $total) { return "Vse zakazano" }
    $danger = ($statuses | Where-Object { $_ -eq "!" }).Count
    if ($danger -gt 0) { return "POZOR: Neco povoleno!" }
    $unset = ($statuses | Where-Object { $_ -eq "-" }).Count
    if ($unset -eq $total) { return "Nenastaveno" }
    return "Smisene nastaveni"
}

function Show-MacroStatusAll {
    Write-Header "Stav Office maker - vsechny aplikace"
    Write-Host ""
    foreach ($key in $OfficeApps.Keys) {
        $st = Get-MacroStatus -AppKey $key
        $color = if ($st -match "podepsanych") { 'Green' }
                 elseif ($st -match "Vse zakazano") { 'Cyan' }
                 elseif ($st -match "Vse povoleno") { 'Red' }
                 elseif ($st -match "notifikaci") { 'Yellow' }
                 else { 'DarkGray' }
        Write-Status $OfficeApps[$key].Name $st $color
    }
}

function Set-MacroPolicy {
    param([int]$Level)
    # Level: 1=AllEnabled, 2=DisableNotif, 3=DisableExceptSigned, 4=DisableAll
    $label = $VBAWarningLabels[$Level]
    Write-Host ""
    Write-Host "  Nastavuji makra na: $label ..." -ForegroundColor Yellow

    foreach ($key in $OfficeApps.Keys) {
        $regPath = $OfficeApps[$key].RegPath
        try {
            if (-not (Test-Path $regPath)) {
                New-Item -Path $regPath -Force | Out-Null
            }
            Set-ItemProperty -Path $regPath -Name "VBAWarnings" -Value $Level -Type DWord -ErrorAction Stop
            Write-Host "    [OK] $($OfficeApps[$key].Name)" -ForegroundColor Green
        } catch {
            Write-Host "    [CHYBA] $($OfficeApps[$key].Name): $_" -ForegroundColor Red
        }
    }
    Write-Host "  Hotovo." -ForegroundColor Green
}

# ==============================================================================
#     M A C R O   -   T R U S T E D   L O C A T I O N S
# ==============================================================================
function Get-TrustedLocations {
    param([string]$AppKey = "Word")
    $app = $OfficeApps[$AppKey]
    if (-not $app) { return @() }

    $basePath = $app.RegPath -replace "\\Security$", "\Security\Trusted Locations"
    $locations = @()

    if (-not (Test-Path $basePath)) { return $locations }

    $subKeys = Get-ChildItem -Path $basePath -ErrorAction SilentlyContinue
    foreach ($sub in $subKeys) {
        $props = Get-ItemProperty -Path $sub.PSPath -ErrorAction SilentlyContinue
        if ($props.Path) {
            $locations += [PSCustomObject]@{
                Key         = $sub.PSChildName
                Path        = $props.Path
                AllowSub    = [bool]$props.AllowSubFolders
                Description = if ($props.Description) { $props.Description } else { "-" }
            }
        }
    }
    return $locations
}

function Show-TrustedLocations {
    Write-Header "Trusted Locations - duveryhodna umisteni maker"
    Write-Host ""

    foreach ($appKey in $OfficeApps.Keys) {
        $locs = Get-TrustedLocations -AppKey $appKey
        Write-Host "  $($OfficeApps[$appKey].Name):" -ForegroundColor White
        if ($locs.Count -eq 0) {
            Write-Host "    Zadne vlastni trusted locations." -ForegroundColor DarkGray
        } else {
            foreach ($loc in $locs) {
                $subText = if ($loc.AllowSub) { " (+podslozky)" } else { "" }
                Write-Host "    [$($loc.Key)] $($loc.Path)$subText" -ForegroundColor Cyan
                if ($loc.Description -ne "-") {
                    Write-Host "         Popis: $($loc.Description)" -ForegroundColor DarkGray
                }
            }
        }
        Write-Host ""
    }
}

function Add-TrustedLocation {
    Write-Host ""
    Write-Host "  -- Pridani Trusted Location --" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Makra ze souboru v teto slozce budou povolena bez upozorneni." -ForegroundColor DarkGray
    Write-Host ""

    $folder = Read-Host "  Cesta ke slozce (prazdne = zrusit)"
    if ([string]::IsNullOrWhiteSpace($folder)) { return }

    $desc = Read-Host "  Popis (volitelne, Enter = preskocit)"

    Write-Host ""
    Write-Host "  Aplikace pro pridani:" -ForegroundColor Yellow
    Write-MenuItem "1" "Vsechny Office aplikace" Green
    Write-MenuItem "2" "Jen Word"
    Write-MenuItem "3" "Jen Excel"
    Write-MenuItem "4" "Jen PowerPoint"
    Write-Host ""
    $appChoice = Read-Host "  Vyberte"

    $targetApps = switch ($appChoice) {
        "1" { $OfficeApps.Keys }
        "2" { @("Word") }
        "3" { @("Excel") }
        "4" { @("PowerPoint") }
        default { $OfficeApps.Keys }
    }

    Write-Host ""
    $allowSub = Read-Host "  Povolit i podslozky? (a/n, vychozi: a)"
    $allowSubVal = if ($allowSub -eq "n") { 0 } else { 1 }

    foreach ($appKey in $targetApps) {
        $basePath = $OfficeApps[$appKey].RegPath -replace "\\Security$", "\Security\Trusted Locations"
        try {
            if (-not (Test-Path $basePath)) {
                New-Item -Path $basePath -Force | Out-Null
            }
            # Najit dalsi volny Location klic
            $existing = Get-ChildItem -Path $basePath -ErrorAction SilentlyContinue
            $nextNum = 100  # Zaciname od 100 aby neklidovaly s defaultnimi
            if ($existing) {
                $nums = $existing.PSChildName | Where-Object { $_ -match "^Location(\d+)$" } |
                    ForEach-Object { [int]($_ -replace "Location", "") }
                if ($nums) { $nextNum = ($nums | Measure-Object -Maximum).Maximum + 1 }
            }

            $locPath = "$basePath\Location$nextNum"
            New-Item -Path $locPath -Force | Out-Null
            Set-ItemProperty -Path $locPath -Name "Path" -Value $folder -Type String
            Set-ItemProperty -Path $locPath -Name "AllowSubFolders" -Value $allowSubVal -Type DWord
            if (-not [string]::IsNullOrWhiteSpace($desc)) {
                Set-ItemProperty -Path $locPath -Name "Description" -Value $desc -Type String
            }

            Write-Host "    [OK] $($OfficeApps[$appKey].Name): $folder" -ForegroundColor Green
        } catch {
            Write-Host "    [CHYBA] $($OfficeApps[$appKey].Name): $_" -ForegroundColor Red
        }
    }
    Write-Host "  Hotovo." -ForegroundColor Green
}

function Remove-TrustedLocation {
    Write-Host ""
    Write-Host "  -- Odebrani Trusted Location --" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Vyberte aplikaci:" -ForegroundColor Yellow

    $appKeys = @($OfficeApps.Keys)
    for ($i = 0; $i -lt $appKeys.Count; $i++) {
        Write-MenuItem "$($i+1)" $OfficeApps[$appKeys[$i]].Name
    }
    Write-Host ""
    $appIdx = Read-Host "  Cislo aplikace (prazdne = zrusit)"
    if ([string]::IsNullOrWhiteSpace($appIdx)) { return }
    $idx = [int]$appIdx - 1
    if ($idx -lt 0 -or $idx -ge $appKeys.Count) {
        Write-Host "  Neplatna volba." -ForegroundColor Red
        return
    }

    $appKey = $appKeys[$idx]
    $locs = Get-TrustedLocations -AppKey $appKey
    if ($locs.Count -eq 0) {
        Write-Host "  Zadne trusted locations k odebrani." -ForegroundColor Yellow
        return
    }

    Write-Host ""
    Write-Host "  Existing locations pro $($OfficeApps[$appKey].Name):" -ForegroundColor White
    for ($i = 0; $i -lt $locs.Count; $i++) {
        Write-MenuItem "$($i+1)" "[$($locs[$i].Key)] $($locs[$i].Path)"
    }
    Write-Host ""
    $locIdx = Read-Host "  Cislo k odebrani (prazdne = zrusit)"
    if ([string]::IsNullOrWhiteSpace($locIdx)) { return }
    $li = [int]$locIdx - 1
    if ($li -lt 0 -or $li -ge $locs.Count) {
        Write-Host "  Neplatna volba." -ForegroundColor Red
        return
    }

    $basePath = $OfficeApps[$appKey].RegPath -replace "\\Security$", "\Security\Trusted Locations"
    $targetKey = "$basePath\$($locs[$li].Key)"
    try {
        Remove-Item -Path $targetKey -Recurse -Force -ErrorAction Stop
        Write-Host "  [OK] Odebrano: $($locs[$li].Path)" -ForegroundColor Green
    } catch {
        Write-Host "  [CHYBA] $_" -ForegroundColor Red
    }
}

# ==============================================================================
#    M A C R O   -   T R U S T E D   P U B L I S H E R S
# ==============================================================================
function Show-TrustedPublishers {
    Write-Header "Trusted Publishers - duveryhodne vydavatele"
    Write-Host ""
    try {
        $certs = Get-ChildItem Cert:\CurrentUser\TrustedPublisher -ErrorAction Stop
        if ($certs.Count -eq 0) {
            Write-Host "  Zadne duveryhodne vydavatele." -ForegroundColor DarkGray
        } else {
            foreach ($cert in $certs) {
                $subj = if ($cert.Subject.Length -gt 60) { $cert.Subject.Substring(0,57) + "..." } else { $cert.Subject }
                Write-Host "  [" -NoNewline
                Write-Host "$($cert.Thumbprint.Substring(0,12))..." -ForegroundColor Cyan -NoNewline
                Write-Host "] " -NoNewline
                Write-Host "$subj" -ForegroundColor White
                Write-Host "       Platnost: $($cert.NotBefore.ToString('dd.MM.yyyy')) - $($cert.NotAfter.ToString('dd.MM.yyyy'))" -ForegroundColor DarkGray
            }
        }
        Write-Host ""

        # Machine level
        Write-Host "  Machine-level publishers:" -ForegroundColor White
        $mcerts = Get-ChildItem Cert:\LocalMachine\TrustedPublisher -ErrorAction SilentlyContinue
        if ($mcerts -and $mcerts.Count -gt 0) {
            foreach ($cert in $mcerts) {
                $subj = if ($cert.Subject.Length -gt 60) { $cert.Subject.Substring(0,57) + "..." } else { $cert.Subject }
                Write-Host "  [$($cert.Thumbprint.Substring(0,12))...] $subj" -ForegroundColor DarkGray
            }
        } else {
            Write-Host "  Zadne." -ForegroundColor DarkGray
        }
    } catch {
        Write-Host "  CHYBA: $_" -ForegroundColor Red
    }
}

function Add-TrustedPublisher {
    Write-Host ""
    Write-Host "  -- Pridani Trusted Publisher z certifikatu --" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Muzete zadat cestu k:" -ForegroundColor DarkGray
    Write-Host "    - .cer / .crt souboru (certifikat)" -ForegroundColor DarkGray
    Write-Host "    - podepsanemu .exe / .dll (extrahuje certifikat)" -ForegroundColor DarkGray
    Write-Host ""

    $file = Read-Host "  Cesta k souboru (prazdne = zrusit)"
    if ([string]::IsNullOrWhiteSpace($file)) { return }
    if (-not (Test-Path $file)) {
        Write-Host "  [CHYBA] Soubor nenalezen: $file" -ForegroundColor Red
        return
    }

    try {
        $ext = [IO.Path]::GetExtension($file).ToLower()
        if ($ext -in ".cer", ".crt") {
            $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($file)
        } else {
            # Extrahovat certifikat z podepsaneho souboru
            $sig = Get-AuthenticodeSignature $file -ErrorAction Stop
            if ($sig.Status -eq "Valid" -or $sig.Status -eq "UnknownError") {
                $cert = $sig.SignerCertificate
            } else {
                Write-Host "  [CHYBA] Soubor neni validne podepsany (status: $($sig.Status))" -ForegroundColor Red
                return
            }
        }

        if (-not $cert) {
            Write-Host "  [CHYBA] Nelze ziskat certifikat." -ForegroundColor Red
            return
        }

        Write-Host "  Certifikat: $($cert.Subject)" -ForegroundColor White
        Write-Host "  Platnost:   $($cert.NotBefore.ToString('dd.MM.yyyy')) - $($cert.NotAfter.ToString('dd.MM.yyyy'))" -ForegroundColor DarkGray
        Write-Host ""

        if ($cert.NotAfter -lt (Get-Date)) {
            Write-Host "  [VAROVANI] Certifikat je EXPIROVAN (do: $($cert.NotAfter.ToString('dd.MM.yyyy')))!" -ForegroundColor Red
            Write-Host "  Expirovanhy certifikat nemusĂ­ poskytnout ochranu." -ForegroundColor Yellow
        }

        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("TrustedPublisher", "CurrentUser")
        $store.Open("ReadWrite")
        $store.Add($cert)
        $store.Close()

        Write-Host "  [OK] Publisher pridan do TrustedPublisher (CurrentUser)" -ForegroundColor Green
    } catch {
        Write-Host "  [CHYBA] $_" -ForegroundColor Red
    }
}

# ==============================================================================
#    P O W E R S H E L L   H A R D E N I N G
# ==============================================================================
function Get-PSLanguageModeStatus {
    try {
        # Prioritne kontrolujeme promennou prostredi, ktera muze byt nastavena docasne
        if ($env:__PSLockdownPolicy) {
            return "Constrained (docasne)"
        }
        # Pak kontrolujeme systemove nastaveni v registru
        $val = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -Name "__PSLockdownPolicy" -ErrorAction SilentlyContinue
        if ($val -and $val.__PSLockdownPolicy -eq "4") {
            return "Constrained (trvale)"
        }
        return "Full Language"
    } catch {
        return "Neznamy"
    }
}

function Set-PSLanguageMode {
    param([bool]$Constrained)
    Write-Host ""
    if ($Constrained) {
        Write-Host "  Zapinam PowerShell Constrained Language Mode..." -ForegroundColor Yellow
        try {
            # Nastaveni systemove promenne pro trvale pouziti
            Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -Name "__PSLockdownPolicy" -Value "4" -Type String -ErrorAction Stop
            Write-Host "  [OK] Constrained Language Mode bude aktivni po restartu nebo v novem terminalu." -ForegroundColor Green
            Write-Host "  POZN: WDAC politika muze tento mod vynutit automaticky." -ForegroundColor DarkGray
        } catch {
            Write-Host "  [CHYBA] Nepodarilo se nastavit registr: $_" -ForegroundColor Red
        }
    } else {
        Write-Host "  Vypinam PowerShell Constrained Language Mode..." -ForegroundColor Yellow
        try {
            # Odstraneni systemove promenne
            Remove-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -Name "__PSLockdownPolicy" -ErrorAction SilentlyContinue
            Write-Host "  [OK] Constrained Language Mode bude deaktivovan po restartu nebo v novem terminalu." -ForegroundColor Green
        } catch {
            Write-Host "  [CHYBA] Nepodarilo se upravit registr: $_" -ForegroundColor Red
        }
    }
}

# ==============================================================================
#       V O L B A   9 9   -   K O M P L E T N I   P R E H L E D
# ==============================================================================
function Show-WDACWorkflow {
    Show-Banner
    Write-Header "WDAC - PODROBNY NAVOD"

    Write-Host ""
    Write-Host "  ================================================================" -ForegroundColor DarkCyan
    Write-Host "  CO JE WDAC?" -ForegroundColor Cyan
    Write-Host "  ================================================================" -ForegroundColor DarkCyan
    Write-Host "  WDAC (Windows Defender Application Control) je technologie" -ForegroundColor White
    Write-Host "  Microsoftu ktera definuje KTERE aplikace smi na PC bezet." -ForegroundColor White
    Write-Host "  Vsechno ostatni je blokovano. Chrani pred malwarem, ransomwarem" -ForegroundColor White
    Write-Host "  i pred nahodnym spoustenim neoverenych programu." -ForegroundColor White

    Write-Host ""
    Write-Host "  ================================================================" -ForegroundColor DarkCyan
    Write-Host "  SLOZKA PRO POLITIKY" -ForegroundColor Cyan
    Write-Host "  ================================================================" -ForegroundColor DarkCyan
    Write-Host "  Vsechny politiky (XML, BIN) se ukladaji do:" -ForegroundColor White
    Write-Host "  $WDACPolicyDir" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Soubory:" -ForegroundColor White
    Write-Host "    DefaultPolicy.xml  = Zakladni politika (co Windows povoli)" -ForegroundColor DarkGray
    Write-Host "    CustomRules.xml    = Vase vlastni pravidla (vase aplikace)" -ForegroundColor DarkGray
    Write-Host "    MergedPolicy.xml   = Sloupceni obou do jednoho souboru" -ForegroundColor DarkGray
    Write-Host "    MergedPolicy.bin   = Skompilovana politika (co se nasazuje)" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  WDAC Wizard uklada XML tam, kam si vyberte - ulozte ho do" -ForegroundColor Yellow
    Write-Host "  slozky vyse, at ho tento skript snadno najde." -ForegroundColor Yellow

    Write-Host ""
    Write-Host "  ================================================================" -ForegroundColor DarkCyan
    Write-Host "  WORKFLOW A) S WDAC WIZARDEM (doporuceno pro zacatecniky)" -ForegroundColor Cyan
    Write-Host "  ================================================================" -ForegroundColor DarkCyan
    Write-Host ""
    Write-Host "  KROK 1: Stahnout WDAC Wizard" -ForegroundColor Yellow
    Write-Host "    -> V tomto skriptu: Volba 12" -ForegroundColor White
    Write-Host "    -> Nebo rucne z: https://aka.ms/wdacwizard" -ForegroundColor DarkGray
    Write-Host "    -> Nebo Microsoft Store: hledejte 'WDAC Wizard'" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  KROK 2: Vytvorit politiku ve Wizardu" -ForegroundColor Yellow
    Write-Host "    -> Spustit ze Start menu" -ForegroundColor White
    Write-Host "    -> Zvolit: Policy Creator -> Base Policy" -ForegroundColor White
    Write-Host "    -> Sablona: 'Default Windows Mode' (povoluje Windows komponenty)" -ForegroundColor White
    Write-Host "    -> Rezim: AUDIT MODE (nejprve jen loguje, neblokuje!)" -ForegroundColor White
    Write-Host ""
    Write-Host "  KROK 3: Pridat vase aplikace ve Wizardu" -ForegroundColor Yellow
    Write-Host "    -> 'Custom Rules' -> pridat pravidla:" -ForegroundColor White
    Write-Host "       Publisher = povoli vsechny app od daneho vydavatele (nejlepsi)" -ForegroundColor DarkGray
    Write-Host "       Path      = povoli vsechny app z dane slozky" -ForegroundColor DarkGray
    Write-Host "       Hash      = povoli jen konkretni soubor (nejprisnejsi)" -ForegroundColor DarkGray
    Write-Host "    -> Priklad: Pridat C:\Program Files\Mozilla Firefox\*.exe" -ForegroundColor DarkGray
    Write-Host "    -> Priklad: Pridat publisher 'Mozilla Corporation'" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  KROK 4: Ulozit XML politiku" -ForegroundColor Yellow
    Write-Host "    -> Ulozit do: $WDACPolicyDir" -ForegroundColor Green
    Write-Host "    -> Pojmenovat napr. 'MojePolitika.xml'" -ForegroundColor White
    Write-Host ""
    Write-Host "  KROK 5: Importovat do tohoto skriptu" -ForegroundColor Yellow
    Write-Host "    -> Volba 13 -> Importovat externi XML politiku" -ForegroundColor White
    Write-Host "    -> Skript nabidne nalezene XML soubory" -ForegroundColor White
    Write-Host "    -> Zvolit 'Pouzit jako vychozi politiku'" -ForegroundColor White
    Write-Host ""
    Write-Host "  KROK 6: Kompilovat a nasadit" -ForegroundColor Yellow
    Write-Host "    -> Volba 7 -> Skript zkompiluje XML na BIN a nasadi" -ForegroundColor White
    Write-Host "    -> RESTARTOVAT POCITAC" -ForegroundColor Red
    Write-Host ""
    Write-Host "  KROK 7: Overit ze vse funguje" -ForegroundColor Yellow
    Write-Host "    -> Volba 11 -> Zobrazit Event Log" -ForegroundColor White
    Write-Host "    -> Hledejte udalosti s ID 3076 (audit: tohle by se zablokovalo)" -ForegroundColor White
    Write-Host "    -> Pokud neco chybi, vradte se ke kroku 3 a pridejte pravidla" -ForegroundColor White
    Write-Host ""
    Write-Host "  KROK 8: Prepnout na ENFORCE (az jste si jisti!)" -ForegroundColor Yellow
    Write-Host "    -> Volba 9 -> Prepnout na Enforce mod" -ForegroundColor White
    Write-Host "    -> Volba 7 -> Znovu kompilovat a nasadit" -ForegroundColor White
    Write-Host "    -> RESTARTOVAT POCITAC" -ForegroundColor Red
    Write-Host "    -> Neschvalene aplikace budou nyni BLOKOVANY" -ForegroundColor Red

    Write-Host ""
    Write-Host "  ================================================================" -ForegroundColor DarkCyan
    Write-Host "  WORKFLOW B) PRIMO V TOMTO SKRIPTU (pro pokrocile)" -ForegroundColor Cyan
    Write-Host "  ================================================================" -ForegroundColor DarkCyan
    Write-Host ""
    Write-Host "  1. Volba 1  -> Vytvorit vychozi politiku (Audit mod)" -ForegroundColor White
    Write-Host "  2. Volba 6  -> Proskenovad slozky s vasimi aplikacemi" -ForegroundColor White
    Write-Host "     (napr. C:\Program Files, C:\Program Files (x86))" -ForegroundColor DarkGray
    Write-Host "  3. Volby 3-5 -> Pridat jednotlive aplikace (cesta/publisher/hash)" -ForegroundColor White
    Write-Host "  4. Volba 7  -> Kompilovat a nasadit" -ForegroundColor White
    Write-Host "  5. Restartovat PC" -ForegroundColor White
    Write-Host "  6. Volba 11 -> Zkontrolovat Event Log" -ForegroundColor White
    Write-Host "  7. Volba 9  -> Prepnout na Enforce (az vse funguje)" -ForegroundColor White
    Write-Host "  8. Volba 7  -> Znovu kompilovat a nasadit -> Restart" -ForegroundColor White

    Write-Host ""
    Write-Host "  ================================================================" -ForegroundColor DarkCyan
    Write-Host "  DULEZITE TIPY" -ForegroundColor Cyan
    Write-Host "  ================================================================" -ForegroundColor DarkCyan
    Write-Host "  - VZDY zacnete v AUDIT modu! Enforce muze zablokovat PC." -ForegroundColor Yellow
    Write-Host "  - Po kazde zmene je treba KOMPILOVAT (volba 7) a RESTARTOVAT." -ForegroundColor Yellow
    Write-Host "  - Event Log ID 3076 = audit (tohle BY se zablokovalo)." -ForegroundColor Yellow
    Write-Host "  - Event Log ID 3077 = enforce (tohle se ZABLOKOVALO)." -ForegroundColor Yellow
    Write-Host "  - Pokud se po Enforce neco rozbije, spusdte v Safe Mode" -ForegroundColor Yellow
    Write-Host "    a smazte soubor: $WDACDeployedPath" -ForegroundColor Yellow
    Write-Host "  - Publisher pravidla jsou nejlepsi - preziji aktualizace app." -ForegroundColor Yellow
    Write-Host "  - Hash pravidla jsou nejprisnejsi ale musi se menit po updatu." -ForegroundColor Yellow
    Write-Host ""
}

function Show-QuickStartGuide {
    Show-Banner
    Write-Header "RYCHLY NAVOD - JAK ZACIT"

    Write-Host ""
    Write-Host "  ================================================================" -ForegroundColor DarkCyan
    Write-Host "  1) APPLICATION WHITELISTING (WDAC) - menu volba 1" -ForegroundColor Cyan
    Write-Host "  ================================================================" -ForegroundColor DarkCyan
    Write-Host ""
    Write-Host "  Nejjednodussi postup:" -ForegroundColor White
    Write-Host "    A. Jdete do WDAC menu (volba 1)" -ForegroundColor Yellow
    Write-Host "    B. Stahnete WDAC Wizard (volba 12) - GUI od Microsoftu" -ForegroundColor Yellow
    Write-Host "    C. Ve Wizardu vytvorte politiku:" -ForegroundColor Yellow
    Write-Host "       -> Base Policy -> DefaultWindows -> Audit Mode" -ForegroundColor White
    Write-Host "       -> Pridejte vase aplikace (Firefox, Chrome, 7-Zip...)" -ForegroundColor White
    Write-Host "       -> Ulozte XML do: $WDACPolicyDir" -ForegroundColor Green
    Write-Host "    D. Importujte (volba 13) -> Kompilujte (volba 7) -> Restart" -ForegroundColor Yellow
    Write-Host "    E. Otestujte a prepnete Enforce (volba 9)" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Podrobny navod: WDAC menu -> volba 14" -ForegroundColor DarkGray

    Write-Host ""
    Write-Host "  ================================================================" -ForegroundColor DarkCyan
    Write-Host "  2) MACRO WHITELISTING - menu volba 2" -ForegroundColor Cyan
    Write-Host "  ================================================================" -ForegroundColor DarkCyan
    Write-Host ""
    Write-Host "  Nejjednodussi postup:" -ForegroundColor White
    Write-Host "    A. Jdete do Macro menu (volba 2)" -ForegroundColor Yellow
    Write-Host "    B. Zvolte 'Zakazat vse krome podepsanych' (volba 2)" -ForegroundColor Yellow
    Write-Host "    C. Pokud mate vlastni makra, pridejte Trusted Location:" -ForegroundColor Yellow
    Write-Host "       -> Volba 7 -> zadejte slozku s vasimi Office soubory" -ForegroundColor White
    Write-Host "    D. Hotovo! Makra bezi jen podepsana nebo z vasich slozek." -ForegroundColor Yellow
    Write-Host ""
}

function Show-FullStatus {
    Show-Banner
    Write-Header "KOMPLETNI PREHLED"

    function Get-StatusColor([string]$Value) {
        if ($Value -match "Enforce|podepsanych|Vse zakazano") { 'Green' }
        elseif ($Value -match "Vypnuto|Nenastaveno|povoleno") { 'Red' }
        else { 'Yellow' }
    }

    Write-Host ""
    Write-Host "  -- WDAC (Application Whitelisting) --------------------------------" -ForegroundColor Magenta
    $v = Get-WDACStatus; Write-Status "WDAC stav" $v (Get-StatusColor $v)

    $pFiles = @($WDACDefaultXml, $WDACCustomXml, $WDACMergedXml, $WDACCompiledBin) |
        Where-Object { Test-Path $_ }
    Write-Status "Pripravene politiky" "$($pFiles.Count) souboru" 'Cyan'

    Write-Host ""
    Write-Host "  -- POWERSHELL -----------------------------------------------------" -ForegroundColor Magenta
    $v = Get-PSLanguageModeStatus; Write-Status "PS Language Mode" $v (Get-StatusColor $v)

    Write-Host ""
    Write-Host "  -- OFFICE MAKRA ---------------------------------------------------" -ForegroundColor Magenta
    foreach ($key in $OfficeApps.Keys) {
        $st = Get-MacroStatus -AppKey $key
        $color = if ($st -match "podepsanych") { 'Green' }
                 elseif ($st -match "Vse zakazano") { 'Cyan' }
                 elseif ($st -match "Vse povoleno") { 'Red' }
                 elseif ($st -match "notifikaci") { 'Yellow' }
                 else { 'DarkGray' }
        Write-Status "  $($OfficeApps[$key].Name)" $st $color
    }

    Write-Host ""
    Write-Host "  -- TRUSTED LOCATIONS ---------------------------------------------" -ForegroundColor Magenta
    foreach ($appKey in @("Word", "Excel", "PowerPoint")) {
        $locs = Get-TrustedLocations -AppKey $appKey
        if ($locs.Count -gt 0) {
            foreach ($loc in $locs) {
                Write-Host "    $($OfficeApps[$appKey].Name): $($loc.Path)" -ForegroundColor Cyan
            }
        }
    }

    Write-Host ""
    Write-Host "  -- TRUSTED PUBLISHERS --------------------------------------------" -ForegroundColor Magenta
    $certs = Get-ChildItem Cert:\CurrentUser\TrustedPublisher -ErrorAction SilentlyContinue
    if ($certs -and $certs.Count -gt 0) {
        foreach ($c in $certs) {
            $subj = if ($c.Subject.Length -gt 55) { $c.Subject.Substring(0,52) + "..." } else { $c.Subject }
            Write-Host "    $subj" -ForegroundColor Cyan
        }
    } else {
        Write-Host "    Zadne." -ForegroundColor DarkGray
    }

    Write-Host ""
}

# ==============================================================================
#                      S U B - M E N U
# ==============================================================================

# -- 1) WDAC ------------------------------------------------------------------
function Show-Menu-WDAC {
    do {
        Show-Banner
        Write-SubHeader "WDAC - Application Whitelisting" @"
  WDAC (Windows Defender Application Control) umoznuje definovat
  ktere aplikace smi bezet na vasem PC. Vse ostatni je blokovano.

  ====== RYCHLY NAVOD (krok za krokem) ======
  A) S WDAC WIZARDEM (jednodussi, GUI):
     1. Volba 12 -> Stahnout WDAC Wizard
     2. Spustit Wizard ze Start menu
     3. V Wizardu: New Policy -> Base -> DefaultWindows -> Audit
     4. Pridat vase aplikace (Publisher/Path/Hash)
     5. Ulozit XML do: $($WDACPolicyDir)
     6. Volba 13 -> Importovat XML politiku
     7. Volba 7  -> Kompilovat a nasadit
     8. Restartovat PC, otestovat, pak volba 9 -> Enforce

  B) PRIMO V TOMTO SKRIPTU (bez Wizardu):
     1. Volba 1  -> Vytvorit vychozi politiku (Audit)
     2. Volby 3-6 -> Pridat vase aplikace
     3. Volba 7  -> Kompilovat a nasadit
     4. Restartovat PC, zkontrolovat Event Log (volba 11)
     5. Az vse funguje, volba 9 -> Enforce

  Slozka politik: $($WDACPolicyDir)
  Volba 14 -> Podrobny navod s vysvetlenim
"@

        $wdacSt = Get-WDACStatus
        $wColor = if ($wdacSt -match "Enforce") { 'Green' } elseif ($wdacSt -match "Audit") { 'Yellow' } else { 'Red' }
        Write-Host "  Aktualni stav:" -ForegroundColor DarkGray
        Write-Host "    WDAC: " -NoNewline -ForegroundColor DarkGray
        Write-Host $wdacSt -ForegroundColor $wColor
        Write-Host ""

        Write-Host "    Vytvoreni politiky:" -ForegroundColor Cyan
        Write-MenuItem "1"  "Vytvorit vychozi politiku (AUDIT mod) - DOPORUCENO" Green
        Write-MenuItem "2"  "Vytvorit vychozi politiku (ENFORCE mod) - POZOR!"
        Write-Host ""
        Write-Host "    Vlastni pravidla (whitelist):" -ForegroundColor Cyan
        Write-MenuItem "3"  "Pridat pravidlo podle CESTY (FilePath)"
        Write-MenuItem "4"  "Pridat pravidlo podle VYDAVATELE (Publisher)"
        Write-MenuItem "5"  "Pridat pravidlo podle HASHE souboru"
        Write-MenuItem "6"  "Proskenovad slozku a povolit vsechny nalezene app"
        Write-Host ""
        Write-Host "    Nasazeni:" -ForegroundColor Cyan
        Write-MenuItem "7"  "Kompilovat a nasadit politiku"
        Write-MenuItem "8"  "Prepnout na AUDIT mod"
        Write-MenuItem "9"  "Prepnout na ENFORCE mod"
        Write-MenuItem "10" "Odebrat nasazenou politiku"
        Write-Host ""
        Write-Host "    Nastroje a import:" -ForegroundColor Cyan
        Write-MenuItem "11" "Zobrazit detailni stav + Event Log + VBS/HVCI"
        Write-MenuItem "12" "Stahnout a nainstalovat WDAC Wizard (Microsoft GUI)" Cyan
        Write-MenuItem "13" "Importovat externi XML politiku (z Wizardu apod.)"
        Write-MenuItem "14" "Zobrazit podrobny navod (workflow)" DarkCyan
        Write-MenuItem "15" "Zablokovane/auditovane aplikace (Event IDs 3076/3077)" Yellow
        Write-MenuItem "16" "Pruvodce blokovani LOLBins (mshta/wscript/certutil)" DarkCyan
        Write-Host ""
        Write-MenuItem "0"  "<- Zpet do hlavniho menu" Yellow
        Write-Host ""

        $c = Read-MenuChoice
        switch ($c) {
            "1"  { New-WDACDefaultPolicy -AuditMode; Pause-Menu }
            "2"  {
                Write-Host ""
                Write-Host "  VAROVANI: ENFORCE mod okamzite blokuje neschvalene aplikace!" -ForegroundColor Red
                Write-Host "  Doporucujeme nejprve pouzit AUDIT mod." -ForegroundColor Yellow
                $confirm = Read-Host "  Opravdu pokracovat? (ano/ne)"
                if ($confirm -eq "ano") { New-WDACDefaultPolicy }
                else { Write-Host "  Zruseno." -ForegroundColor Yellow }
                Pause-Menu
            }
            "3"  { Add-WDACPathRule; Pause-Menu }
            "4"  { Add-WDACPublisherRule; Pause-Menu }
            "5"  { Add-WDACHashRule; Pause-Menu }
            "6"  { Add-WDACFolderScan; Pause-Menu }
            "7"  { Deploy-WDACPolicy; Pause-Menu }
            "8"  { Switch-WDACAuditEnforce -Audit; Pause-Menu }
            "9"  {
                Write-Host ""
                Write-Host "  VAROVANI: ENFORCE zacne blokovat neschvalene aplikace!" -ForegroundColor Red
                $confirm = Read-Host "  Opravdu pokracovat? (ano/ne)"
                if ($confirm -eq "ano") { Switch-WDACAuditEnforce }
                else { Write-Host "  Zruseno." -ForegroundColor Yellow }
                Pause-Menu
            }
            "10" { Remove-WDACPolicy; Pause-Menu }
            "11" { Show-WDACDetail; Pause-Menu }
            "12" { Install-WDACWizard; Pause-Menu }
            "13" { Import-WDACExternalPolicy; Pause-Menu }
            "14" { Show-WDACWorkflow; Pause-Menu }
            "15" { Show-WDACBlockedEvents; Pause-Menu }
            "16" { Add-LOLBinGuidance; Pause-Menu }
            "0"  { return }
            default { Write-Host "  Neplatna volba." -ForegroundColor Red; Start-Sleep 1 }
        }
    } while ($true)
}

# -- 2) Macro Whitelisting ----------------------------------------------------
function Show-Menu-Macros {
    do {
        Show-Banner
        Write-SubHeader "OFFICE MACRO WHITELISTING" @"
  Makra v Office souborech jsou casty vektor utoku (phishing, malware).
  Doporuceni: Zakazat vsechna makra KROM podepsanych duveryhodnymi
  vydavateli. Pro vlastni makra pouzijte Trusted Locations (duveryhodne
  slozky) nebo podepiste makra vlastnim certifikatem.
  Podepsana makra = bezpecnejsi. Trusted Locations = pohodlnejsi.
"@

        $macSt = Get-MacroStatusShort
        $mColor = if ($macSt -match "podepsane") { 'Green' } elseif ($macSt -match "POZOR") { 'Red' } else { 'Yellow' }
        Write-Host "  Aktualni stav:" -ForegroundColor DarkGray
        Write-Host "    Makra: " -NoNewline -ForegroundColor DarkGray
        Write-Host $macSt -ForegroundColor $mColor
        Write-Host ""

        Write-Host "    Uroven ochrany maker:" -ForegroundColor Cyan
        Write-MenuItem "1"  "Zobrazit stav vsech Office aplikaci"
        Write-MenuItem "2"  "Zakazat vse KROME PODEPSANYCH (doporuceno)" Green
        Write-MenuItem "3"  "Zakazat vse s notifikaci (vychozi Office)"
        Write-MenuItem "4"  "Zakazat UPLNE VSE (zadna makra)"
        Write-MenuItem "5"  "Povolit vse (NEBEZPECNE!)" Red
        Write-Host ""
        Write-Host "    Trusted Locations (duveryhodne slozky):" -ForegroundColor Cyan
        Write-MenuItem "6"  "Zobrazit vsechny Trusted Locations"
        Write-MenuItem "7"  "Pridat Trusted Location"
        Write-MenuItem "8"  "Odebrat Trusted Location"
        Write-Host ""
        Write-Host "    Trusted Publishers (duveryhodne vydavatele):" -ForegroundColor Cyan
        Write-MenuItem "9"  "Zobrazit Trusted Publishers"
        Write-MenuItem "10" "Pridat Trusted Publisher (ze souboru/certifikatu)"
        Write-Host ""
        Write-Host "    Certifikaty pro podpis:" -ForegroundColor Cyan
        Write-MenuItem "11" "Vytvorit self-signed certifikat pro podpis maker/skriptu" Green
        Write-Host ""
        Write-MenuItem "0"  "<- Zpet do hlavniho menu" Yellow
        Write-Host ""

        $c = Read-MenuChoice
        switch ($c) {
            "1"  { Show-MacroStatusAll; Pause-Menu }
            "2"  { Set-MacroPolicy -Level 3; Pause-Menu }
            "3"  { Set-MacroPolicy -Level 2; Pause-Menu }
            "4"  { Set-MacroPolicy -Level 4; Pause-Menu }
            "5"  {
                Write-Host ""
                Write-Host "  VAROVANI: Povoleni vsech maker je NEBEZPECNE!" -ForegroundColor Red
                $confirm = Read-Host "  Opravdu pokracovat? (ano/ne)"
                if ($confirm -eq "ano") { Set-MacroPolicy -Level 1 }
                else { Write-Host "  Zruseno." -ForegroundColor Yellow }
                Pause-Menu
            }
            "6"  { Show-TrustedLocations; Pause-Menu }
            "7"  { Add-TrustedLocation; Pause-Menu }
            "8"  { Remove-TrustedLocation; Pause-Menu }
            "9"  { Show-TrustedPublishers; Pause-Menu }
            "10" { Add-TrustedPublisher; Pause-Menu }
            "11" { New-CodeSigningCertificate; Pause-Menu }
            "0"  { return }
            default { Write-Host "  Neplatna volba." -ForegroundColor Red; Start-Sleep 1 }
        }
    } while ($true)
}

# -- 3) PowerShell Hardening --------------------------------------------------
function Show-Menu-PSHardening {
    do {
        Show-Banner
        Write-SubHeader "POWERSHELL HARDENING" @"
  PowerShell Constrained Language Mode je bezpecnostni funkce, ktera
  omezuje potencialne nebezpecne operace v PowerShellu. Blokuje pristup
  k .NET, COM objektum a dalsim pokrocilym funkcim, ktere casto
  zneuziva malware. Je to idealni doplnek k WDAC.
  I kdyz WDAC blokuje neschvalene skripty, Constrained Mode chrani
  pred utoky primo v interaktivni konzoli.
"@

        $psMode = Get-PSLanguageModeStatus
        $pColor = if ($psMode -match "Constrained") { 'Green' } else { 'Red' }
        Write-Host "  Aktualni stav:" -ForegroundColor DarkGray
        Write-Host "    PS Language Mode: " -NoNewline -ForegroundColor DarkGray
        Write-Host $psMode -ForegroundColor $pColor
        Write-Host ""

        Write-MenuItem "1"  "Zapnout Constrained Language Mode (trvale)" Green
        Write-MenuItem "2"  "Vypnout Constrained Language Mode (trvale)" Red
        Write-Host ""
        Write-MenuItem "0"  "<- Zpet do hlavniho menu" Yellow
        Write-Host ""

        $c = Read-MenuChoice
        switch ($c) {
            "1"  { Set-PSLanguageMode -Constrained $true; Pause-Menu }
            "2"  { Set-PSLanguageMode -Constrained $false; Pause-Menu }
            "0"  { return }
            default { Write-Host "  Neplatna volba." -ForegroundColor Red; Start-Sleep 1 }
        }
    } while ($true)
}

# ==============================================================================
#                       H L A V N I   M E N U
# ==============================================================================

function Start-AppLockerMode {
do {
    Show-Banner
    Write-Host ""
    Write-Host "  +------------------------------------------------------------+" -ForegroundColor DarkGray
    Write-Host "  |                      HLAVNI MENU                           |" -ForegroundColor Cyan
    Write-Host "  +------------------------------------------------------------+" -ForegroundColor DarkGray
    Write-Host ""

    # Quick-status
    $wdacQ  = Get-WDACStatusShort
    $macroQ = Get-MacroStatusShort
    $psQ    = Get-PSLanguageModeStatus

    $wdacC  = if ($wdacQ -match "Enforce") { 'Green' } elseif ($wdacQ -match "Audit") { 'Yellow' } else { 'Red' }
    $macroC = if ($macroQ -match "podepsane") { 'Green' } elseif ($macroQ -match "POZOR") { 'Red' } else { 'Yellow' }
    $psC    = if ($psQ -match "Constrained") { 'Green' } else { 'Red' }

    Write-Host "    1)  WDAC (Application Whitelisting)" -ForegroundColor White -NoNewline
    Write-Host "  [" -NoNewline -ForegroundColor DarkGray
    Write-Host "$wdacQ" -NoNewline -ForegroundColor $wdacC
    Write-Host "]" -ForegroundColor DarkGray
    Write-Host "        Povolte jen duveryhodne aplikace." -ForegroundColor DarkGray
    Write-Host ""

    Write-Host "    2)  Office Macro Whitelisting" -ForegroundColor White -NoNewline
    Write-Host "       [" -NoNewline -ForegroundColor DarkGray
    Write-Host "$macroQ" -NoNewline -ForegroundColor $macroC
    Write-Host "]" -ForegroundColor DarkGray
    Write-Host "        Kontrola maker, trusted locations, publishers." -ForegroundColor DarkGray
    Write-Host ""

    Write-Host "    3)  PowerShell Hardening" -ForegroundColor White -NoNewline
    Write-Host "          [" -NoNewline -ForegroundColor DarkGray
    Write-Host "$psQ" -NoNewline -ForegroundColor $psC
    Write-Host "]" -ForegroundColor DarkGray
    Write-Host "        Omezeni nebezpecnych PS prikazu." -ForegroundColor DarkGray
    Write-Host ""

    Write-Host "   99)  Kompletni prehled stavu" -ForegroundColor Cyan
    Write-Host "    4)  Rychly navod - jak zacit" -ForegroundColor DarkCyan
    Write-Host ""
    Write-Host "    0)  Konec" -ForegroundColor Yellow
    Write-Host ""

    $mainChoice = Read-MenuChoice

    switch ($mainChoice) {
        "1"  { Show-Menu-WDAC }
        "2"  { Show-Menu-Macros }
        "3"  { Show-Menu-PSHardening }
        "4"  { Show-QuickStartGuide; Pause-Menu }
        "99" { Show-FullStatus; Pause-Menu }
        "0"  {
            Write-Host ""
            Write-Host "  Ukoncuji. Zustan v bezpeci!" -ForegroundColor Cyan
            Write-Host ""
        }
        default {
            Write-Host "  Neplatna volba, zkuste znovu." -ForegroundColor Red
            Start-Sleep -Seconds 1
        }
    }
} while ($mainChoice -ne "0")
}

# ==============================================================================
#   H L A V N I   V Y B E R   M O D U L U   ( P C   S E C U R I T Y   S U I T E )
# ==============================================================================
do {
    Clear-Host
    Write-Host ""
    Write-Host "  +============================================================+" -ForegroundColor Cyan
    Write-Host "  |         PC SECURITY SUITE - Interaktivni nastroj           |" -ForegroundColor Cyan
    Write-Host "  |                   vytvoril: Mischa Princ                   |" -ForegroundColor DarkCyan
    Write-Host "  +============================================================+" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Vyberte modul ktery chcete pouzit:" -ForegroundColor White
    Write-Host ""
    Write-Host "    1)  Zabezpeceni (Hardening)" -ForegroundColor Green
    Write-Host "        ASR, Defender, SmartScreen, Sysmon, DNS, pokrocile zabezpeceni," -ForegroundColor DarkGray
    Write-Host "        Windows Update, Winget, BitLocker, WDigest, LSA, NTLMv2, UAC..." -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "    2)  Monitoring a Audit" -ForegroundColor Yellow
    Write-Host "        Security events, persistence, procesy, sit, DNS cache," -ForegroundColor DarkGray
    Write-Host "        Sysmon parent-child detekce, export dat, detekce hrozeb..." -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "    3)  Application Whitelisting (WDAC + Makra)" -ForegroundColor Cyan
    Write-Host "        WDAC politiky (audit/enforce), vlastni pravidla, Office makra," -ForegroundColor DarkGray
    Write-Host "        Trusted Locations/Publishers, PS Constrained Mode..." -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "    x)  QuickNav  (x1{pod}{vol} / x2{vol} / x3{pod}{vol})" -ForegroundColor DarkGray
    Write-Host "        Priklad: x1411 = Modul1 podmenu4 volba11  |  x193 = Modul1 pod9 volba3" -ForegroundColor DarkGray
    Write-Host "                 x26   = Modul2 volba6            |  x312 = Modul3 WDAC volba2" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "    0)  Konec" -ForegroundColor Yellow
    Write-Host ""

    $suiteChoice = Read-Host "  Vyberte modul (nebo x-kod)"

    # --- QuickNav parser: x{modul}{podmenu}{volba} ---
    if ($suiteChoice -match '^[xX]([123])(.+)$') {
        $qMod  = $Matches[1]
        $qRest = $Matches[2]
        $script:QNPath = @()
        switch ($qMod) {
            "2" {
                # Modul 2 nema podmenu: x2{volba}
                $script:QNPath = @($qRest)
            }
            default {
                # Modul 1 a 3: x{M}{podmenu:1}{volba:rest}
                if ($qRest.Length -ge 2) {
                    $script:QNPath = @([string]$qRest[0], $qRest.Substring(1))
                } else {
                    $script:QNPath = @($qRest)
                }
            }
        }
        $suiteChoice = $qMod
    }

    switch ($suiteChoice) {
        "1" {
            $script:ActiveMode = "SECURE"
            Start-SecureMode
            $script:ActiveMode = ""
        }
        "2" {
            $script:ActiveMode = "MONITOR"
            Start-MonitorMode
            $script:ActiveMode = ""
        }
        "3" {
            $script:ActiveMode = "APPLOCKER"
            Start-AppLockerMode
            $script:ActiveMode = ""
        }
        "0" {
            Write-Host ""
            Write-Host "  Ukoncuji PC Security Suite. Zustan v bezpeci!" -ForegroundColor Cyan
            Write-Host ""
        }
        default {
            Write-Host "  Neplatna volba, zkuste znovu." -ForegroundColor Red
            Start-Sleep -Seconds 1
        }
    }
} while ($suiteChoice -ne "0")
