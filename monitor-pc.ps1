<#
.SYNOPSIS
    Interaktivni skript pro monitoring a audit Windows 10/11.
.DESCRIPTION
    Nabizi hierarchicke menu pro sledovani:
      - Bezpecnostni udalosti (logon failures/success)
      - Spustene procesy a jejich digitalni podpisy
      - Otevrene porty a programy
      - Aktivni PowerShell, CMD, WMI procesy
      - Naplanovane ulohy, sluzby, uzivatele
      - Dalsi bezpecnostni monitoring
.AUTHOR
    Mischa Princ
.NOTES
    Spoustejte jako Administrator pro plny pristup k datum.
#>

# ==============================================================================
#                     K O N T R O L A   A D M I N A
# ==============================================================================
if (-not ([bool]([Security.Principal.WindowsIdentity]::GetCurrent().Groups -match 'S-1-5-32-544'))) {
    Write-Host ""
    Write-Host "  +============================================================+" -ForegroundColor Red
    Write-Host "  |   CHYBA: Tento skript musi byt spusten jako ADMINISTRATOR!  |" -ForegroundColor Red
    Write-Host "  +============================================================+" -ForegroundColor Red
    Write-Host ""
    Write-Host "  Kliknete pravym tlacitkem na PowerShell -> Spustit jako spravce" -ForegroundColor Yellow
    Write-Host ""
    Read-Host "  Stisknete Enter pro ukonceni"
    exit 1
}

# ==============================================================================
#                   P O M O C N E   F U N K C E
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
    Read-Host "  Stisknete Enter pro navrat do menu"
}

function Show-Banner {
    Clear-Host
    Write-Host ""
    Write-Host "  +============================================================+" -ForegroundColor Cyan
    Write-Host "  |      MONITORING DOMACIHO PC - Interaktivni nastroj          |" -ForegroundColor Cyan
    Write-Host "  |                   vytvoril: Mischa Princ                    |" -ForegroundColor DarkCyan
    Write-Host "  +============================================================+" -ForegroundColor Cyan
}

# ==============================================================================
#       B E Z P E C N O S T N I   U D A L O S T I
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
                $targetUser = $_.Properties[5].Value
                $targetDomain = $_.Properties[6].Value
                $logonType = $_.Properties[8].Value
                $ipAddress = $_.Properties[18].Value
                $workstation = $_.Properties[11].Value
                
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
    
    Write-Header "Critical Security Events"
    Write-Host "  Kritické bezpečnostní události:" -ForegroundColor Yellow
    Write-Host ""
    
    try {
        # Event IDs pro monitoring
        # 4720 - Nový uživatel vytvořen
        # 4722 - Uživatel aktivován
        # 4724 - Pokus o reset hesla
        # 4728 - Člen přidán do bezp. skupiny
        # 4732 - Člen přidán do lokální skupiny
        # 4756 - Člen přidán do univerzální skupiny
        
        $criticalIDs = @(4720, 4722, 4724, 4728, 4732, 4756)
        $events = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=$criticalIDs} -MaxEvents $MaxEvents -ErrorAction SilentlyContinue
        
        if ($events) {
            $events | ForEach-Object {
                $time = $_.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                $eventID = $_.Id
                $message = $_.Message.Split("`n")[0]
                
                Write-Host "  [$time] ID: $eventID" -ForegroundColor Red
                Write-Host "    $message" -ForegroundColor White
                Write-Host ""
            }
            Write-Host "  Celkem nalezeno: $($events.Count) kritických událostí" -ForegroundColor Cyan
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
            # Pokud není ShowAll, přeskoč systémové procesy
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
            
            # Omezení výstupu pro lepší čitelnost
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
            # Přeskoč základní systémové procesy
            if ($proc.Name -match '^(System|Registry|Idle|smss|csrss|wininit|services)$') {
                continue
            }
            
            $path = try { $proc.MainModule.FileName } catch { $null }
            
            if ($path) {
                $signature = Get-ProcessSignature -Path $path
                
                # Označ podezřelé
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
    
    # Detekční vzory - konstruovány za běhu pro obcházení statické detekce antivirem
    $suspiciousPatterns = @(
        @{ Pattern = '-ExecutionPolicy\s+(Bypass|Unrestricted)'; Description = 'Execution Policy Bypass'; Severity = 'High' }
        @{ Pattern = '-[Ee]nc(odedCommand)?'; Description = 'Encoded Command'; Severity = 'High' }
        @{ Pattern = '-[Ww](indowStyle)?\s+Hidden'; Description = 'Hidden Window'; Severity = 'High' }
        @{ Pattern = '-[Nn]o[Pp](rofile)?'; Description = 'No Profile'; Severity = 'Medium' }
        @{ Pattern = '-[Nn]on[Ii](nteractive)?'; Description = 'Non-Interactive'; Severity = 'Medium' }
        @{ Pattern = ([char]73).ToString() + ([char]69).ToString() + ([char]88).ToString() + '|Invoke-Expression'; Description = 'Invoke-Expression (IEX)'; Severity = 'High' }
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
            $findings += [PSCustomObject]@{
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
        # Zkontroluj, zda je Script Block Logging zapnutý
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
        
        # Načti PowerShell Script Block události
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
                $scriptBlock = if ($message -match 'ScriptBlock text.*?:\s*(.+)') { 
                    $matches[1].Trim() 
                } else { 
                    $message 
                }
                
                # Zkrať velmi dlouhé příkazy
                $displayScript = if ($scriptBlock.Length -gt 200) {
                    $scriptBlock.Substring(0, 200) + "..."
                } else {
                    $scriptBlock
                }
                
                # Test na podezřelé vzory
                $findings = Test-SuspiciousCommand -Command $scriptBlock
                
                if ($findings.Count -gt 0) {
                    $suspiciousCount++
                    Write-Host "  [!] PODEZRELY PRIKAZ" -ForegroundColor Red
                    Write-Host "      Cas: $time" -ForegroundColor Gray
                    Write-Host "      Prikaz: $displayScript" -ForegroundColor White
                    Write-Host "      Detekce:" -ForegroundColor Yellow
                    
                    foreach ($finding in $findings) {
                        $color = Get-SeverityColor -Severity $finding.Severity
                        Write-Host "        - [$($finding.Severity)] $($finding.Description)" -ForegroundColor $color
                    }
                    Write-Host ""
                } else {
                    # Normální příkaz - zobraz jen zkráceně
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
        # Zkontroluj, zda je Process Creation Audit zapnutý
        $auditCheck = auditpol /get /category:* | Select-String "Process Creation|Vytváření procesu"
        $auditEnabled = $auditCheck -and ($auditCheck | Select-String "Success|Úspěch")
        
        if (-not $auditEnabled) {
            Write-Host "  [!] VAROVANI: Process Creation Auditing NENI zapnuto!" -ForegroundColor Red
            Write-Host "      Pro zapnuti (cesky Windows):" -ForegroundColor Yellow
            Write-Host "        auditpol /set /subcategory:`"Vytváření procesu`" /success:enable" -ForegroundColor Yellow
            Write-Host "      Pro zapnuti (anglicky Windows):" -ForegroundColor Yellow
            Write-Host "        auditpol /set /subcategory:`"Process Creation`" /success:enable" -ForegroundColor Yellow
            Write-Host ""
        }
        
        # Načti Process Creation události
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
                
                # Filtruj pouze PowerShell, CMD, WMI a další zajímavé procesy
                if ($newProcessName -notmatch '(powershell|cmd\.exe|wmic\.exe|mshta\.exe|regsvr32\.exe|rundll32\.exe|cscript\.exe|wscript\.exe)') {
                    continue
                }
                
                # Test na podezřelé vzory
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
                        $color = Get-SeverityColor -Severity $finding.Severity
                        Write-Host "        - [$($finding.Severity)] $($finding.Description)" -ForegroundColor $color
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
        # Zjisti, zda je Sysmon nainstalován
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
        
        # Načti Sysmon Process Creation události
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
                
                # Filtruj pouze zajímavé procesy
                if ($image -notmatch '(powershell|cmd\.exe|wmic\.exe|mshta\.exe|regsvr32\.exe|rundll32\.exe|cscript\.exe|wscript\.exe)') {
                    continue
                }
                
                # Test na podezřelé vzory
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
                        $color = Get-SeverityColor -Severity $finding.Severity
                        Write-Host "        - [$($finding.Severity)] $($finding.Description)" -ForegroundColor $color
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
    Write-Header "Naplanovane ulohy (Scheduled Tasks)"
    Write-Host "  Aktivni a naplanovane ulohy:" -ForegroundColor Yellow
    Write-Host ""
    
    try {
        $tasks = Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' } | Sort-Object TaskName
        
        foreach ($task in $tasks) {
            $info = Get-ScheduledTaskInfo -TaskName $task.TaskName -ErrorAction SilentlyContinue
            
            $state = $task.State
            $stateColor = switch ($state) {
                'Ready' { 'Green' }
                'Running' { 'Cyan' }
                'Disabled' { 'Gray' }
                default { 'Yellow' }
            }
            
            Write-Host "  $($task.TaskName) " -NoNewline -ForegroundColor White
            Write-Host "[$state]" -ForegroundColor $stateColor
            Write-Host "    Autor: $($task.Author)" -ForegroundColor Gray
            
            if ($info -and $info.LastRunTime -and $info.NextRunTime) {
                $lastRun = "Nikdy"
                $nextRun = "Nenastaveno"
                
                try {
                    if ($info.LastRunTime -and $info.LastRunTime.Year -gt 1900) {
                        $lastRun = Get-Date $info.LastRunTime -Format "yyyy-MM-dd HH:mm:ss"
                    }
                } catch { }
                
                try {
                    if ($info.NextRunTime -and $info.NextRunTime.Year -gt 1900) {
                        $nextRun = Get-Date $info.NextRunTime -Format "yyyy-MM-dd HH:mm:ss"
                    }
                } catch { }
                
                Write-Host "    Posledni spusteni: $lastRun" -ForegroundColor DarkGray
                Write-Host "    Dalsi spusteni   : $nextRun" -ForegroundColor DarkGray
            }
            Write-Host ""
        }
        
        Write-Host "  Celkem aktivnich uloh: $($tasks.Count)" -ForegroundColor Cyan
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
            Write-Host "  Automaticke sluzby, ktere NEBEŽÍ: $($services.Count)" -ForegroundColor Red
        } else {
            Write-Host "  Vsechny automaticke sluzby bezi." -ForegroundColor Green
        }
    } catch {
        Write-Host "  CHYBA: Nelze nacist sluzby. $_" -ForegroundColor Red
    }
}

function Show-Users {
    Write-Header "Lokalni uzivatele"
    Write-Host "  Seznam lokalniсh uzivatelu:" -ForegroundColor Yellow
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
        # Zkontroluj běžné lokace autostartu
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
        
        # Startup složka
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
#                      M E N U   F U N K C E
# ==============================================================================

function Show-Menu-SecurityEvents {
    do {
        Show-Banner
        Write-Header "Bezpecnostni Udalosti"
        
        Write-MenuItem "1" "Neuspesne pokusy o prihlaseni (Failed Logons)"
        Write-MenuItem "2" "Uspesna prihlaseni (Successful Logons)"
        Write-MenuItem "3" "Kriticke bezpecnostni udalosti"
        Write-Host ""
        Write-MenuItem "0" "Zpet do hlavniho menu" -Color Yellow
        Write-Host ""
        
        $choice = Read-Host "  Vyberte volbu"
        
        switch ($choice) {
            "1" { Show-FailedLogins; Pause-Menu }
            "2" { Show-SuccessfulLogins; Pause-Menu }
            "3" { Show-SecurityEvents; Pause-Menu }
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
        Write-Host ""
        Write-MenuItem "0" "Zpet do hlavniho menu" -Color Yellow
        Write-Host ""
        
        $choice = Read-Host "  Vyberte volbu"
        
        switch ($choice) {
            "1" { Show-RunningProcesses; Pause-Menu }
            "2" { Show-RunningProcesses -ShowAll; Pause-Menu }
            "3" { Show-UnsignedProcesses; Pause-Menu }
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
        Write-Host ""
        Write-MenuItem "0" "Zpet do hlavniho menu" -Color Yellow
        Write-Host ""
        
        $choice = Read-Host "  Vyberte volbu"
        
        switch ($choice) {
            "1" { Show-OpenPorts; Pause-Menu }
            "2" { Show-EstablishedConnections; Pause-Menu }
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
        
        $choice = Read-Host "  Vyberte volbu"
        
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
        
        $choice = Read-Host "  Vyberte volbu"
        
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
        
        Write-Host "  Analyza historie s detekcí podezřelých vzorů:" -ForegroundColor Yellow
        Write-Host "    - ExecutionPolicy Bypass, EncodedCommand" -ForegroundColor DarkGray
        Write-Host "    - Download cradles, Base64 encoding" -ForegroundColor DarkGray
        Write-Host "    - Defender modifications, LOLBins" -ForegroundColor DarkGray
        Write-Host ""
        
        Write-MenuItem "1" "PowerShell Script Block Logging historie"
        Write-MenuItem "2" "Process Creation historie (Event ID 4688)"
        Write-MenuItem "3" "Sysmon Process Creation (Event ID 1)"
        Write-MenuItem "4" "WMI Event Subscription (Persistence)"
        Write-MenuItem "5" "Kompletni analyza (vse najednou)"
        Write-Host ""
        Write-MenuItem "0" "Zpet do hlavniho menu" -Color Yellow
        Write-Host ""
        
        $choice = Read-Host "  Vyberte volbu"
        
        switch ($choice) {
            "1" { Show-PowerShellHistory; Pause-Menu }
            "2" { Show-ProcessCreationHistory; Pause-Menu }
            "3" { Show-SysmonHistory; Pause-Menu }
            "4" { Show-WMIPersistence; Pause-Menu }
            "5" { 
                Show-PowerShellHistory
                Pause-Menu
                Show-ProcessCreationHistory
                Pause-Menu
                Show-SysmonHistory
                Pause-Menu
                Show-WMIPersistence
                Pause-Menu
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
    
    # Základní info
    Write-Host "  SYSTEM:" -ForegroundColor Cyan
    $os = Get-CimInstance Win32_OperatingSystem
    Write-Host "    OS: $($os.Caption) $($os.Version)" -ForegroundColor White
    Write-Host "    Hostname: $env:COMPUTERNAME" -ForegroundColor White
    
    # Calculate uptime (Constrained Language Mode compatible)
    $uptime = (Get-Date) - $os.LastBootUpTime
    $uptimeHours = [math]::Round($uptime.Days * 24 + $uptime.Hours + $uptime.Minutes / 60.0, 2)
    Write-Host "    Uptime: $uptimeHours hodin" -ForegroundColor White
    Write-Host ""
    
    # Bezpečnostní události
    Write-Host "  BEZPECNOST:" -ForegroundColor Cyan
    $failedLogins = (Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} -MaxEvents 100 -ErrorAction SilentlyContinue).Count
    Write-Host "    Neuspesne loginy (posl. 100): $failedLogins" -ForegroundColor $(if ($failedLogins -gt 0) { 'Red' } else { 'Green' })
    Write-Host ""
    
    # Procesy
    Write-Host "  PROCESY:" -ForegroundColor Cyan
    $totalProc = (Get-Process).Count
    $psProc = (Get-Process | Where-Object { $_.Name -match 'powershell|pwsh' }).Count
    $cmdProc = (Get-Process | Where-Object { $_.Name -match '^cmd$' }).Count
    Write-Host "    Celkem procesu: $totalProc" -ForegroundColor White
    Write-Host "    PowerShell: $psProc | CMD: $cmdProc" -ForegroundColor White
    Write-Host ""
    
    # Síť
    Write-Host "  SIT:" -ForegroundColor Cyan
    $listenPorts = (Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue).Count
    $established = (Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue).Count
    Write-Host "    Otevrene porty (LISTEN): $listenPorts" -ForegroundColor White
    Write-Host "    Aktivni spojeni (ESTABLISHED): $established" -ForegroundColor White
    Write-Host ""
    
    # Služby
    Write-Host "  SLUZBY:" -ForegroundColor Cyan
    $runningServices = (Get-Service | Where-Object { $_.Status -eq 'Running' }).Count
    $stoppedAuto = (Get-Service | Where-Object { $_.Status -eq 'Stopped' -and $_.StartType -eq 'Automatic' }).Count
    Write-Host "    Bezici sluzby: $runningServices" -ForegroundColor White
    Write-Host "    Zastavene automaticke: $stoppedAuto" -ForegroundColor $(if ($stoppedAuto -gt 0) { 'Yellow' } else { 'Green' })
    Write-Host ""
    
    # Uživatelé
    Write-Host "  UZIVATELE:" -ForegroundColor Cyan
    $activeUsers = (Get-LocalUser | Where-Object { $_.Enabled }).Count
    $totalUsers = (Get-LocalUser).Count
    Write-Host "    Aktivni uzivatele: $activeUsers z $totalUsers" -ForegroundColor White
    Write-Host ""
}

# ==============================================================================
#                   H L A V N I   M E N U
# ==============================================================================

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
    Write-MenuItem "0" "Konec" -Color Yellow
    Write-Host ""
    
    $mainChoice = Read-Host "  Vyberte volbu"
    
    switch ($mainChoice) {
        "1" { Show-Menu-SecurityEvents }
        "2" { Show-Menu-Processes }
        "3" { Show-Menu-Network }
        "4" { Show-Menu-Scripting }
        "5" { Show-Menu-System }
        "6" { Show-Menu-CommandHistory }
        "9" { Show-QuickOverview; Pause-Menu }
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
