<#
.SYNOPSIS
    Interaktivni skript pro monitoring a audit Windows 10/11.
.DESCRIPTION
    Nabizi hierarchicke menu s moznosti:
      - Vypis bezpecnostnich udalosti (chybne/uspesne loginy)
      - Monitoring bezicich procesu a jejich podpisu
      - Vypis otevrenych portu a programu
      - Monitoring PowerShell, CMD, WMI procesu
      - Vypis naplanovanych uloh, sluzeb, uzivatelu
.AUTHOR
    Hack3r.cz
.NOTES
    Spoustejte jako Administrator.
#>

# ======================================================================
#                   K O N T R O L A   A D M I N A
# ======================================================================
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

function Show-MainMenu {
    Clear-Host
    Write-Host "  +============================================================+" -ForegroundColor Cyan
    Write-Host "  |       MONITORING & AUDIT MENU - Interaktivni nastroj        |" -ForegroundColor Cyan
    Write-Host "  |                   vytvoril: Mischa Princ                    |" -ForegroundColor DarkCyan
    Write-Host "  +============================================================+" -ForegroundColor Cyan
    Write-Host "1. Bezpecnostni udalosti (chybne loginy, apod.)"
    Write-Host "2. Monitorovani spustenych procesu"
    Write-Host "3. Otevrene porty"
    Write-Host "4. Monitoring PowerShell, CMD, WMI, atd."
    Write-Host "5. Dalsi monitoring (navrhy)"
    Write-Host "0. Konec"
    $choice = Read-Host "\nZadejte volbu"
    switch ($choice) {
        '1' { Show-SecurityEventsMenu }
        '2' { Show-ProcessMenu }
        '3' { Show-PortsMenu }
        '4' { Show-ScriptEnginesMenu }
        '5' { Show-OtherMonitoringMenu }
        '0' { return }
        default { Show-MainMenu }
    }
}

function Show-SecurityEventsMenu {
    Clear-Host
    Write-Host "--- Bezpecnostni udalosti ---" -ForegroundColor Yellow
    Write-Host "1. Chybne prihlaseni (Logon Failure)"
    Write-Host "2. Uspesne prihlaseni"
    Write-Host "3. Zpet"
    $choice = Read-Host "\nZadejte volbu"
    switch ($choice) {
        '1' { Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625} -MaxEvents 20 | Format-Table TimeCreated, Message -AutoSize; Pause }
        '2' { Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624} -MaxEvents 20 | Format-Table TimeCreated, Message -AutoSize; Pause }
        '3' { Show-MainMenu }
        default { Show-SecurityEventsMenu }
    }
    Show-SecurityEventsMenu
}

function Show-ProcessMenu {
    Clear-Host
    Write-Host "--- Spustene procesy a podpisy ---" -ForegroundColor Yellow
    $procs = Get-Process | Sort-Object ProcessName
    foreach ($proc in $procs) {
        $path = $null
        try { $path = $proc.Path } catch {}
        if ($path) {
            $sig = Get-AuthenticodeSignature -FilePath $path
            $signer = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { 'Nepodepsano' }
        } else {
            $signer = 'N/A'
        }
        Write-Host ("{0,-30} {1,-8} {2}" -f $proc.ProcessName, $proc.Id, $signer)
    }
    Pause
    Show-MainMenu
}

function Show-PortsMenu {
    Clear-Host
    Write-Host "--- Otevrene porty a programy ---" -ForegroundColor Yellow
    $conns = Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort,OwningProcess
    foreach ($conn in $conns) {
        $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
        $pname = if ($proc) { $proc.ProcessName } else { 'N/A' }
        Write-Host ("{0,-15} {1,-6} {2}" -f $conn.LocalAddress, $conn.LocalPort, $pname)
    }
    Pause
    Show-MainMenu
}

function Show-ScriptEnginesMenu {
    Clear-Host
    Write-Host "--- Monitoring PowerShell, CMD, WMI, ... ---" -ForegroundColor Yellow
    Write-Host "1. Vypis spustenych PowerShell procesu"
    Write-Host "2. Vypis spustenych CMD procesu"
    Write-Host "3. Vypis spustenych WMI procesu"
    Write-Host "4. Zpet"
    $choice = Read-Host "\nZadejte volbu"
    switch ($choice) {
        '1' { Get-Process -Name powershell, pwsh | Format-Table Id, ProcessName, StartTime, Path -AutoSize; Pause }
        '2' { Get-Process -Name cmd | Format-Table Id, ProcessName, StartTime, Path -AutoSize; Pause }
        '3' { Get-Process -Name wmiprvse | Format-Table Id, ProcessName, StartTime, Path -AutoSize; Pause }
        '4' { Show-MainMenu }
        default { Show-ScriptEnginesMenu }
    }
    Show-ScriptEnginesMenu
}

function Show-OtherMonitoringMenu {
    Clear-Host
    Write-Host "--- Dalsi monitoring ---" -ForegroundColor Yellow
    Write-Host "1. Vypis naplanovanych uloh (Scheduled Tasks)"
    Write-Host "2. Vypis sluzeb (Services)"
    Write-Host "3. Vypis uzivatelu v systemu"
    Write-Host "4. Zpet"
    $choice = Read-Host "\nZadejte volbu"
    switch ($choice) {
        '1' { Get-ScheduledTask | Format-Table TaskName, State, Author -AutoSize; Pause }
        '2' { Get-Service | Format-Table Status, Name, DisplayName -AutoSize; Pause }
        '3' { Get-LocalUser | Format-Table Name, Enabled, LastLogon -AutoSize; Pause }
        '4' { Show-MainMenu }
        default { Show-OtherMonitoringMenu }
    }
    Show-OtherMonitoringMenu
}

Show-MainMenu
