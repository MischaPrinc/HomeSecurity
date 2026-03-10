# Nástroje pro Zabezpečení a Hardening Windows

Tento repozitář obsahuje sadu interaktivních PowerShell skriptů pro pokročilé zabezpečení a hardening pracovních stanic s operačním systémem Windows 10 a 11. Skripty jsou navrženy tak, aby byly snadno použitelné i pro uživatele bez hlubokých znalostí PowerShellu, a to díky přehlednému menu.

**Autor:** Mischa Princ

> **Důležité:** Všechny skripty musí být spuštěny s administrátorskými oprávněními.

---

## Obsah

1.  [**`secure-pc.ps1`** - Interaktivní Hardening](#secure-pcps1---interaktivní-hardening)
2.  [**`applocker-pc.ps1`** - Application & Macro Whitelisting](#applocker-pcps1---application--macro-whitelisting)
3.  [**`monitor-pc.ps1`** - Monitoring & Audit](#monitor-pcps1---monitoring--audit)

---

## `secure-pc.ps1` - Interaktivní Hardening

Tento skript poskytuje komplexní sadu nástrojů pro posílení bezpečnosti systému Windows prostřednictvím interaktivního menu. Umožňuje snadno konfigurovat klíčové bezpečnostní prvky.

### Funkce

-   **Windows Defender & Attack Surface Reduction (ASR):**
    -   Detailní správa všech ASR pravidel (zapnutí/vypnutí/audit).
    -   Aktivace ochrany proti potenciálně nechtěným aplikacím (PUA).
    -   Zapnutí a konfigurace Controlled Folder Access (CFA) pro ochranu před ransomwarem.
    -   Správa Tamper Protection, která brání neoprávněným změnám v nastavení Defenderu.
    -   Aktivace Real-Time a Cloud-based ochrany.

-   **SmartScreen:**
    -   Zapnutí/vypnutí SmartScreen filtru pro Windows (Explorer) i pro prohlížeč Microsoft Edge.

-   **Sítě a Protokoly:**
    -   Správa stavu Windows Firewall.
    -   Zakázání/povolení RDP (Vzdálená plocha).
    -   Deaktivace zastaralého a nebezpečného protokolu SMBv1.
    -   Deaktivace LLMNR pro ochranu před poisoning útoky.

-   **Systém a Logování:**
    -   Zakázání funkce AutoRun/AutoPlay.
    -   Aktivace PowerShell Script Block Logging pro lepší audit a detekci hrozeb.

-   **Bezpečné DNS:**
    -   Snadné nastavení bezpečných DNS serverů od Cloudflare (s filtrováním malware a/nebo obsahu pro dospělé).

-   **Sysmon:**
    -   Automatická instalace a konfigurace Sysmonu (System Monitor) z Sysinternals Suite.
    -   Využívá pokročilou a komunitou prověřenou konfiguraci od Olafa Hartonga (`sysmon-modular`).

-   **Aktualizace a Software:**
    -   **Windows Update:**
        -   Zobrazení přehledu nainstalovaných Windows aktualizací.
        -   Detekce chybějících bezpečnostních aktualizací.
        -   Možnost spustit instalaci Windows aktualizací přímo ze skriptu.
    -   **Správa software (Winget):**
        -   Zobrazení seznamu veškerého nainstalovaného software včetně verzí.
        -   Kontrola dostupných aktualizací pro nainstalované aplikace.
        -   Automatická aktualizace všech aplikací pomocí Windows Package Manager (Winget).
        -   Fallback na registry, pokud Winget není dostupný.
    -   **Quick status:**
        -   Rychlý přehled dostupných aktualizací software přímo v hlavním menu.

-   **Další doporučená nastavení:**
    -   Zakázání ukládání LM hashů pro lepší zabezpečení hesel.
    -   Zabezpečení proti zneužití Sticky Keys.
    -   Návod na aktivaci BitLocker šifrování disku.

### Menu a ovládání

Skript nabízí přehledné hierarchické menu s číslovanými volbami. Každá sekce má vlastní podmenu s detailními možnostmi konfigurace. Aktuální stav jednotlivých bezpečnostních prvků je zobrazován přímo v menu s barevným označením (zelená = bezpečné, červená = rizikové, žlutá = částečné).

### Doporučené použití

1. Spusťte skript s administrátorskými právy
2. Použijte volbu **"10) ZAPNOUT VSE (maximum zabezpeceni)"** pro rychlou aktivaci všech doporučených nastavení
3. Nebo procházejte jednotlivými sekcemi a přizpůsobte nastavení podle vašich potřeb
4. Pravidelně kontrolujte sekci **"8) Aktualizace a Software"** pro udržení systému aktuálního

---

## `applocker-pc.ps1` - Application & Macro Whitelisting

Tento nástroj se zaměřuje na implementaci "Application Whitelisting" pomocí WDAC (Windows Defender Application Control) a na zabezpečení maker v Microsoft Office.

### Funkce

-   **Windows Defender Application Control (WDAC):**
    -   **Tvorba a správa politik:**
        -   Vytvoření výchozí politiky, která povoluje pouze součásti Windows, WHQL ovladače a aplikace z Microsoft Store.
        -   Přepínání mezi `Audit` (pouze loguje) a `Enforce` (aktivně blokuje) módem.
    -   **Vlastní pravidla:**
        -   Možnost přidávat vlastní výjimky pro aplikace na základě cesty k souboru, digitálního podpisu (publisher) nebo hashe.
        -   Funkce pro skenování celé složky (např. `C:\Program Files`) a automatické vytvoření pravidel pro veškerý nalezený software.
    -   **Správa politik:**
        -   Slučování (merge) více politik do jedné.
        -   Kompilace a nasazení politiky do systému.
        -   Bezpečné odebrání aktivní politiky.
    -   **WDAC Wizard:**
        -   Nástroj nabízí stažení a instalaci oficiálního GUI nástroje `WDAC Wizard` od Microsoftu pro snazší vizuální tvorbu politik.

-   **Zabezpečení maker v Microsoft Office:**
    -   **Globální nastavení:**
        -   Hromadné nastavení úrovně zabezpečení maker pro všechny aplikace Office (Word, Excel, PowerPoint, atd.).
        -   Možnost nastavit politiku "Povolit pouze digitálně podepsaná makra".
    -   **Důvěryhodná umístění (Trusted Locations):**
        -   Správa složek, ve kterých je spouštění maker vždy povoleno.
    -   **Důvěryhodní vydavatelé (Trusted Publishers):**
        -   Správa seznamu důvěryhodných certifikátů, jejichž makra budou vždy povolena.
        -   Možnost přidat vydavatele z `.cer` souboru nebo přímo z podepsaného `exe`/`dll`.

---

## `monitor-pc.ps1` - Monitoring & Audit

Tento skript slouží k interaktivnímu monitoringu a auditu systému Windows. Umožňuje rychle získat přehled o bezpečnostních událostech, běžících procesech, otevřených portech, aktivitě skriptovacích enginů a další klíčové informace včetně pokročilé **detekce hrozeb**.

### Funkce

- **Bezpečnostní události:**
  - Výpis chybných a úspěšných přihlášení (Logon Failure/Success) ze Security logu.
  - Kritické bezpečnostní události (vytváření uživatelů, změny skupin).

- **Spuštěné procesy:**
  - Výpis všech běžících procesů včetně informace o digitálním podpisu spustitelného souboru.
  - Detekce nepodepsaných a podezřelých procesů.
  - Barevné označení podle typu podpisu (Microsoft, podepsáno, nepodepsáno).

- **Otevřené porty:**
  - Výpis všech otevřených TCP portů a procesů, které je otevřely.
  - Aktivní síťová spojení (ESTABLISHED).

- **Monitoring PowerShell, CMD, WMI:**
  - Výpis aktuálně spuštěných PowerShell, CMD a WMI procesů.
  - Zobrazení command line argumentů a času spuštění.

- **🔴 Historie příkazů a detekce hrozeb (NOVÉ!):**
  - **PowerShell Script Block Logging:**
    - Analýza historie PowerShell příkazů z Event Logu (Event ID 4104).
    - Automatická detekce podezřelých vzorů a technik.
  - **Process Creation Audit:**
    - Monitoring vytváření procesů (Event ID 4688).
    - Detekce skriptovacích procesů a jejich parametrů.
  - **Sysmon Process Creation:**
    - Pokročilá analýza pomocí Sysmon logů (Event ID 1).
    - Zobrazení parent procesů a hashů.
  - **WMI Persistence:**
    - Kontrola WMI Event Subscriptions pro detekci persistence.
  - **Pokročilá detekce:**
    - `-ExecutionPolicy Bypass` / `Unrestricted`
    - `-EncodedCommand` a Base64 encoding
    - `-WindowStyle Hidden` a `-NoProfile`
    - Download cradles (`IEX`, `Invoke-WebRequest`, `WebClient`)
    - Reflective loading (`Reflection.Assembly.Load`)
    - Defender modifications (`Add-MpPreference -ExclusionPath`, `DisableRealtimeMonitoring`)
    - LOLBins (`mshta.exe`, `regsvr32.exe`, `rundll32.exe`)
    - Known offensive tools (Mimikatz, PowerDump, atd.)
    - Output suppression a obfuscation
  - **Severity hodnocení:**
    - **Critical** (Magenta) - Nejzávažnější hrozby (Defender disable, offensive tools)
    - **High** (Red) - Vysoké riziko (encoded commands, downloads, reflective loading)
    - **Medium** (Yellow) - Střední riziko (NoProfile, nested PowerShell, temp directory)
    - **Low** (Cyan) - Nízké riziko (output suppression, CMD execution)

- **Další monitoring:**
  - Výpis naplánovaných úloh (Scheduled Tasks).
  - Výpis služeb (Services) - běžící i zastavené automatické.
  - Výpis uživatelů a skupin v systému.
  - Programy spouštěné při startu systému.
  - Rychlý přehled systému (dashboard).

### Menu a ovládání

Skript nabízí přehledné hlavní menu a podmenu pro jednotlivé oblasti monitoringu. Po výběru požadované volby se zobrazí odpovídající informace, případně další možnosti. Menu **Historie příkazů a detekce hrozeb** poskytuje komplexní bezpečnostní audit s automatickou detekcí známých útočných technik.

### Doporučení

Pro maximální efektivitu detekce hrozeb doporučujeme:
1. Zapnout **PowerShell Script Block Logging** pomocí `secure-pc.ps1`
2. Zapnout **Process Creation Audit**:
   - **Český Windows**: `auditpol /set /subcategory:"Vytváření procesu" /success:enable`
   - **Anglický Windows**: `auditpol /set /subcategory:"Process Creation" /success:enable`
3. Nainstalovat **Sysmon** pomocí `secure-pc.ps1` pro pokročilý logging
4. Pravidelně kontrolovat sekci "Historie příkazů" pro detekci podezřelých aktivit

### Kompatibilita

Skript je plně kompatibilní s **PowerShell Constrained Language Mode** (AppLocker/Device Guard), parsuje události přímo z Properties místo XML pro zajištění funkčnosti i v zabezpečených prostředích.

---

## ⚠️ Antivir Blokování - Řešení

V některých případech (zejména na systémech s agresivnějšími antiviry) se skript `monitor-pc.ps1` může zablokovat s chybou:

```
This script contains malicious content and has been blocked by your antivirus software.
```

### Proč se to děje?

Skript obsahuje **detekční vzory pro bezpečnostní hrozby** (ExecutionPolicy Bypass, encoded commands, atd.), které antivirový software mylně interpretuje jako "malicious content". Jedná se o **falešný pozitiv** (false positive) - skript je legální bezpečnostní nástroj.

### Řešení

#### **Možnost 1: Dočasně vypnout Real-Time Protection (Nejrychlejší)**

V PowerShellu (jako Administrator):
```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
# Nyní spusť skript
.\monitor-pc.ps1
# Po skončení jej znovu zapni:
Set-MpPreference -DisableRealtimeMonitoring $false
```

#### **Možnost 2: Přidat výjimku do Windows Defenderu**

V **PowerShellu (jako Administrator)**:
```powershell
$scriptPath = (Get-Item ".\monitor-pc.ps1").FullName
Add-MpPreference -ExclusionPath $scriptPath
```

Nebo v **GUI** (Defender → Virus and threat protection → Manage settings → Exclusions → Add exclusions):
- Vyberte **Files** a přidejte cestu k souboru `monitor-pc.ps1`

#### **Možnost 3: Změnit Execution Policy (Dočasně)**

V PowerShellu (jako Administrator):
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
.\monitor-pc.ps1
# Afterwards restore:
Set-ExecutionPolicy -ExecutionPolicy Restricted -Scope CurrentUser
```

#### **Možnost 4: Odblokovat skript - Vlastnosti souboru**

1. Klikněte **pravým tlačítkem** na `monitor-pc.ps1`
2. Vyberte **Properties** (Vlastnosti)
3. Na kartě **General** zaškrtněte **"Unblock"** (Odblokovat)
4. Klikněte **Apply** a **OK**

#### **Možnost 5: Snadný přístup - Skript pro odblokování**

Vytvořte soubor `unblock-scripts.ps1`:
```powershell
# Unlock all PowerShell scripts
Get-ChildItem -Filter "*.ps1" | Unblock-File
Write-Host "Všechny PS1 soubory odblokováno!" -ForegroundColor Green
```

Spusťte jej:
```powershell
.\unblock-scripts.ps1
```

### Technické pozadí

Detekční vzory v `monitor-pc.ps1` jsou obfuskované a konstruovány za běhu, aby minimalizovaly falešné pozitivy od antivirových nástrojů. Přesto některé stringy jako "Invoke-Expression" nebo "Mimikatz" mohou spustit heuristickou detekci.

**Skript je bezpečný** - nejde o žádný malware nebo trojan. Jednoduše analyzuje systémové logy a detekuje podezřelé aktivity.

### Bezpečnostní poznámka

Pokud si nejste jisti, že jde o falešný pozitiv:
- ✅ Stáhněte si skript z **důvěryhodného zdroje** (GitHub)
- ✅ Zkontrolujte kód v textovém editoru
- ✅ Věnujte pozornost tomu, co skript dělá (pouze čte, nic mění)
- ✅ Spusťte jej v testovacím prostředí nejprve





