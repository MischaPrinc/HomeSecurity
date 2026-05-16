# PC Security Suite — Nástroj pro Zabezpečení Domácího PC

Komplexní sada interaktivních PowerShell nástrojů pro pokročilé zabezpečení, monitoring a hardening pracovních stanic s Windows 10 a 11. Skripty jsou navrženy pro domácí uživatele i pokročilejší správce — přehledné menu, žádné ruční editace registrů.

**Autor:** Mischa Princ

> **Důležité:** Všechny skripty musí být spuštěny s administrátorskými oprávněními.

---

## Rychlý start

### Doporučeno: Jednotný skript `pc-suite.ps1`

```powershell
# Klikněte pravým tlačítkem na PowerShell -> Spustit jako správce
.\pc-suite.ps1
```

Po spuštění se zobrazí hlavní výběr modulu:

```
  +============================================================+
  |         PC SECURITY SUITE - Interaktivni nastroj           |
  |                   vytvoril: Mischa Princ                   |
  +============================================================+

  Vyberte modul ktery chcete pouzit:

    1)  Zabezpeceni (Hardening)
    2)  Monitoring a Audit
    3)  Application Whitelisting (WDAC + Makra)

    0)  Konec
```

---

## Obsah

1. [**`pc-suite.ps1`** — Jednotný skript (doporučeno)](#pc-suiteps1--jednotný-skript-doporučeno)
2. [Modul 1: Zabezpečení (Hardening)](#modul-1-zabezpečení-hardening)
3. [Modul 2: Monitoring a Audit](#modul-2-monitoring-a-audit)
4. [Modul 3: Application Whitelisting (WDAC + Makra)](#modul-3-application-whitelisting-wdac--makra)
5. [Alternativa: Samostatné skripty](#alternativa-samostatné-skripty)
6. [Antivir blokování — řešení](#-antivir-blokování--řešení)

---

## `pc-suite.ps1` — Jednotný skript (doporučeno)

Jeden soubor (~5800 řádků) kombinující všechny tři moduly. Na začátku vyberete modul, do kterého chcete vstoupit, a po návratu zpět se vrátíte do hlavního výběru.

### Spuštění

```powershell
# Jako Administrator:
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
.\pc-suite.ps1
```

Nebo odblokování a spuštění jedním příkazem:

```powershell
Unblock-File .\pc-suite.ps1
powershell -ExecutionPolicy Bypass -File .\pc-suite.ps1
```

---

## Modul 1: Zabezpečení (Hardening)

Interaktivní menu s hierarchickým systémem podmenu. Každá volba zobrazuje aktuální stav příslušného nastavení (zelená = bezpečné, červená = rizikové, žlutá = částečné).

### Podmenu

| Volba | Oblast | Co nastavuje |
|-------|--------|--------------|
| `1` | **Defender + ASR** | ASR pravidla (14x), PUA, CFA, Tamper Protection, Real-Time + Cloud ochrana |
| `2` | **SmartScreen** | SmartScreen pro Explorer i Microsoft Edge |
| `3` | **Síť** | Windows Firewall, RDP, SMBv1, LLMNR |
| `4` | **Systém + Logování** | AutoRun, PowerShell Script Block Logging |
| `5` | **Sysmon** | Instalace/odinstalace Sysmon64, pokročilá konfigurace, plánovaná údržba |
| `6` | **Bezpečné DNS** | Cloudflare 1.1.1.1 (Malware), 1.1.1.2 (Malware+Dospělý obsah) |
| `7` | **Další doporučení** | LM hash, Sticky Keys, BitLocker návod |
| `8` | **Aktualizace + Software** | Windows Update, Winget — přehled, kontrola, instalace |
| `9` | **Pokročilé zabezpečení** | WDigest, LSA PPL, Network Protection, NetBIOS, NTLMv2, WSH, UAC, Event log velikosti, Remote Registry, Secure Boot (info), VBS/HVCI (info) |
| `10` | **Zapnout vše** | Aktivuje všechna doporučená nastavení najednou |
| `99` | **Kompletní přehled** | Zobrazí aktuální stav všech sledovaných parametrů |

### Doporučené použití

1. Spusťte skript → vyberte **modul 1**
2. Použijte volbu **`10) ZAPNOUT VSE`** pro rychlé nastavení
3. Nebo procházejte podmenu a přizpůsobte si nastavení
4. Pravidelně kontrolujte **`8) Aktualizace a Software`**

---

## Modul 2: Monitoring a Audit

Interaktivní monitorovací nástroj pro zjišťování bezpečnostních událostí, analýzu procesů a detekci hrozeb.

### Podmenu

| Volba | Oblast | Co zobrazuje |
|-------|--------|--------------|
| `1` | **Bezpečnostní události** | Neúspěšná přihlášení (4625), úspěšná přihlášení (4624), kritické události (4616, 4648, 4697, 4698, 4702, 4720, 4726, 4740...), smazání logu (1102), **Persistence events** (Run keys, Startup, Winlogon, IFEO, AppInit_DLLs, nové tasky) |
| `2` | **Procesy** | Všechny procesy (top 30 / kompletní), nepodepsané a podezřelé procesy, **procesy ze podezřelých cest** (Temp/AppData/Downloads/Public) |
| `3` | **Síť** | Otevřené porty (LISTENING), aktivní spojení (ESTABLISHED), **DNS cache** — filtruje bezpečné domény, zvýrazňuje TTL < 300s |
| `4` | **Skriptovací procesy** | PowerShell, CMD, WMI procesy, **podezřelé parent-child vztahy** (Sysmon ID 1) — winword→PS, excel→cmd, mshta→PS atd. |
| `5` | **Systém a správa** | Naplánované úlohy (jen non-Microsoft), služby (běžící/zastavené), uživatelé, skupiny, startup programy |
| `6` | **Historie a detekce** | Script Block Logging (4104), Process Creation (4688), Sysmon (ID 1), WMI Persistence |
| `9` | **Rychlý přehled** | Dashboard — stav Defenderu, Sysmon, Secure Boot, otevřené porty, poslední selhání přihlášení, 24h statistiky |
| `E` | **Export dat** | Uloží výstup všech monitorovacích funkcí do `Desktop\MonitorReport_YYYYMMDD_HHMMSS.txt` |

### Detekce hrozeb — severity

| Úroveň | Barva | Příklady |
|--------|-------|---------|
| **Critical** | Magenta | Deaktivace Defenderu, Mimikatz, PowerDump |
| **High** | Red | EncodedCommand, download cradles, reflective loading |
| **Medium** | Yellow | -NoProfile, nested PowerShell, procesy v Temp |
| **Low** | Cyan | Output suppression, CMD z PS |

### Doporučení pro maximální efektivitu

```powershell
# 1. Zapnout Script Block Logging (v modulu Zabezpečení -> 4)
# 2. Zapnout Process Creation Audit:
auditpol /set /subcategory:"Process Creation" /success:enable
# 3. Nainstalovat Sysmon (v modulu Zabezpečení -> 5)
```

---

## Modul 3: Application Whitelisting (WDAC + Makra)

Správa WDAC (Windows Defender Application Control) politik a zabezpečení maker v Microsoft Office.

### Podmenu

#### WDAC — Application Whitelisting

| Volba | Funkce |
|-------|--------|
| `1` / `2` | Vytvořit výchozí politiku (Audit / Enforce) |
| `3` | Přidat pravidlo podle **cesty** |
| `4` | Přidat pravidlo podle **vydavatele** (Publisher) |
| `5` | Přidat pravidlo podle **hashe** souboru |
| `6` | Naskenovat složku a vytvořit pravidla pro vše nalezené |
| `7` | **Kompilovat a nasadit** politiku do systému |
| `8` / `9` | Přepnout na Audit / Enforce mód |
| `10` | Odebrat nasazenou politiku (se zálohou `.bak`) |
| `11` | Detailní stav + Event Log + **VBS/HVCI/Credential Guard** |
| `12` | Stáhnout WDAC Wizard (oficiální Microsoft GUI) |
| `13` | Importovat XML politiku z externího zdroje |
| `14` | Zobrazit podrobný návod (workflow) |
| `15` | **Zobrazit zablokované aplikace** (Event IDs 3076/3077) |
| `16` | **Průvodce blokování LOLBins** (mshta, wscript, cscript, certutil) |

#### Office Makra

| Volba | Funkce |
|-------|--------|
| `1` | Stav všech Office aplikací (Word, Excel, PowerPoint...) |
| `2` | **Zakázat vše kromě podepsaných** (doporučeno) |
| `3` | Zakázat vše s notifikací (výchozí Office) |
| `4` | Zakázat úplně vše |
| `5` | Povolit vše (nebezpečné!) |
| `6-8` | Trusted Locations — zobrazit / přidat / odebrat |
| `9-10` | Trusted Publishers — zobrazit / přidat |
| `11` | **Vytvořit self-signed certifikát** pro podepisování maker/skriptů |

#### PowerShell Hardening

Nastavení PowerShell Constrained Language Mode pro omezení nebezpečných operací v PowerShellu.

### Doporučený workflow WDAC

```
1. Volba 1  → Vytvořit výchozí politiku (AUDIT mód)
2. Volba 6  → Naskenovat C:\Program Files a přidat vaše aplikace
3. Volba 7  → Kompilovat a nasadit
4. Restart PC → testovat normální práci
5. Volba 15 → Zkontrolovat co by bylo blokováno (Event 3076)
6. Volba 9  → Přepnout na ENFORCE až je vše OK
```

> **Poznámka:** WDAC vyžaduje Windows 10/11 **Pro** nebo vyšší edici.

---

## Alternativa: Samostatné skripty

Pokud preferujete jednotlivé skripty bez sloučení, jsou k dispozici:

| Soubor | Popis |
|--------|-------|
| `secure-pc.ps1` | Pouze modul Zabezpečení (Hardening) |
| `monitor-pc.ps1` | Pouze modul Monitoring a Audit |
| `applocker-pc.ps1` | Pouze modul WDAC + Makra |

Všechny tři jsou plně funkční samostatně a mají identické funkce jako odpovídající moduly v `pc-suite.ps1`.

---

## ⚠️ Antivir Blokování — Řešení

V některých případech může antivir zablokovat skripty s chybou:

```
This script contains malicious content and has been blocked by your antivirus software.
```

Toto je **falešný pozitiv** — skripty obsahují detekční vzory pro bezpečnostní hrozby (ExecutionPolicy Bypass, encoded commands, názvy útočných nástrojů), které AV mylně identifikuje jako škodlivé. **Skripty jsou bezpečné.**

### Řešení

#### Možnost 1: Odblokovat soubor (nejjednodušší)

```powershell
Unblock-File .\pc-suite.ps1
```

Nebo v GUI: Pravý klik → Vlastnosti → záložka Obecné → zaškrtněte **Odblokovat** → OK

#### Možnost 2: Přidat výjimku do Windows Defenderu

```powershell
# V PowerShellu jako Administrator:
$scriptPath = (Get-Item ".\pc-suite.ps1").FullName
Add-MpPreference -ExclusionPath $scriptPath
```

#### Možnost 3: Spustit s Bypass

```powershell
powershell -ExecutionPolicy Bypass -File .\pc-suite.ps1
```

#### Možnost 4: Odblokovat všechny PS1 soubory v adresáři

```powershell
Get-ChildItem -Filter "*.ps1" | Unblock-File
Write-Host "Vsechny PS1 soubory odblokovany!" -ForegroundColor Green
```

### Bezpečnostní poznámka

Pokud si nejste jisti:
- ✅ Zkontrolujte kód v textovém editoru před spuštěním
- ✅ Stáhněte z důvěryhodného zdroje
- ✅ Monitoring funkce pouze **čtou** systémová data — nic nemodifikují
- ✅ Hardening funkce mění nastavení Windows — vždy si přečtěte popis volby

