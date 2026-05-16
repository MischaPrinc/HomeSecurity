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
2. [**QuickNav — rychlé kódy**](#quicknav--rychlé-kódy)
3. [Modul 1: Zabezpečení (Hardening)](#modul-1-zabezpečení-hardening)
4. [Modul 2: Monitoring a Audit](#modul-2-monitoring-a-audit)
5. [Modul 3: Application Whitelisting (WDAC + Makra)](#modul-3-application-whitelisting-wdac--makra)
6. [Alternativa: Samostatné skripty](#alternativa-samostatné-skripty)
7. [Antivir blokování — řešení](#-antivir-blokování--řešení)

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

## QuickNav — rychlé kódy

Místo procházení menu stačí na výzvu `Vyberte modul` zadat x-kód a skript vás přenese přímo na požadovanou volbu.

### Formát

```
x{modul}{podmenu}{volba}
```

| Část | Popis |
|------|-------|
| `x` | prefix (povinný) |
| `{modul}` | 1 = Zabezpečení, 2 = Monitoring, 3 = WDAC+Makra |
| `{podmenu}` | číslo podmenu (pro modul 1: 1–9, modul 3: 1–3; modul 2 nemá podmenu) |
| `{volba}` | číslo volby v podmenu (1–21) |

**Příklady:**
```
x1411   → Modul 1, podmenu 4 (Systém+Logování), volba 11 (nedefinovaná — ukázka formátu)
x193    → Modul 1, podmenu 9 (Pokročilé), volba 3  → Zapnout LSA PPL
x112    → Modul 1, podmenu 1 (Defender+ASR), volba 2 → ASR BLOKOVAT [DOPORUČENO]
x26     → Modul 2, volba 6  → Historie příkazů a detekce hrozeb
x311    → Modul 3, podmenu 1 (WDAC), volba 1 → Vytvořit WDAC politiku (Audit)
```

Po provedení volby se skript vrátí do normálního interaktivního režimu daného podmenu.

---

### Modul 1 — Zabezpečení: všechny rychlokódy

#### Podmenu 1 — Defender + ASR (`x11...`)

| Kód | Akce |
|-----|------|
| `x111` | ASR pravidla — zobrazit detail |
| `x112` | ASR pravidla — BLOKOVAT vše ✅ |
| `x113` | ASR pravidla — AUDIT |
| `x114` | ASR pravidla — VYPNOUT |
| `x115` | PUA ochrana — BLOKOVAT ✅ |
| `x116` | PUA ochrana — AUDIT |
| `x117` | PUA ochrana — VYPNOUT |
| `x118` | Defender Real-Time + Cloud — ZAPNOUT ✅ |
| `x119` | Defender Real-Time — VYPNOUT |
| `x1110` | Controlled Folder Access — ZAPNOUT ✅ |
| `x1111` | Controlled Folder Access — AUDIT |
| `x1112` | Controlled Folder Access — VYPNOUT |
| `x1113` | Tamper Protection — ZAPNOUT ✅ |
| `x1114` | Tamper Protection — VYPNOUT |
| `x1115` | Office registry zabezpečení ✅ |
| `x1116` | Defender sandboxing ✅ |
| `x1117` | Aktualizovat Defender signatury ✅ |

#### Podmenu 2 — SmartScreen (`x12...`)

| Kód | Akce |
|-----|------|
| `x121` | SmartScreen (Windows) — ZAPNOUT ✅ |
| `x122` | SmartScreen (Windows) — VYPNOUT |
| `x123` | SmartScreen (Edge) — ZAPNOUT ✅ |
| `x124` | SmartScreen (Edge) — VYPNOUT |

#### Podmenu 3 — Síť (`x13...`)

| Kód | Akce |
|-----|------|
| `x131` | Windows Firewall — ZAPNOUT ✅ |
| `x132` | Windows Firewall — VYPNOUT |
| `x133` | RDP — ZAKÁZAT ✅ |
| `x134` | RDP — POVOLIT |
| `x135` | SMBv1 — ZAKÁZAT ✅ |
| `x136` | SMBv1 — POVOLIT |
| `x137` | LLMNR — ZAKÁZAT ✅ |
| `x138` | LLMNR — POVOLIT |

#### Podmenu 4 — Systém + Logování (`x14...`)

| Kód | Akce |
|-----|------|
| `x141` | AutoRun/AutoPlay — ZAKÁZAT ✅ |
| `x142` | AutoRun/AutoPlay — POVOLIT |
| `x143` | PS Script Block Logging — ZAPNOUT ✅ |
| `x144` | PS Script Block Logging — VYPNOUT |

#### Podmenu 5 — Sysmon (`x15...`)

| Kód | Akce |
|-----|------|
| `x151` | Instalovat Sysmon64 + konfigurace |
| `x152` | Aktualizovat konfiguraci Sysmon |
| `x153` | Použít vlastní XML konfiguraci |
| `x154` | Odinstalovat Sysmon |

#### Podmenu 6 — Bezpečné DNS (`x16...`)

| Kód | Akce |
|-----|------|
| `x161` | Zobrazit detail DNS |
| `x162` | Cloudflare malware DNS (1.1.1.2) ✅ |
| `x163` | Cloudflare malware + dospělý obsah (1.1.1.3) ✅ |
| `x164` | Cloudflare standard (1.1.1.1) |
| `x165` | Reset DNS na DHCP |

#### Podmenu 7 — Další doporučení (`x17...`)

| Kód | Akce |
|-----|------|
| `x171` | Zakázat LM hash ✅ |
| `x172` | Povolit LM hash |
| `x173` | Sticky Keys — odstranit Debugger ✅ |
| `x174` | Sticky Keys — ponechat výchozí |
| `x175` | BitLocker — zobrazit návod |

#### Podmenu 8 — Aktualizace + Software (`x18...`)

| Kód | Akce |
|-----|------|
| `x181` | Windows Update — zobrazit stav |
| `x182` | Windows Update — spustit instalaci ✅ |
| `x183` | Winget — nainstalovaný software |
| `x184` | Winget — dostupné aktualizace |
| `x185` | Winget — aktualizovat vše ✅ |

#### Podmenu 9 — Pokročilé zabezpečení (`x19...`)

| Kód | Akce |
|-----|------|
| `x191` | WDigest — ZAKÁZAT (bez plaintext hesel v RAM) ✅ |
| `x192` | WDigest — POVOLIT |
| `x193` | LSA PPL — ZAPNOUT (ochrana lsass.exe) ✅ |
| `x194` | LSA PPL — VYPNOUT |
| `x195` | Network Protection — BLOKOVAT ✅ |
| `x196` | Network Protection — AUDIT |
| `x197` | Network Protection — VYPNOUT |
| `x198` | NetBIOS — ZAKÁZAT ✅ |
| `x199` | NetBIOS — POVOLIT |
| `x1910` | NTLMv2 — úroveň 5 (nejsilnější) ✅ |
| `x1911` | NTLMv2 — úroveň 3 (Windows výchozí) |
| `x1912` | Windows Script Host — ZAKÁZAT ✅ |
| `x1913` | Windows Script Host — POVOLIT |
| `x1914` | UAC — MAXIMUM ✅ |
| `x1915` | UAC — STANDARD |
| `x1916` | UAC — Windows výchozí |
| `x1917` | Event Logy — zvětšit velikost ✅ |
| `x1918` | Remote Registry — ZAKÁZAT ✅ |
| `x1919` | Remote Registry — obnovit na Manual |
| `x1920` | LSA Registry Protection Audit — zobrazit |
| `x1921` | LSA Registry Auditing — zapnout (Event 4657/4663) ✅ |

---

### Modul 2 — Monitoring: všechny rychlokódy (`x2...`)

| Kód | Akce |
|-----|------|
| `x21` | Bezpečnostní události (Security Events) |
| `x22` | Spuštěné procesy |
| `x23` | Síťová připojení |
| `x24` | Skriptovací procesy (PS/CMD/WMI) |
| `x25` | Systém a správa (služby/úlohy/uživatelé) |
| `x26` | Historie příkazů a detekce hrozeb |
| `x29` | Rychlý přehled systému (dashboard) |
| `x2E` | Export všech dat do souboru |

---

### Modul 3 — WDAC + Makra: všechny rychlokódy

#### Podmenu 1 — WDAC (`x31...`)

| Kód | Akce |
|-----|------|
| `x311` | Vytvořit výchozí politiku — AUDIT mód |
| `x312` | Vytvořit výchozí politiku — ENFORCE mód |
| `x313` | Přidat pravidlo podle cesty |
| `x314` | Přidat pravidlo podle vydavatele |
| `x315` | Přidat pravidlo podle hashe souboru |
| `x316` | Naskenovat složku a přidat pravidla |
| `x317` | Kompilovat a nasadit politiku ✅ |
| `x318` | Přepnout na AUDIT mód |
| `x319` | Přepnout na ENFORCE mód |
| `x3110` | Odebrat nasazenou politiku |
| `x3111` | Detailní stav + VBS/HVCI/Credential Guard |
| `x3112` | Stáhnout WDAC Wizard (Microsoft GUI) |
| `x3113` | Importovat XML politiku |
| `x3114` | Zobrazit podrobný návod (workflow) |
| `x3115` | Zobrazit zablokované aplikace (Event 3076/3077) |
| `x3116` | Průvodce blokování LOLBins |

#### Podmenu 2 — Office Makra (`x32...`)

| Kód | Akce |
|-----|------|
| `x321` | Stav všech Office aplikací |
| `x322` | Zakázat vše kromě podepsaných ✅ |
| `x323` | Zakázat vše s notifikací |
| `x324` | Zakázat úplně vše |
| `x325` | Povolit vše (nebezpečné!) |
| `x326` | Trusted Locations — zobrazit |
| `x327` | Trusted Locations — přidat |
| `x328` | Trusted Locations — odebrat |
| `x329` | Trusted Publishers — zobrazit |
| `x3210` | Trusted Publishers — přidat |
| `x3211` | Vytvořit self-signed certifikát pro makra ✅ |

#### Podmenu 3 — PowerShell Hardening (`x33...`)

| Kód | Akce |
|-----|------|
| `x331` | PS Constrained Language Mode — ZAPNOUT |
| `x332` | PS Constrained Language Mode — VYPNOUT |

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

