# HomeSecurity
# Nástroje pro Zabezpečení a Hardening Windows

Tento repozitář obsahuje sadu interaktivních PowerShell skriptů pro pokročilé zabezpečení a hardening pracovních stanic s operačním systémem Windows 10 a 11. Skripty jsou navrženy tak, aby byly snadno použitelné i pro uživatele bez hlubokých znalostí PowerShellu, a to díky přehlednému menu.

**Autor:** Mischa Princ

> **Důležité:** Všechny skripty musí být spuštěny s administrátorskými oprávněními.

---

## Obsah

1.  [**`secure-pc.ps1`** - Interaktivní Hardening](#secure-pcps1---interaktivní-hardening)
2.  [**`applocker-pc.ps1`** - Application & Macro Whitelisting](#applocker-pcps1---application--macro-whitelisting)

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
