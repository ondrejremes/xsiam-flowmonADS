#!/usr/bin/env python3
"""Generates Czech documentation for FlowmonADS content pack as a .docx file."""

from docx import Document
from docx.shared import Pt, RGBColor, Inches
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml.ns import qn
from docx.oxml import OxmlElement

OUTPUT = "Packs/FlowmonADS/FlowmonADS-dokumentace.docx"


def set_cell_bg(cell, hex_color):
    tc = cell._tc
    tcPr = tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), hex_color)
    tcPr.append(shd)


def add_table(doc, headers, rows, col_widths=None):
    table = doc.add_table(rows=1, cols=len(headers))
    table.style = "Table Grid"
    table.alignment = WD_TABLE_ALIGNMENT.LEFT

    # Header row
    hdr = table.rows[0].cells
    for i, h in enumerate(headers):
        hdr[i].text = h
        set_cell_bg(hdr[i], "2E75B6")
        p = hdr[i].paragraphs[0]
        run = p.runs[0]
        run.bold = True
        run.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
        run.font.size = Pt(10)

    # Data rows
    for row_data in rows:
        row = table.add_row().cells
        for i, val in enumerate(row_data):
            row[i].text = val
            row[i].paragraphs[0].runs[0].font.size = Pt(10)

    # Column widths
    if col_widths:
        for i, w in enumerate(col_widths):
            for row in table.rows:
                row.cells[i].width = Inches(w)

    return table


def add_heading(doc, text, level):
    p = doc.add_heading(text, level=level)
    if level == 1:
        p.runs[0].font.color.rgb = RGBColor(0x1F, 0x49, 0x7D)
    elif level == 2:
        p.runs[0].font.color.rgb = RGBColor(0x2E, 0x75, 0xB6)
    return p


def add_code(doc, text):
    p = doc.add_paragraph()
    run = p.add_run(text)
    run.font.name = "Courier New"
    run.font.size = Pt(9)
    run.font.color.rgb = RGBColor(0x1A, 0x1A, 0x1A)
    p.paragraph_format.left_indent = Inches(0.3)
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), "F2F2F2")
    p._p.get_or_add_pPr().append(shd)
    return p


doc = Document()

# Page margins
for section in doc.sections:
    section.top_margin = Inches(1)
    section.bottom_margin = Inches(1)
    section.left_margin = Inches(1.2)
    section.right_margin = Inches(1.2)

# ── Title page ────────────────────────────────────────────────────────────────
title = doc.add_heading("Flowmon ADS – Integrace s Cortex XSIAM", 0)
title.alignment = WD_ALIGN_PARAGRAPH.CENTER
title.runs[0].font.color.rgb = RGBColor(0x1F, 0x49, 0x7D)

subtitle = doc.add_paragraph("Technická dokumentace content packu")
subtitle.alignment = WD_ALIGN_PARAGRAPH.CENTER
subtitle.runs[0].font.size = Pt(13)
subtitle.runs[0].font.color.rgb = RGBColor(0x70, 0x70, 0x70)

version = doc.add_paragraph("Verze 1.0.6  |  Autor: Ondrej Remes")
version.alignment = WD_ALIGN_PARAGRAPH.CENTER
version.runs[0].font.size = Pt(10)
version.runs[0].font.color.rgb = RGBColor(0x70, 0x70, 0x70)

doc.add_page_break()

# ── 1. Přehled ────────────────────────────────────────────────────────────────
add_heading(doc, "1. Přehled", 1)
doc.add_paragraph(
    "Tento content pack integruje Progress Flowmon Anomaly Detection System (ADS) "
    "s platformou Palo Alto Cortex XSIAM. Umožňuje automatický příjem síťových anomálií "
    "detekovaných Flowmonem jako bezpečnostních alertů v XSIAM, obohacuje vyšetřování "
    "o kontextová data ze síťových toků a podporuje obousměrné zrcadlení stavu alertů."
)

add_heading(doc, "1.1 Klíčové funkce", 2)
for item in [
    "Automatický fetch ADS eventů do XSIAM jako incidentů/alertů",
    "Mapování priority Flowmon ADS (1–5) na závažnost XSIAM (Low → Critical)",
    "Filtrování eventů podle Perspektivy (podle jména)",
    "Obousměrné zrcadlení stavu: uzavření alertu v XSIAM uzavře event ve Flowmonu a naopak",
    "Příkazy pro ruční dotazování perspektiv a eventů přímo z XSIAM",
    "Podpora MITRE ATT&CK mapování technik",
    "Deduplikace eventů při fetchování",
]:
    p = doc.add_paragraph(item, style="List Bullet")
    p.runs[0].font.size = Pt(10)

add_heading(doc, "1.2 Požadavky", 2)
add_table(doc,
    ["Komponenta", "Minimální verze / požadavek"],
    [
        ["Cortex XSIAM / XSOAR", "6.10.0 nebo novější"],
        ["Flowmon ADS", "REST API musí být dostupné"],
        ["Síťová konektivita", "XSIAM → Flowmon appliance (HTTPS, port 443)"],
        ["Flowmon účet", "Uživatel s oprávněním číst a zavírat ADS eventy"],
    ],
    col_widths=[2.5, 3.5],
)

doc.add_page_break()

# ── 2. Komponenty packu ───────────────────────────────────────────────────────
add_heading(doc, "2. Komponenty content packu", 1)
add_table(doc,
    ["Typ", "Název", "Popis"],
    [
        ["Integrace", "FlowmonADS", "Hlavní integrace – komunikace s Flowmon REST API"],
        ["Incident Type", "Flowmon ADS Event", "Typ incidentu/alertu pro Flowmon eventy"],
        ["Layout", "Flowmon ADS Event", "Vizuální layout detailu alertu (Summary, MITRE ATT&CK, War Room)"],
        ["Layout Rule", "FlowmonADS Event Layout Rule", "Pravidlo mapující typ alertu na layout (nutno vytvořit ručně v UI)"],
        ["Incident Fields", "12× vlastní pole", "Flowmon-specifická pole (Source IP, Perspectives, Priority, …)"],
    ],
    col_widths=[1.5, 2.2, 3.3],
)

doc.add_page_break()

# ── 3. Instalace a konfigurace ────────────────────────────────────────────────
add_heading(doc, "3. Instalace a konfigurace", 1)

add_heading(doc, "3.1 Upload content packu", 2)
doc.add_paragraph(
    "Content pack se nahrává přes demisto-sdk. Kvůli omezení SDK je nutný dvoustupňový postup:"
)
add_code(doc, "source /home/ondrreme/.venv-demisto/bin/activate")
add_code(doc, "source .env")
add_code(doc,
    "DEMISTO_SDK_IGNORE_CONTENT_WARNING=1 \\\n"
    "demisto-sdk unify -i Packs/FlowmonADS/Integrations/FlowmonADS/ -o /tmp/FlowmonADS.yml --force"
)
add_code(doc,
    "DEMISTO_SDK_IGNORE_CONTENT_WARNING=1 \\\n"
    "demisto-sdk upload -i /tmp/FlowmonADS.yml --insecure"
)
doc.add_paragraph(
    "Ostatní komponenty (Layout, Incident Fields, Incident Type) se nahrávají zvlášť:"
)
add_code(doc,
    "demisto-sdk upload -i Packs/FlowmonADS/Layouts/layout-FlowmonADS_Event.json --insecure\n"
    "demisto-sdk upload -i Packs/FlowmonADS/IncidentTypes/incidenttype-FlowmonADSEvent.json --insecure\n"
    "for f in Packs/FlowmonADS/IncidentFields/*.json; do\n"
    "  demisto-sdk upload -i \"$f\" --insecure\n"
    "done"
)

add_heading(doc, "3.2 Konfigurace integrační instance", 2)
doc.add_paragraph(
    "V XSIAM přejdi na Settings → Integrations → FlowmonADS → Add instance."
)
add_table(doc,
    ["Parametr", "Popis", "Příklad / výchozí"],
    [
        ["Flowmon URL", "Základní URL Flowmon appliance", "https://flowmon.example.com"],
        ["Username / Password", "Přihlašovací údaje Flowmon uživatele", "—"],
        ["Trust any certificate", "Vypnout ověření TLS (jen pro testování)", "Vypnuto"],
        ["Use system proxy", "Použít systémový proxy", "Vypnuto"],
        ["Fetch incidents", "Povolit automatický příjem eventů", "Zapnuto"],
        ["Maximum events per fetch", "Max. počet eventů na jedno spuštění (1–200)", "50"],
        ["First fetch time", "Jak daleko zpět při prvním spuštění", "1 hour"],
        ["Perspective Name", "Omezit fetch na konkrétní perspektivu (podle jména)", "Security issues"],
    ],
    col_widths=[2.0, 3.0, 2.0],
)

add_heading(doc, "3.3 Layout Rule (ruční krok)", 2)
doc.add_paragraph(
    "Layout Rule nelze nahrát přes demisto-sdk – musí se vytvořit ručně v XSIAM UI:"
)
for step in [
    "Přejdi na Settings → Alerts & Incidents → Alert Layout Rules",
    "Klikni na New Rule",
    "Rule Name: Flowmon ADS Event Layout Rule",
    "Layout: Flowmon ADS Event",
    "Podmínka: Alert Type = Flowmon ADS Event",
    "Ulož",
]:
    p = doc.add_paragraph(step, style="List Number")
    p.runs[0].font.size = Pt(10)

doc.add_page_break()

# ── 4. Autentizace ────────────────────────────────────────────────────────────
add_heading(doc, "4. Autentizace", 1)
doc.add_paragraph(
    "Integrace používá OAuth2 Password Grant flow pro získání bearer tokenu:"
)
add_table(doc,
    ["Parametr", "Hodnota"],
    [
        ["Token endpoint", "https://<flowmon-host>/resources/oauth/token"],
        ["Client ID", "invea-tech (pevně dáno, bez konfigurace)"],
        ["Grant type", "password"],
        ["Token", "Automaticky získán a znovupoužit v rámci instance"],
    ],
    col_widths=[2.5, 4.5],
)
doc.add_paragraph(
    "Token je získán při prvním volání a uložen v paměti instance. "
    "Při vypršení je automaticky obnoven."
)

doc.add_page_break()

# ── 5. Příkazy ────────────────────────────────────────────────────────────────
add_heading(doc, "5. Dostupné příkazy", 1)

add_heading(doc, "5.1 flowmon-ads-perspectives-get", 2)
doc.add_paragraph("Vrátí seznam nakonfigurovaných ADS perspektiv.")
doc.add_paragraph("Výstup: ID a název každé perspektivy.")

add_heading(doc, "5.2 flowmon-ads-events-get", 2)
doc.add_paragraph("Vrátí seznam ADS anomálií pro zadaný časový rozsah.")
add_table(doc,
    ["Argument", "Popis", "Výchozí"],
    [
        ["from_time", "Začátek rozsahu (YYYY-MM-DD HH:MM)", "1 hodina zpět"],
        ["to_time", "Konec rozsahu (YYYY-MM-DD HH:MM)", "Nyní"],
        ["perspective_id", "Filtr podle ID perspektivy", "—"],
        ["limit", "Max. počet eventů (1–200)", "50"],
    ],
    col_widths=[1.8, 3.2, 2.0],
)

add_heading(doc, "5.3 flowmon-ads-event-get", 2)
doc.add_paragraph("Vrátí detailní informace o konkrétním ADS eventu.")
add_table(doc,
    ["Argument", "Popis", "Povinný"],
    [
        ["event_id", "ID ADS eventu", "Ano"],
    ],
    col_widths=[1.8, 3.2, 2.0],
)

add_heading(doc, "5.4 flowmon-ads-event-close", 2)
doc.add_paragraph(
    "Uzavře ADS event nebo ho označí jako false positive. "
    "Volán automaticky zrcadlovacím mechanizmem při uzavření alertu v XSIAM."
)
add_table(doc,
    ["Argument", "Popis", "Výchozí"],
    [
        ["event_id", "ID ADS eventu", "—"],
        ["status", "closed / false_positive / investigating", "closed"],
        ["comment", "Volitelný komentář k uzavření", "—"],
    ],
    col_widths=[1.8, 3.2, 2.0],
)

doc.add_page_break()

# ── 6. Fetch incidentů ────────────────────────────────────────────────────────
add_heading(doc, "6. Automatický příjem eventů (Fetch)", 1)
doc.add_paragraph(
    "Integrace v pravidelných intervalech dotazuje Flowmon ADS REST API "
    "a vytváří nové XSIAM alerty z ADS eventů."
)

add_heading(doc, "6.1 Průběh fetch cyklu", 2)
for step in [
    "Načte čas posledního fetche z last_run (nebo first_fetch při prvním spuštění)",
    "Zavolá GET /rest/ads/events s parametry from, to a volitelně perspective",
    "Aplikuje klientský filtr podle Perspective Name (pokud je nastaven)",
    "Přeskočí eventy, které již byly zpracovány (deduplikace podle ID)",
    "Převede eventy na XSIAM incidenty a uloží čas posledního zpracovaného eventu",
]:
    p = doc.add_paragraph(step, style="List Number")
    p.runs[0].font.size = Pt(10)

add_heading(doc, "6.2 Mapování severity", 2)
add_table(doc,
    ["Flowmon priorita", "Popis", "XSIAM závažnost"],
    [
        ["0", "Neklasifikováno", "Unknown"],
        ["1", "Nejnižší", "Low"],
        ["2", "Nízká", "Low"],
        ["3", "Střední", "Medium"],
        ["4", "Vysoká", "High"],
        ["5", "Kritická", "Critical"],
    ],
    col_widths=[2.0, 2.5, 2.5],
)
doc.add_paragraph(
    "Priorita je určena jako maximum přes všechny perspektivy eventu. "
    "Pokud perspektivy nemají prioritu, použije se top-level priorita eventu."
)

doc.add_page_break()

# ── 7. Zrcadlení ──────────────────────────────────────────────────────────────
add_heading(doc, "7. Obousměrné zrcadlení (Mirroring)", 1)
doc.add_paragraph(
    "Integrace podporuje obousměrnou synchronizaci stavu mezi XSIAM a Flowmon ADS."
)

add_heading(doc, "7.1 XSIAM → Flowmon ADS", 2)
doc.add_paragraph(
    "Při uzavření alertu v XSIAM je odpovídající ADS event automaticky uzavřen:"
)
add_table(doc,
    ["XSIAM Close Reason", "Flowmon ADS status"],
    [
        ["False Positive", "false_positive"],
        ["Cokoliv jiného (Resolved, …)", "closed"],
    ],
    col_widths=[3.0, 4.0],
)
doc.add_paragraph(
    "K uzavření je automaticky přidán komentář s informací o analytikovi a důvodu uzavření."
)

add_heading(doc, "7.2 Flowmon ADS → XSIAM", 2)
doc.add_paragraph(
    "Při příštím mirror sync (get-remote-data) integrace zkontroluje stav ADS eventu:"
)
add_table(doc,
    ["Flowmon ADS status", "Akce v XSIAM"],
    [
        ["closed", "Alert uzavřen s důvodem Resolved"],
        ["false_positive", "Alert uzavřen s důvodem False Positive"],
        ["open / investigating", "Žádná akce"],
    ],
    col_widths=[3.0, 4.0],
)

doc.add_page_break()

# ── 8. Vlastní pole ───────────────────────────────────────────────────────────
add_heading(doc, "8. Vlastní pole incidentu", 1)
add_table(doc,
    ["CLI název", "Zobrazovaný název", "Typ", "Popis"],
    [
        ["flowmonadseventid", "Flowmon ADS Event ID", "Text", "Identifikátor ADS eventu"],
        ["flowmonadseventtype", "Flowmon ADS Event Type", "Text", "Typ eventu (např. ANOMALY)"],
        ["flowmonadspriority", "Flowmon ADS Priority", "Číslo", "Priorita 1–5"],
        ["flowmonadsinterest", "Flowmon ADS Interest Score", "Číslo", "Skóre neobvyklosti 0–1"],
        ["flowmonadssourceip", "Flowmon ADS Source IP", "Text", "Zdrojová IP adresa"],
        ["flowmonadssourcehostname", "Flowmon ADS Source Hostname", "Text", "Přeložený hostname zdroje"],
        ["flowmonadsourcecountry", "Flowmon ADS Source Country", "Text", "Země zdrojové IP"],
        ["flowmonadstargetips", "Flowmon ADS Target IPs", "Text", "Cílové IP adresy (čárkou oddělené)"],
        ["flowmonadsdetectionmodel", "Flowmon ADS Detection Model", "Text", "Kód detekčního modelu"],
        ["flowmonadsnfsource", "Flowmon ADS NetFlow Source", "Text", "NetFlow zdroj (kolektor/kanál)"],
        ["flowmonadsperspectives", "Flowmon ADS Perspectives", "Text", "Perspektivy (čárkou oddělené názvy)"],
        ["flowmonadstechniques", "Flowmon ADS MITRE Techniques", "Text", "MITRE ATT&CK techniky (např. T1046)"],
    ],
    col_widths=[2.2, 2.2, 1.0, 2.6],
)

doc.add_page_break()

# ── 9. Layout detailu alertu ──────────────────────────────────────────────────
add_heading(doc, "9. Layout detailu alertu", 1)
doc.add_paragraph(
    "Layout Flowmon ADS Event organizuje detail alertu do tří záložek:"
)
add_table(doc,
    ["Záložka", "Sekce", "Zobrazená pole"],
    [
        ["Summary", "Network Context", "Source IP, Source Hostname, Source Country, Target IPs, NetFlow Source, Perspectives"],
        ["Summary", "Detection Details", "Priority, Interest Score, Detection Model, Event Type, Event ID, MITRE Techniques"],
        ["MITRE ATT&CK", "ATT&CK Techniques", "MITRE Technique (full-width), MITRE Tactic (full-width), Flowmon Techniques (full-width)"],
        ["War Room", "War Room", "Komentáře a akce analytiků"],
    ],
    col_widths=[1.5, 2.0, 3.5],
)

doc.add_page_break()

# ── 10. Filtrování podle perspektivy ─────────────────────────────────────────
add_heading(doc, "10. Filtrování podle perspektivy", 1)
doc.add_paragraph(
    "Parametr Perspective Name v konfiguraci integrace umožňuje omezit fetch "
    "pouze na eventy z konkrétní ADS perspektivy."
)
add_heading(doc, "Jak funguje filtr", 2)
for item in [
    "Jméno perspektivy se předá do GET /rest/ads/events jako serverový filtr (search.perspective=ID) — "
    "pozn.: serverový filtr pracuje s ID, proto integrace aplikuje i klientský filtr podle jména jako pojistku.",
    "Po získání odpovědi integrace zkontroluje pole perspectives každého eventu "
    "a zahrne pouze ty, jejichž perspectives obsahují perspektivu se shodným názvem.",
    "Pokud pole zůstane prázdné, jsou fetchovány eventy ze všech perspektiv.",
]:
    p = doc.add_paragraph(item, style="List Bullet")
    p.runs[0].font.size = Pt(10)

doc.add_paragraph("")
doc.add_paragraph(
    "Příklad: zadej Security issues pro omezení pouze na bezpečnostní perspektivu."
)

doc.add_page_break()

# ── 11. Troubleshooting ───────────────────────────────────────────────────────
add_heading(doc, "11. Řešení problémů", 1)
add_table(doc,
    ["Problém", "Pravděpodobná příčina", "Řešení"],
    [
        ["Test module selže", "Špatné přihlašovací údaje nebo URL", "Ověř URL a credentials v konfiguraci instance"],
        ["Žádné eventy se nefetchují", "Perspective Name neodpovídá žádné perspektivě", "Zkontroluj přesný název perspektivy přes příkaz flowmon-ads-perspectives-get"],
        ["Alert se nezavírá ve Flowmonu", "Flowmon API nepodporuje PUT /rest/ads/event/{id}", "Integrace se pokusí přidat komentář jako fallback – zkontroluj logy"],
        ["[object Object] v layoutu", "Pole v layoutu mapuje na rawJSON objekt místo custom field", "Ujisti se, že layout používá incident_flowmonadsperspectives (ne rawJSON.perspectives)"],
        ["Layout se nezobrazuje správně", "Chybí Layout Rule", "Vytvoř pravidlo ručně v Settings → Alert Layout Rules"],
    ],
    col_widths=[2.0, 2.5, 2.5],
)

doc.add_page_break()

# ── 12. Historie verzí ────────────────────────────────────────────────────────
add_heading(doc, "12. Historie verzí", 1)
add_table(doc,
    ["Verze", "Změny"],
    [
        ["1.0.0", "Počáteční release – základní fetch, příkazy, mirroring"],
        ["1.0.2", "Oprava formátu occurred timestampu (RFC3339)"],
        ["1.0.3", "Vylepšení mapování severity, pole Description, Security domain"],
        ["1.0.4", "Přidání hostname/MITRE polí, vlastní layout, odstranění šumových raw polí"],
        ["1.0.5", "Parametr Perspective Name pro filtrování fetchovaných eventů"],
        ["1.0.6", "Vylepšený layout alertu – 2-sloupcový grid, reorganizace sekcí"],
    ],
    col_widths=[1.2, 5.8],
)

# Save
doc.save(OUTPUT)
print(f"Dokumentace uložena: {OUTPUT}")
