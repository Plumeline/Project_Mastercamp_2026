import os
import json
import pandas as pd
import re
from datetime import datetime

def consolidation():
    # Recherche du dossier data (sur le bureau ou en relatif)
    base_dir = os.path.expanduser("~/Desktop/data")
    if not os.path.exists(base_dir):
        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "data"))
        if not os.path.exists(base_dir):
            base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "data"))

    avis_dir = os.path.join(base_dir, "Avis") if os.path.exists(os.path.join(base_dir, "Avis")) else os.path.join(base_dir, "avis")
    alertes_dir = os.path.join(base_dir, "alertes")
    bulletin_dirs = [avis_dir, alertes_dir]
    mitre_dir = os.path.join(base_dir, "mitre")
    first_dir = os.path.join(base_dir, "first")

    rows = []

    def charger_json_sans_extension(dossier, cve_id):
        for nom in [cve_id, f"{cve_id}.json"]:
            chemin = os.path.join(dossier, nom)
            if os.path.exists(chemin):
                try:
                    with open(chemin, encoding="utf-8") as f:
                        return json.load(f)
                except Exception as e:
                    print(f"[!] Erreur lecture fichier {chemin} → {e}")
        return None

    def convertir_float(val):
        try:
            return float(val)
        except:
            return None

    def formater_date(date_str):
        try:
            return datetime.fromisoformat(date_str.replace("Z", "")).strftime("%Y-%m-%d")
        except:
            return date_str

    for folder in bulletin_dirs:
        if not os.path.exists(folder):
            print(f"[✘] Dossier manquant : {folder}")
            continue

        print(f"\nLecture de {folder}")
        fichiers = os.listdir(folder)
        total_files = len(fichiers)
        print(f"Fichiers trouvés : {total_files}")

        for idx, file in enumerate(fichiers):
            if idx % 5000 == 0:
                print(f"➡ [{os.path.basename(folder)}] {idx} / {total_files} fichiers traités...")

            full_path = os.path.join(folder, file)
            if not os.path.isfile(full_path):
                continue

            with open(full_path, encoding="utf-8") as f:
                try:
                    bulletin = json.load(f)
                except Exception as e:
                    print(f"[!] Erreur lecture JSON {file} : {e}")
                    continue

            bulletin_id = os.path.splitext(file)[0]
            titre = bulletin.get("title", "")
            type_bulletin = "Alerte" if "alertes" in folder.lower() else "Avis"
            description = bulletin.get("description", "")

            ref_cert = bulletin.get("reference", "")
            lien_bulletin = ""
            if ref_cert.startswith("CERTFR"):
                type_url = "avis" if "AVI" in ref_cert else "alerte"
                lien_bulletin = f"https://www.cert.ssi.gouv.fr/{type_url}/{ref_cert}/"

            cves = bulletin.get("cves", [])
            if not cves:
                texte = json.dumps(bulletin)
                cve_matches = set(re.findall(r"CVE-\d{4}-\d{4,7}", texte))
                cves = [{"name": cve} for cve in cve_matches]

            for cve in cves:
                cve_id = cve.get("name", "")
                if not cve_id:
                    continue

                cvss = base_severity = cwe = vendor = product = versions = mitre_desc = date_pub_mitre = ""
                mitre = charger_json_sans_extension(mitre_dir, cve_id)
                if mitre:
                    try:
                        cve_metadata = mitre.get("cveMetadata", {})
                        date_pub_mitre = cve_metadata.get("datePublished", "")

                        metrics = mitre.get("containers", {}).get("cna", {}).get("metrics", [])
                        if metrics:
                            m = metrics[0]
                            cvss = m.get("cvssV3_1", {}).get("baseScore") or m.get("cvssV3_0", {}).get("baseScore")
                            base_severity = m.get("cvssV3_1", {}).get("baseSeverity") or m.get("cvssV3_0", {}).get("baseSeverity")

                        pt = mitre.get("containers", {}).get("cna", {}).get("problemTypes", [])
                        if pt and "descriptions" in pt[0]:
                            cwe = pt[0]["descriptions"][0].get("cweId") or pt[0]["descriptions"][0].get("value", "")

                        affected = mitre.get("containers", {}).get("cna", {}).get("affected", [])
                        if affected:
                            vendor = affected[0].get("vendor", "")
                            product = affected[0].get("product", "")
                            versions = ", ".join([v.get("version", "") for v in affected[0].get("versions", [])])

                        descs = mitre.get("containers", {}).get("cna", {}).get("descriptions", [])
                        if descs:
                            mitre_desc = descs[0].get("value", "")
                    except Exception as e:
                        print(f"[!] Erreur parsing MITRE {cve_id} : {e}")

                epss = ""
                first = charger_json_sans_extension(first_dir, cve_id)
                if first:
                    try:
                        epss = first.get("data", [{}])[0].get("epss", "")
                    except:
                        epss = ""

                date_pub_bulletin = bulletin.get("revision_date", "")
                date_pub = formater_date(date_pub_bulletin or date_pub_mitre)

                rows.append({
                    "ID Bulletin": bulletin_id,
                    "Titre": titre,
                    "Type": type_bulletin,
                    "Date publication": date_pub,
                    "CVE": cve_id,
                    "Score CVSS": convertir_float(cvss),
                    "Base Severity": base_severity,
                    "Type CWE": cwe,
                    "Score EPSS": convertir_float(epss),
                    "Lien bulletin": lien_bulletin,
                    "Description": mitre_desc or description,
                    "Vendor": vendor,
                    "Produit": product,
                    "Versions affectées": versions
                })

    df = pd.DataFrame(rows)
    output_path = os.path.join(os.path.dirname(__file__), "consolidated_cve_data.csv")
    df.to_csv(output_path, index=False, encoding="utf-8", float_format="%.2f")
    print(f"\nLignes dans le DataFrame : {len(df)}")
    print(f"Fichier généré : {output_path}")
