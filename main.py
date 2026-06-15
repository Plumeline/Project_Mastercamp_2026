# main.py

from RSS_extraction import get_rss_feed
from CVE_extraction import get_CVE_extraction
from Enrichissement_CVE import connect_API_CVE, connect_API_EPSS
from consolidation import consolidation

def main():
    print("=== Étape 1 : Extraction des flux RSS ANSSI (Démo) ===")
    try:
        get_rss_feed(display=True)
    except Exception as e:
        print(f"[!] Échec extraction RSS : {e}")

    print("\n=== Étape 2 : Extraction de CVE depuis un bulletin (Démo) ===")
    try:
        get_CVE_extraction(display=True)
    except Exception as e:
        print(f"[!] Échec extraction CVE : {e}")

    print("\n=== Étape 3 : Connexion API CVE et EPSS (Démo) ===")
    try:
        connect_API_CVE(display=True)
        connect_API_EPSS(display=True)
    except Exception as e:
        print(f"[!] Échec appels API : {e}")
    
    print("\n=== Étape 4 : Consolidation des données (Locale) ===")
    consolidation()

    print("\n=== Étape 5 : Génération d'alertes personnalisées ===")
    import os
    from alerting import check_and_alert
    csv_path = os.path.join(os.path.dirname(__file__), "consolidated_cve_data.csv")
    check_and_alert(
        csv_path=csv_path,
        target_vendor="Apache",
        target_product="Tomcat",
        recipient_email="responsable-securite@entreprise.com",
        min_cvss=8.0
    )

if __name__ == "__main__":
    main()
