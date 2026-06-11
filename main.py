# main.py

from RSS_extraction import traiter_flux
from CVE_extraction import extraire_cves_depuis_fichiers
from Enrichissement_CVE import enrichissement
from consolidation import consolidation

def main():
    
    """
    print("=== Étape 1 : Téléchargement des bulletins ANSSI ===")
    traiter_flux("https://www.cert.ssi.gouv.fr/avis/feed", "avis")
    traiter_flux("https://www.cert.ssi.gouv.fr/alerte/feed", "alertes")

    print("\n=== Étape 2 : Extraction des CVE depuis les bulletins ===")
    extraire_cves_depuis_fichiers("avis")
    extraire_cves_depuis_fichiers("alertes")

    print("\n=== Étape 3 : Enrichissement (déjà exécuté dans le script Enrichissement_CVE.py) ===")
    enrichissement()
    """
    # Pour éviter de passer 30minutes a extraire tout les appels API
    
    
    print("\n=== Étape 4 : Consolidation des données enrichies ===")
    consolidation()

if __name__ == "__main__":
    main()
