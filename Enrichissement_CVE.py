import os
import json
import requests
import re
import time
def enrichissement():
    os.makedirs("data/mitre", exist_ok=True)
    os.makedirs("data/first", exist_ok=True)
    
    bulletin_dirs = ["data/avis", "data/alertes"]
    
    cve_pattern = r"CVE-\d{4}-\d{4,7}"
    cve_trouvees = set()
    
    for folder in bulletin_dirs:
        if not os.path.exists(folder):
            continue
    
        for file in os.listdir(folder):
            if not file.endswith(".json"):
                continue
    
            with open(os.path.join(folder, file), encoding="utf-8") as f:
                try:
                    contenu = json.load(f)
                except:
                    continue
                texte = json.dumps(contenu)
                cves = re.findall(cve_pattern, texte)
                cve_trouvees.update(cves)
    
    for cve_id in sorted(cve_trouvees):
        print(f" Traitement de {cve_id}")
    
        mitre_path = os.path.join("data/mitre", f"{cve_id}.json")
        if not os.path.exists(mitre_path):
            try:
                url_mitre = f"https://cveawg.mitre.org/api/cve/{cve_id}"
                response = requests.get(url_mitre, timeout=10)
                response.raise_for_status()
                with open(mitre_path, "w", encoding="utf-8") as f:
                    f.write(response.text)
                print(f"[✔] MITRE OK → {mitre_path}")
            except Exception as e:
                print(f"[✘] MITRE FAIL → {e}")
    
        first_path = os.path.join("data/first", f"{cve_id}.json")   
        if not os.path.exists(first_path):
            try:
                url_epss = f"https://api.first.org/data/v1/epss?cve={cve_id}"
                response = requests.get(url_epss, timeout=10)
                response.raise_for_status()
                with open(first_path, "w", encoding="utf-8") as f:
                    f.write(response.text)
                print(f"[✔] FIRST OK → {first_path}")
            except Exception as e:
                print(f"[✘] FIRST FAIL → {e}")
    
        time.sleep(1)
        
        

def get_CSS_data(cve_id, display = False):
    import requests
    #cve_id = "CVE-2023-24488"
    url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
    response = requests.get(url)
    data = response.json()
    # Extraire la description
    description = data["containers"]["cna"]["descriptions"][0]["value"]
    # Extraire le score CVSS
    #ATTENTION tous les CVE ne contiennent pas nécessairement ce champ, gérez l’exception,
    #ou peut etre au lieu de cvssV3_0 c’est cvssV3_1 ou autre clé
    cvss_score =data["containers"]["cna"]["metrics"][0]["cvssV3_1"]["baseScore"]
    cwe = "Non disponible"
    cwe_desc="Non disponible"
    problemtype = data["containers"]["cna"].get("problemTypes", {})
    if problemtype and "descriptions" in problemtype[0]:
        cwe = problemtype[0]["descriptions"][0].get("cweId", "Non disponible")
        cwe_desc=problemtype[0]["descriptions"][0].get("description", "Non disponible")
    # Extraire les produits affectés
    affected = data["containers"]["cna"]["affected"]
    for product in affected:
        vendor = product["vendor"]
        product_name = product["product"]
        versions = [v["version"] for v in product["versions"] if v["status"] == "affected"]
        if(display):
            print(f"Éditeur : {vendor}, Produit : {product_name}, Versions : {', '.join(versions)}")

    # Afficher les résultats
    if (display):
        print(f"CVE : {cve_id}")
        print(f"Description : {description}")
        print(f"Score CVSS : {cvss_score}")
        print(f"Type CWE : {cwe}")
        print(f"CWE Description : {cwe_desc}")

    return [cve_id, description, cvss_score, cwe, cwe_desc, affected]

def get_EPSS_data(cve_id, display = False):

    import requests
    # URL de l'API EPSS pour récupérer la probabilité d'exploitation
    #cve_id = "CVE-2023-46805"
    url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
    # Requête GET pour récupérer les données JSON
    response = requests.get(url)
    data = response.json()
    # Extraire le score EPSS
    epss_data = data.get("data", [])
    if epss_data:
        epss_score = epss_data[0]["epss"]

        if display:
            print(f"CVE : {cve_id}")
            print(f"Score EPSS : {epss_score}")
        return [cve_id, epss_score]
    else:
        if display:
            print(f"Aucun score EPSS trouvé pour {cve_id}")

    return [cve_id, -1]