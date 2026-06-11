import os
import json
from time import sleep

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
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
    except Exception as e:
        print(f"[✘] Erreur lors de la récupération des données MITRE pour {cve_id}: {e}")
        return [cve_id, "Non disponible", "Non disponible", "Non disponible", "Non disponible", []]
    
    # Vérifier la structure de la réponse
    if "containers" not in data or "cna" not in data.get("containers", {}):
        print(f"[✘] Structure API invalide pour {cve_id}")
        return [cve_id, "Non disponible", "Non disponible", "Non disponible", "Non disponible", []]
    
    # Extraire la description
    try:
        description = data["containers"]["cna"]["descriptions"][0]["value"]
    except (KeyError, IndexError, TypeError):
        description = "Non disponible"
    # Extraire le score CVSS
    #ATTENTION tous les CVE ne contiennent pas nécessairement ce champ, gérez l’exception,
    #ou peut etre au lieu de cvssV3_0 c’est cvssV3_1 ou autre clé
    #print('data : ', data)

    #print(data["containers"]["cna"].keys())


    
    cvss_score = None
    try:
        # Chercher les données CVSS dans les différentes clés possibles
        metrics = data["containers"]["cna"].get("metrics", [])
        if metrics:
            cvss_score = metrics[0].get("cvssV3_1", {}).get("baseScore")
        
        # Si pas trouvé, chercher dans d'autres clés possibles
        if cvss_score is None:
            for key, value in data["containers"]["cna"].items():
                if isinstance(value, list) and len(value) > 0:
                    if isinstance(value[0], dict) and "cvssV3_1" in value[0]:
                        cvss_score = value[0]["cvssV3_1"].get("baseScore")
                        break
                    elif isinstance(value[0], dict) and "cvssV3_0" in value[0]:
                        cvss_score = value[0]["cvssV3_0"].get("baseScore")
                        break
        #Si après avoir fait tout ça on a toujours pas trouvé le cvss_score, on abandonne et le set a None
        if cvss_score is None:
            cvss_score = "Non disponible"
    except (KeyError, IndexError, TypeError):
        cvss_score = "Non disponible"

    #après le cvss score, on essaie de trouver le cwe
    cwe = "Non disponible"
    cwe_desc="Non disponible"

    #on cherche le type de problème dans data->containers->cna->problemTypes
    problemtype = data["containers"]["cna"].get("problemTypes", {})

    #on checke si problemType contient bien une liste non nulle
    if problemtype and isinstance(problemtype, list) and len(problemtype) > 0:
        #si on trouve la description dans le type de problème,
        if "descriptions" in problemtype[0]:
            #on peut affecter le cwe et sa description
            cwe = problemtype[0]["descriptions"][0].get("cweId", "Non disponible")
            cwe_desc=problemtype[0]["descriptions"][0].get("description", "Non disponible")
    
    # Extraire les produits affectés
    affected = []
    try:
        affected = data["containers"]["cna"].get("affected", [])
        for product in affected:
            vendor = product.get("vendor", "Non disponible")
            product_name = product.get("product", "Non disponible")
            versions = [v["version"] for v in product.get("versions", []) if v.get("status") == "affected"]
            if(display):
                print(f"Éditeur : {vendor}, Produit : {product_name}, Versions : {', '.join(versions)}")
    except (KeyError, IndexError, TypeError) as e:
        print(f"[✘] Erreur lors de l'extraction des produits affectés: {e}")

    # Afficher les résultats
    if (display):
        print(f"CVE : {cve_id}")
        print(f"Description : {description}")
        print(f"Score CVSS : {cvss_score}")
        print(f"Type CWE : {cwe}")
        print(f"CWE Description : {cwe_desc}")

    #dans tous les cas, on retournera une liste. En cas d'erreur, celle ci contiendre des None dans les colonnes
    # où la valeur ne pouvait pas être trouvée
    return [cve_id, description, cvss_score, cwe, cwe_desc, affected]




def get_EPSS_data(cve_id, display = False):

    import requests
    # URL de l'API EPSS pour récupérer la probabilité d'exploitation
    #cve_id = "CVE-2023-46805"
    url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
    try:
        # Requête GET pour récupérer les données JSON
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
    except Exception as e:

        print(f"[✘] Erreur lors de la récupération des données EPSS pour {cve_id}: {e}")
        return [cve_id, -1]
    
    # Extraire le score EPSS
    try:
        epss_data = data.get("data", [])
        if epss_data and isinstance(epss_data, list) and len(epss_data) > 0:
            epss_score = epss_data[0].get("epss", -1)

            if display:
                print(f"CVE : {cve_id}")
                print(f"Score EPSS : {epss_score}")
            return [cve_id, epss_score]
        else:
            if display:
                print(f"Aucun score EPSS trouvé pour {cve_id}")
    except (KeyError, IndexError, TypeError) as e:
        print(f"[x] Erreur lors de l'extraction du score EPSS: {e}")

    #si on arrive pas à obtenir la valeur, étant donné qu'il s'agit d'une probabilité, on utilise -1 comme signalétique
    # d'erreur
    return [cve_id, -1]


import CVE_extraction



def new_enrichissement(cve_id):
    """
    returns a list of the information taken from the APIs to be added to the dataset.
    The list is of the form :
    [cve_id, description, cvss_score, cwe, cwe_desc, affected, epss_score]

    :param cve_id: id of the cve whose information will be returned
    :return: a list of the information taken from the APIs to be added to the dataset.
    """

    epss = get_EPSS_data(cve_id)

    css = get_CSS_data(cve_id)

    css.append(epss[1])

    #On met un sleep pour éviter de bombarder le serveur de requêtes. Cela ralentit considérablement le processus,
    #mais évite de faire crasher le site hôte ou de se faire bannir à cause d'une tentative de DDOS involontaire.
    sleep(1)

    return css

def new_enrichissement_from_rss(rss):

    """
    Returns a structure of data of the form :
    {title_of_alert : list_of_CVES_information }
    the list_of_CVES_information is a list of lists. Each sublist is an output of the function new_enrichissment(cve_id)
    these sublists contain a list of the form :
    [cve_id, description, cvss_score, cwe, cwe_desc, affected, epss_score]

    :param rss: the data coming from the RSS_extraction function
    :return: a dictionnary which returns the extra info of each CVEs for each alert (n alerts and n*k CVEs info)
    """

    rss_CVEs = {}
    print("RSS : ",rss)
    for alert in rss:
        link = alert['link']
        cve_list = CVE_extraction.get_CVE_extraction(link)
        cves_enriched =[]

        for cve in cve_list :
            cves_enriched.append(new_enrichissement(cve))

        rss_CVEs[alert['title']] = cves_enriched

    return rss_CVEs


import RSS_extraction

test = RSS_extraction.get_cleaned_rss_feed(RSS_extraction.URL_AVIS)

rss_CEVs = new_enrichissement_from_rss(test)

print(rss_CEVs)