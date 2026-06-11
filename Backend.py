#%%
import feedparser

def get_rss_feed(display = False):
    url = "https://www.cert.ssi.gouv.fr/actualite/feed/"
    rss_feed = feedparser.parse(url)

    #/avis/alerte/feed/
    #/actualite/feed/

    #display of the rss_feed

    if(display):
        for entry in rss_feed.entries:
            print("Titre :", entry.title)
            print("Description:", entry.description)
            print("Lien :", entry.link)
            print("Date :", entry.published)

    return rss_feed


#%%

import requests
import re
url = "https://www.cert.ssi.gouv.fr/alerte/CERTFR-2024-ALE-001/json/"
response = requests.get(url)
data = response.json()
#Extraction des CVE reference dans la clé cves du dict data
ref_cves=list(data["cves"])
#attention il s’agit d’une liste des dictionnaires avec name et url comme clés
print( "CVE référencés ", ref_cves)
# Extraction des CVE avec une regex
cve_pattern = r"CVE-\d{4}-\d{4,7}"
cve_list = list(set(re.findall(cve_pattern, str(data))))
print("CVE trouvés :", cve_list)


#%%

# API CVE ________________________________________________________________

def connect_API_CVE(display = False):
    import requests
    cve_id = "CVE-2023-24488"
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



# API EPSS _______________________________________________________________

def connect_API_EPSS(display = False):

    import requests
    # URL de l'API EPSS pour récupérer la probabilité d'exploitation
    cve_id = "CVE-2023-46805"
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
    else:
        if display:
            print(f"Aucun score EPSS trouvé pour {cve_id}")



            


