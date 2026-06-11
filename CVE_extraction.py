def get_CVE_extraction(url, display = False):
    import requests
    import re


    url+= "json/"
    response = requests.get(url)
    data = response.json()
    #Extraction des CVE reference dans la clé cves du dict data
    ref_cves=list(data["cves"])
    #attention il s’agit d’une liste des dictionnaires avec name et url comme clés

    if display:
        print( "CVE référencés ", ref_cves)
    # Extraction des CVE avec une regex
    cve_pattern = r"CVE-\d{4}-\d{4,7}"
    cve_list = list(set(re.findall(cve_pattern, str(data))))
    if display:
        print("CVE trouvés :", cve_list)
    return ref_cves, cve_list

#url = "https://www.cert.ssi.gouv.fr/alerte/CERTFR-2024-ALE-001/"
#a,b = get_CVE_extraction(url)
#print(a)