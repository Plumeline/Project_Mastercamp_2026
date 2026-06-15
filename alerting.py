# alerting.py

import os
import pandas as pd
import smtplib
from email.mime.text import MIMEText

def generate_security_alert(row, recipient_email):
    """
    Génère un email formaté pour une alerte de sécurité concernant une CVE critique.
    """
    cve_id = row.get("CVE", "Non spécifié")
    titre = row.get("Titre", "Sans titre")
    cvss = row.get("Score CVSS", "N/A")
    severity = row.get("Base Severity", "N/A")
    cwe = row.get("Type CWE", "N/A")
    epss = row.get("Score EPSS", "N/A")
    vendor = row.get("Vendor", "N/A")
    product = row.get("Produit", "N/A")
    versions = row.get("Versions affectées", "N/A")
    lien = row.get("Lien bulletin", "N/A")
    description = row.get("Description", "Aucune description disponible.")

    subject = f"[ALERTE SÉCURITÉ CERT-FR] Vulnérabilité {severity} ({cve_id}) affectant {product}"
    
    body = f"""Bonjour,

Une vulnérabilité critique a été détectée dans votre périmètre technologique :

============================================================
DÉTAILS DE LA VULNÉRABILITÉ
============================================================
* Identifiant : {cve_id}
* Bulletin ANSSI : {titre}
* Gravité : {severity} (Score CVSS : {cvss}/10)
* Probabilité d'exploitation (EPSS) : {epss}
* Type CWE : {cwe}
* Lien du bulletin : {lien}

============================================================
PRODUIT AFFECTÉ
============================================================
* Éditeur : {vendor}
* Produit : {product}
* Versions impactées : {versions}

============================================================
DESCRIPTION
============================================================
{description}

============================================================
ACTION REQUISE
============================================================
Veuillez appliquer les correctifs recommandés par l'éditeur dès que possible.

Cordialement,
Votre équipe de Veille Cyber
"""
    
    return subject, body

def send_email_simulation(to_email, subject, body):
    """
    Simule l'envoi d'un email en l'affichant dans la console.
    Permet de valider la génération des alertes sans nécessiter un SMTP réel.
    """
    print("\n------------------------------------------------------------")
    print(f"📧 [SIMULATION D'ENVOI D'EMAIL]")
    print(f"De : veille-cyber@entreprise.com")
    print(f"À   : {to_email}")
    print(f"Objet : {subject}")
    print("------------------------------------------------------------")
    print(body)
    print("------------------------------------------------------------\n")

def check_and_alert(csv_path, target_vendor, target_product, recipient_email, min_cvss=9.0):
    """
    Vérifie le fichier CSV consolidé pour les vulnérabilités répondant aux critères
    et envoie des alertes de sécurité par email simulé.
    """
    if not os.path.exists(csv_path):
        print(f"[!] Fichier CSV {csv_path} introuvable. Veuillez d'abord exécuter la consolidation.")
        return

    df = pd.read_csv(csv_path)
    
    # Nettoyer les colonnes et filtrer
    df_filtered = df[
        (df["Vendor"].str.contains(target_vendor, case=False, na=False)) &
        (df["Produit"].str.contains(target_product, case=False, na=False)) &
        (df["Score CVSS"] >= min_cvss)
    ]
    
    # Éliminer les doublons de CVE pour ne pas envoyer plusieurs fois le même email
    df_filtered = df_filtered.drop_duplicates(subset=["CVE"])
    
    print(f"🔍 [Veille] Recherche d'alertes pour {target_vendor} {target_product} (CVSS >= {min_cvss})")
    print(f"➡ {len(df_filtered)} vulnérabilité(s) critique(s) trouvée(s).")
    
    for _, row in df_filtered.iterrows():
        subject, body = generate_security_alert(row, recipient_email)
        send_email_simulation(recipient_email, subject, body)

def main():
    # Exemple de démonstration
    csv_path = os.path.join(os.path.dirname(__file__), "consolidated_cve_data.csv")
    
    # Simuler des alertes pour Ivanti et Apache Tomcat qui sont présents dans le dataset de test
    check_and_alert(
        csv_path=csv_path,
        target_vendor="Apache",
        target_product="Tomcat",
        recipient_email="admin-sys@entreprise.com",
        min_cvss=8.0
    )

if __name__ == "__main__":
    main()
