import os
import pandas as pd
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def envoyer_email(to_email, sujet, contenu_html):
    from_email = "mon_mail@email.com"
    mot_de_passe = "mdp_générée_sur_compte"

    message = MIMEMultipart("alternative")
    message["From"] = from_email
    message["To"] = to_email
    message["Subject"] = sujet

    message.attach(MIMEText(contenu_html, "html"))

    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as serveur:
            serveur.starttls()
            serveur.login(from_email, mot_de_passe)
            serveur.sendmail(from_email, to_email, message.as_string())
            print(f"[✔] Email envoyé à {to_email}")
    except Exception as e:
        print(f"[✘] Erreur envoi mail : {e}")

chemin_script = os.path.dirname(os.path.abspath(__file__))
chemin_csv = os.path.join(chemin_script, "consolidated_cve_data.csv")

if not os.path.exists(chemin_csv):
    print(f"[✘] Fichier introuvable : {chemin_csv}")
    exit()

df = pd.read_csv(chemin_csv)
df_critiques = df[df["Score CVSS"] >= 10.0]

if df_critiques.empty:
    print("[ℹ] Aucune vulnérabilité critique détectée.")
    exit()
else:
    print(f"[!] {len(df_critiques)} vulnérabilités critiques détectées.")

df_critiques = df_critiques.head(10)

message_html = """
<h2>Vulnérabilités Critiques détectées</h2>
<table border="1" cellpadding="5" cellspacing="0">
<tr><th>Produit</th><th>CVE</th><th>Score</th><th>Lien</th></tr>
"""

for _, ligne in df_critiques.iterrows():
    produit = ligne.get("Produit", "Inconnu")
    cve = ligne.get("CVE", "Inconnu")
    score = ligne.get("Score CVSS", "N/A")
    lien = ligne.get("Lien bulletin", "#")

    message_html += f"<tr><td>{produit}</td><td>{cve}</td><td>{score}</td><td><a href='{lien}'>Lien</a></td></tr>"

message_html += "</table><p>Veuillez corriger ces vulnérabilités dès que possible.</p>"

destinataire = "destinataire@email.com"
