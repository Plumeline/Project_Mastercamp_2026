import os
import pandas as pd
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def envoyer_email(to_email, sujet, contenu_html):
    from_email = "nom@gmail.com"
    mot_de_passe = "mdp d'application"

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
            print(f"[i] Email envoyé à {to_email}")
    except Exception as e:
        print(f"[x] Erreur envoi mail : {e}")


# --- Chargement des deux CSV
chemin_alertes = "backup/full_cleaned_ALERT.csv"
chemin_avis    = "backup/full_cleaned_AVIS.csv"

dfs = []
for chemin in [chemin_alertes, chemin_avis]:
    if os.path.exists(chemin):
        dfs.append(pd.read_csv(chemin))
        print(f"[i] Chargé : {chemin}")
    else:
        print(f"[X] Fichier introuvable : {chemin}")

if not dfs:
    print("[X] Aucun fichier trouvé, arrêt.")
    exit()

df = pd.concat(dfs, ignore_index=True)
df["cvss_score"] = pd.to_numeric(df["cvss_score"], errors="coerce")

# --- Filtrage (CVSS >= 9.0)
df_critiques = df[df["cvss_score"] >= 9.0].copy()

if df_critiques.empty:
    print("[i] Aucune vulnérabilité critique détectée.")
    exit()
else:
    print(f"[!] {len(df_critiques)} vulnérabilités critiques détectées.")

df_critiques = df_critiques.sort_values("cvss_score", ascending=False).head(10)

# --- Construction HTML mail
message_html = """
<h2>Vulnérabilités Critiques détectées</h2>
<p>Les vulnérabilités suivantes ont un score CVSS supérieur ou égal à 9.0 
et nécessitent une attention immédiate.</p>
<table border="1" cellpadding="5" cellspacing="0" style="border-collapse:collapse;">
<tr style="background-color:#D85A30;color:white;">
    <th>Produit</th>
    <th>CVE</th>
    <th>Score CVSS</th>
    <th>Sévérité</th>
    <th>Score EPSS</th>
    <th>Lien bulletin</th>
</tr>
"""

for _, ligne in df_critiques.iterrows():
    produit  = ligne.get("product", "Inconnu")
    cve      = ligne.get("cve_id", "Inconnu")
    score    = ligne.get("cvss_score", "N/A")
    severite = ligne.get("cwe", "N/A")
    epss     = ligne.get("epss_score", "N/A")
    lien     = ligne.get("link", "#")

    message_html += f"""
    <tr>
        <td>{produit}</td>
        <td><b>{cve}</b></td>
        <td style="color:#D85A30;font-weight:bold;">{score}</td>
        <td>{severite}</td>
        <td>{epss}</td>
        <td><a href="{lien}">Voir le bulletin</a></td>
    </tr>"""

message_html += """
</table>
<p>Veuillez corriger ces vulnérabilités dès que possible.</p>
<p><i>Ce message a été généré automatiquement par le pipeline ANSSI CVE.</i></p>
"""

# --- Affichage du mail test
print("\n=== APERÇU DU MAIL ===")
print(f"Sujet : Alerte - {len(df_critiques)} vulnérabilités critiques détectées")
print(f"Destinataire : destinataire@email.com")
print(f"Nombre de CVE dans le mail : {len(df_critiques)}")
print("Corps HTML généré avec succès.")

# --- Envoi réel 
envoyer_email(
    to_email="destinataire@email.com",
     sujet=f"Alerte - {len(df_critiques)} vulnérabilités critiques détectées",
     contenu_html=message_html
 )
