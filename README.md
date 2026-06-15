# TD Final noté : Analyse des Avis et Alertes ANSSI avec Enrichissement des CVE
## Projet de Consolidation, Visualisation, Machine Learning et Alertes

Ce projet a été réalisé dans le cadre du cours de Python (EFREI 2026). Il consiste à concevoir un pipeline automatisé capable d'extraire, d'enrichir, d'analyser et de générer des alertes pour les vulnérabilités de sécurité publiées par l'ANSSI (CERT-FR).

---

## 📋 Table des Matières
1. [Contexte et Objectifs](#-contexte-et-objectifs)
2. [Installation et Prérequis](#-installation-et-prérequis)
3. [Structure du Projet](#-structure-du-projet)
4. [Description des Fichiers du Pipeline](#-description-des-fichiers-du-pipeline)
5. [Comment lancer le projet](#-comment-lancer-le-projet)
6. [Détails des Étapes Réalisées](#-détails-des-étapes-réalisées)

---

## 🎯 Contexte et Objectifs
Le projet répond aux objectifs suivants :
* **Extraire** les flux RSS des Avis et Alertes de l'ANSSI.
* **Identifier** les identifiants CVE uniques mentionnés dans chaque bulletin.
* **Enrichir** ces CVE à l'aide d'APIs externes :
  * **MITRE** (via `cveawg.mitre.org`) pour récupérer le score CVSS, le type CWE, l'éditeur (Vendor), le produit et les versions affectées.
  * **FIRST** (via `api.first.org`) pour récupérer le score EPSS (probabilité d'exploitation de la faille).
* **Consolider** les données Avis et Alertes dans un DataFrame unifié.
* **Visualiser et Analyser** la distribution de la gravité des failles et les corrélations (Étape 5).
* **Appliquer des modèles de Machine Learning** supervisé (Random Forest) et non supervisé (K-Means) (Étape 6).
* **Générer des alertes par e-mail** contenant des rapports de vulnérabilités critiques ($\ge 9.0$ CVSS) (Étape 7).

---

## ⚙️ Installation et Prérequis
### Prérequis
* Python 3.10+
* Jupyter Notebook ou VS Code avec l'extension Jupyter.

### Dépendances Python
Installez les bibliothèques requises en exécutant la commande suivante dans votre terminal :
```bash
pip install feedparser requests pandas numpy matplotlib seaborn scikit-learn
```

---

## 📂 Structure du Projet
Le projet est organisé comme suit :
* `main.py` : Point d'entrée principal pour exécuter le pipeline de consolidation.
* `RSS_extraction.py` : Extraction et nettoyage des données des flux RSS ANSSI.
* `CVE_extraction.py` : Extraction par expressions régulières (Regex) des CVE présents dans les bulletins.
* `Enrichissement_CVE.py` : Enrichissement des CVE en appelant les APIs de MITRE et FIRST (implémente un délai de sécurité pour le *Rate Limiting*).
* `consolidation.py` : Centralisation et formatage des données brutes en un tableau structuré unifié.
* `envoie_mail.py` : Script automatisé d'envoi d'e-mails pour notifier la présence de vulnérabilités critiques.
* `DataAnalysis.ipynb` : Le notebook d'analyse exploratoire, de visualisations avancées (visualisations temporelles, boxplots par éditeur, etc.) et de modélisation Machine Learning.
* `DataAnalysis.html` : Export HTML du notebook exécuté pour restitution finale.
* `backup/` : Dossier contenant les données de secours pré-téléchargées et nettoyées (`full_cleaned_AVIS.csv` et `full_cleaned_ALERT.csv`).

---

## 🛠️ Description des Fichiers du Pipeline

### 1. Extraction et Récupération des Données
* **`RSS_extraction.py`** : Se connecte aux flux RSS de l'ANSSI, extrait les caractéristiques importantes (Titre, Description, Date de publication, Lien du bulletin) et les nettoie.
* **`CVE_extraction.py`** : Navigue sur les pages/JSON des bulletins et extrait la liste des CVE associés en utilisant des expressions régulières (`CVE-\d{4}-\d{4,7}`).

### 2. Enrichissement et Sauvegarde
* **`Enrichissement_CVE.py`** : Pour chaque CVE, interroge les serveurs du MITRE et de FIRST. Afin de respecter la charte de bon usage des ressources et d'éviter les bannissements, un délai d'une seconde de pause (`sleep(1)`) est appliqué entre chaque requête d'API (Rate Limiting).
* **`consolidation.py`** : Regroupe les données extraites d'Avis et d'Alertes, formate les dates au format ISO, gère les valeurs manquantes, applique la logique de calcul de la classe de sévérité (`Base Severity` : *NONE, LOW, MEDIUM, HIGH, CRITICAL*), et génère la structure finale du DataFrame.

### 3. Visualisation, Modélisation et Alertes
* **`DataAnalysis.ipynb`** :
  * **Visualisations** : Contient 13 visualisations distinctes (distribution CVSS et EPSS, évolution cumulative dans le temps, boxplots par éditeur, barplot d'analyse des éditeurs distinguant les Avis et Alertes, top des versions affectées, matrice de corrélation, etc.).
  * **Machine Learning** :
    * *Clustering K-Means (Non supervisé)* : Partitionnement des vulnérabilités en 3 profils types selon la dangerosité et la probabilité d'exploitation (validé par la méthode du coude).
    * *Random Forest (Supervisé)* : Modèle prédictif mesurant la probabilité de criticité d'une faille, incluant une analyse de l'importance des variables.
* **`envoie_mail.py`** : Lit les jeux de données d'Avis et d'Alertes, filtre automatiquement les vulnérabilités critiques (CVSS $\ge 9.0$), formate un tableau récapitulatif élégant en HTML, et envoie une alerte automatique par e-mail en utilisant le protocole SMTP (sécurisé via TLS).

---

## 🚀 Comment lancer le projet

1. **Lancement du Pipeline (Étape 4 & Consolidation)** :
   Pour consolider les données et générer le fichier de données consolidées :
   ```bash
   python3 main.py
   ```

2. **Lancement du Notebook d'Analyse (Étapes 5 & 6)** :
   Ouvrez le notebook principal [DataAnalysis.ipynb](file:///Users/othmane/Desktop/Cours/MasterC/Project_Mastercamp_2026/DataAnalysis.ipynb) et exécutez toutes les cellules pour générer les graphiques interactifs et les modèles de Machine Learning.

3. **Envoi des Alertes par E-mail (Étape 7)** :
   Pour envoyer l'e-mail d'alerte des vulnérabilités critiques :
   ```bash
   python3 envoie_mail.py
   ```
   *(Note : Vous pouvez modifier l'adresse e-mail de réception et d'envoi dans le fichier `envoie_mail.py`)*.

---

## 📝 Auteurs
Projet réalisé de manière anonyme dans le cadre des rendus du TD de Langage Python (EFREI 2026).