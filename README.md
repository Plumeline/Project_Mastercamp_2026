# Analyse des Avis et Alertes ANSSI avec Enrichissement des CVE

Ce projet permet de collecter, consolider, enrichir, visualiser et analyser les avis et alertes de sécurité émis par l'ANSSI (CERT-FR) à l'aide de techniques de Data Science et de Machine Learning.

---

## 📋 Architecture du Projet

Le projet est structuré de manière modulaire autour des scripts suivants :

1. **`main.py`** : Script d'orchestration principal qui exécute l'ensemble du pipeline (démo d'extraction, consolidation locale des données et simulation d'alertes).
2. **`RSS_extraction.py`** : Module d'extraction et parsing du flux RSS de l'ANSSI en utilisant la bibliothèque `feedparser`.
3. **`CVE_extraction.py`** : Module d'extraction des identifiants CVE depuis les avis et alertes (parsing du JSON de l'avis et détection par expressions régulières).
4. **`Enrichissement_CVE.py`** : Module de connexion aux APIs externes (MITRE pour le score CVSS/type CWE/produits affectés et FIRST pour la probabilité d'exploitation EPSS).
5. **`consolidation.py`** : Module central qui charge les fichiers locaux pré-téléchargés, extrait et enrichit les CVE, puis génère le fichier final de données consolidées au format CSV.
6. **`alerting.py`** : Système de veille et de notification. Il filtre les vulnérabilités critiques affectant des éditeurs/produits cibles et simule l'envoi d'emails d'alerte de sécurité.
7. **`DataAnalysis.ipynb` / `DataAnalysis.html`** : Notebook Jupyter (et son export HTML) contenant l'exploration des données, 9 visualisations graphiques avancées, et les modèles de Machine Learning.

---

## 🛠️ Installation des Dépendances

Les bibliothèques requises pour faire fonctionner ce projet sont répertoriées ci-dessous. Installez-les via `pip` :

```bash
pip install pandas numpy matplotlib seaborn scikit-learn feedparser requests jupyter
```

---

## 🚀 Utilisation

### 1. Lancement du Pipeline Principal
Pour lancer le pipeline complet (extraction de démo, consolidation globale de toutes les données locales et déclenchement des alertes pour Apache Tomcat) :

```bash
python3 main.py
```
Ce script génère le fichier `consolidated_cve_data.csv` contenant toutes les données d'avis, d'alertes, de MITRE et de FIRST consolidées.

### 2. Lancement du Système d'Alerte seul
Pour exécuter uniquement la simulation d'alertes de sécurité sur le périmètre de votre entreprise :

```bash
python3 alerting.py
```

### 3. Visualisation de l'Analyse des Données et du Machine Learning
Pour ouvrir le Notebook d'analyse :

```bash
jupyter notebook DataAnalysis.ipynb
```
Vous pouvez également ouvrir directement le fichier pré-calculé **`DataAnalysis.html`** dans n'importe quel navigateur web pour consulter les analyses et graphiques.

---

## 📊 Exploration et Visualisation des Données
Le notebook génère 9 visualisations interactives et statiques de haute qualité :
- **Distribution des scores CVSS** : Analyse de la répartition de la sévérité globale.
- **Répartition par sévérité (Severity)** : Histogramme des niveaux de risque (Critical, High, Medium, Low).
- **Top 10 CWE** : Classement des faiblesses logicielles les plus courantes.
- **Distribution EPSS** : Analyse de la probabilité d'exploitation des vulnérabilités dans le monde réel (échelle log).
- **Top 10 Éditeurs** : Identification des éditeurs de logiciels subissant le plus de signalements.
- **Heatmap de corrélation** : Corrélation statistique entre la sévérité intrinsèque (CVSS) et la menace réelle (EPSS).
- **Nuage de points CVSS vs EPSS** : Analyse croisée du niveau de dangerosité.
- **Évolution temporelle** : Chronologie du nombre de vulnérabilités publiées mensuellement.
- **Boxplot de dispersion** : Analyse de la répartition des scores CVSS selon le niveau de sévérité.

---

## 🤖 Modèles de Machine Learning implémentés

### 1. Apprentissage Non Supervisé (Clustering)
- **Algorithme** : K-Means appliqué sur les variables standardisées `Score CVSS` et `Score EPSS`.
- **Méthode du coude (Elbow Method)** : Utilisée pour identifier le nombre optimal de clusters ($K=3$).
- **Objectif** : Segmenter les vulnérabilités en 3 niveaux de menace opérationnelle (ex: Menace Théorique vs Menace Active Elevée vs Menace Critique Imminente).

### 2. Apprentissage Supervisé (Classification)
- **Algorithme** : Random Forest Classifier.
- **Cible** : Prédire si une vulnérabilité présente une **gravité extrême (CVSS >= 9.0, soit 'CRITICAL')**.
- **Variables explicatives (Features)** : Score EPSS, Type de bulletin ANSSI (Avis ou Alerte), Encodage one-hot des 10 CWE et 10 Éditeurs les plus fréquents.
- **Validation** : Division Train/Test (70/30), rapport de classification (Précision, Rappel, F1-Score) et heatmap de la matrice de confusion.

---

## 🔒 Anonymisation
Conformément aux instructions du projet, tous les fichiers et métadonnées du projet sont totalement anonymes et exempts d'informations personnelles ou d'indications d'auteurs.