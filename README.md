# PhishGuard AI

PhishGuard AI est une application de detection de sites web de phishing basee sur le machine learning. Le projet combine un pipeline d'extraction de caracteristiques URL/HTML, un modele LightGBM, une API FastAPI, un tableau de bord de supervision et une interface web pour l'analyse interactive d'URL.

## Vue d'ensemble

Le projet repond a un besoin simple : prendre une URL en entree et renvoyer un verdict exploitable en quelques centaines de millisecondes.

Pour y parvenir, l'application :

- extrait 45 caracteristiques alignees avec le modele entraine ;
- combine des signaux statiques de l'URL et des signaux dynamiques issus du HTML ;
- applique une inference LightGBM avec explicabilite locale via SHAP ;
- qualifie le niveau de risque (`low`, `medium`, `high`, `critical`) ;
- journalise les analyses dans SQLite pour alimenter le dashboard ;
- peut recouper le resultat avec VirusTotal si une cle API est configuree.

## Fonctionnalites principales

- Analyse d'URL en temps reel via `POST /api/v1/analyze`
- Explicabilite locale avec les principales variables contributrices
- Dashboard de supervision via `GET /api/v1/stats` et `/dashboard`
- Journalisation des scans dans `phishguard.db`
- Validation d'entree/sortie avec Pydantic
- Frontend web pour la saisie, la lecture des resultats et l'export PDF cote navigateur
- Integration optionnelle VirusTotal
- Allowlist de domaines de confiance avec surcharge du verdict

## Architecture technique

```text
Utilisateur / Frontend
        |
        v
FastAPI (src/api/app.py)
        |
        v
Service d'analyse (src/api/services.py)
        |
        +--> FeatureBuilder
        |      +--> URL features (19)
        |      +--> HTML features (26)
        |
        +--> PhishingPredictor
        |      +--> Pipeline sklearn + LightGBM
        |      +--> SHAP TreeExplainer
        |
        +--> VirusTotal (optionnel)
        |
        +--> SQLite logging / dashboard stats
```

## Techniques et technologies utilisees

| Domaine | Technologies |
| --- | --- |
| Langage | Python 3 |
| API | FastAPI, Uvicorn, Pydantic |
| ML | Scikit-learn, LightGBM, SHAP, Joblib |
| Data | Pandas, NumPy |
| Scraping / fetch | Requests, BeautifulSoup4 |
| Persistence | SQLite |
| Frontend | HTML, CSS, JavaScript |
| Documentation | Markdown, Pandoc |
| Tests | Pytest, httpx, unittest.mock |

## Pipeline ML

Le notebook d'experimentation est conserve dans `notebook_ML.ipynb`, tandis que `export_model.py` sert de script de reconstruction des artefacts de production.

### Strategie d'entrainement

- Dataset : `PhiUSIIL_Phishing_URL_Dataset`
- Cible : `label`
- Scenario exporte : `Case 4 - group split by domain, suspect features removed`
- Split : `GroupShuffleSplit` par domaine pour eviter les fuites entre train et test
- Modele : `LGBMClassifier`
- Serialisation : `artifacts/phishing_model.joblib`, `artifacts/input_features.joblib`, `artifacts/metadata.json`

### Hyperparametres exportes

| Parametre | Valeur |
| --- | --- |
| `n_estimators` | `200` |
| `learning_rate` | `0.1` |
| `num_leaves` | `15` |
| `max_depth` | `10` |
| `min_child_samples` | `30` |
| `subsample` | `0.8` |
| `colsample_bytree` | `1.0` |

### Metriques enregistrees dans les artefacts

Les valeurs ci-dessous proviennent de `artifacts/metadata.json` genere le 10 avril 2026.

| Metrique | Valeur |
| --- | --- |
| Accuracy | `0.999957` |
| Precision | `0.999926` |
| Recall | `1.0` |
| F1-score | `0.999963` |
| ROC-AUC | `1.0` |
| PR-AUC | `1.0` |
| Echantillons train | `189074` |
| Echantillons test | `46721` |

Ces scores sont excellents sur le dataset offline, mais ils ne remplacent pas une evaluation continue sur des cas reels en production.

## Ingenierie de caracteristiques

Le modele utilise 45 variables :

- 19 features URL dans `src/features/url_features.py`
- 26 features HTML/DOM dans `src/features/html_features.py`

### Exemples de signaux URL

- longueur de l'URL ;
- longueur du domaine ;
- presence d'une IP en guise de domaine ;
- nombre de sous-domaines ;
- ratio de caracteres speciaux ;
- presence d'obfuscation `%XX` ;
- utilisation de HTTPS.

### Exemples de signaux HTML

- presence d'un titre et d'une meta description ;
- nombre de redirections ;
- presence d'iframe, de popups et de scripts ;
- champs caches ou mot de passe ;
- formulaires vers un domaine externe ;
- nombre de liens internes, vides et externes ;
- mots-cles lies a la banque, au paiement ou a la crypto.

### Alignement train / inference

`src/features/feature_builder.py` garantit que le DataFrame d'inference suit exactement l'ordre des colonnes enregistrees dans `artifacts/input_features.joblib`. Cette contrainte est critique pour eviter tout decalage silencieux entre entrainement et production.

## Logique de prediction

La classe `PhishingPredictor` dans `src/models/predict.py` :

- charge les artefacts a la demande ;
- reconstruit un DataFrame conforme au schema attendu ;
- calcule `predict_proba` ;
- utilise un seuil de `0.40` sur la probabilite de phishing ;
- calcule les principales contributions locales avec SHAP ;
- retourne un verdict `phishing` ou `legitimate`.

### Regles complementaires cote service

`src/api/services.py` ajoute des regles metier autour du modele :

- allowlist de domaines de confiance via `top_domains.txt` ;
- surcharge en `legitimate` si l'URL appartient a la liste de confiance ;
- surcharge possible en `phishing` si VirusTotal retourne des detections positives ;
- calcul du niveau de risque a partir du score final.

## Backend et API

### Endpoints principaux

| Methode | Route | Role |
| --- | --- | --- |
| `GET` | `/` | Interface principale |
| `GET` | `/dashboard` | Tableau de bord |
| `GET` | `/api/v1/health` | Etat de l'API et du modele |
| `GET` | `/api/v1/stats` | Statistiques globales |
| `POST` | `/api/v1/analyze` | Analyse complete d'une URL |
| `GET` | `/docs` | Documentation Swagger |

### Exemple de requete

```bash
curl -X POST http://localhost:8000/api/v1/analyze ^
  -H "Content-Type: application/json" ^
  -d "{\"url\":\"https://example.com/login\"}"
```

### Exemple de reponse

```json
{
  "url": "https://example.com/login",
  "verdict": "phishing",
  "is_phishing": true,
  "confidence": 0.93,
  "risk_level": "critical",
  "top_features": [],
  "fetch_info": {
    "html_available": true,
    "final_url": "https://example.com/login",
    "redirect_count": 0,
    "error_message": ""
  },
  "virustotal_report": null,
  "analysis_duration_ms": 214.3
}
```

## Frontend

Le frontend est situe dans `frontend/` et fournit :

- un scanner d'URL ;
- un affichage visuel du verdict et du score ;
- un historique local via `localStorage` ;
- un rendu des signaux SHAP ;
- un export PDF cote navigateur via `html2pdf.js`.

Le dashboard affiche les indicateurs agreges stockes dans SQLite : volume de scans, ratio phishing, moyenne des scores et dernieres URLs analysees.

## Base de donnees et monitoring

`src/api/db.py` initialise automatiquement `phishguard.db` et enregistre pour chaque scan :

- horodatage ;
- URL ;
- verdict ;
- score de confiance ;
- niveau de risque ;
- duree d'analyse ;
- JSON des principales features explicatives.

Cette base permet de transformer le projet en application supervisable plutot qu'en simple demo de modele.

## Arborescence du projet

```text
.
|-- artifacts/
|   |-- input_features.joblib
|   |-- metadata.json
|   `-- phishing_model.joblib
|-- frontend/
|   |-- static/
|   |   |-- script.js
|   |   `-- style.css
|   `-- templates/
|       |-- dashboard.html
|       `-- index.html
|-- src/
|   |-- api/
|   |   |-- app.py
|   |   |-- db.py
|   |   |-- schemas.py
|   |   |-- services.py
|   |   `-- top_domains.txt
|   |-- features/
|   |   |-- feature_builder.py
|   |   |-- html_features.py
|   |   `-- url_features.py
|   |-- models/
|   |   `-- predict.py
|   `-- config.py
|-- tests/
|-- export_model.py
|-- main.py
|-- notebook_ML.ipynb
|-- RAPPORT.md
`-- requirements.txt
```

## Installation

### 1. Creer et activer l'environnement virtuel

```bash
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### 2. Installer les dependances

```bash
pip install -r requirements.txt
```

### 3. Configurer les variables d'environnement

Copier `.env.example` vers `.env`, puis ajuster les valeurs si necessaire.

Variables utiles :

| Variable | Role | Defaut |
| --- | --- | --- |
| `ARTIFACTS_DIR` | dossier des artefacts du modele | `artifacts` |
| `FETCH_TIMEOUT` | timeout HTTP | `10` |
| `FETCH_RETRIES` | nombre de tentatives de fetch | `2` |
| `RISK_LOW_MAX` | seuil risque faible | `0.3` |
| `RISK_MEDIUM_MAX` | seuil risque moyen | `0.6` |
| `RISK_HIGH_MAX` | seuil risque eleve | `0.85` |
| `API_HOST` | hote FastAPI | `0.0.0.0` |
| `API_PORT` | port FastAPI | `8000` |
| `API_RELOAD` | auto-reload dev | `true` |
| `CORS_ORIGINS` | origines autorisees | `*` |
| `VIRUSTOTAL_API_KEY` | cle API optionnelle | vide |

## Execution

### Re-entrainer et exporter les artefacts

```bash
python export_model.py --dataset "C:\PhiUSIIL_Phishing_URL_Dataset.csv"
```

### Lancer l'application

```bash
python main.py
```

Puis ouvrir :

- `http://localhost:8000/`
- `http://localhost:8000/dashboard`
- `http://localhost:8000/docs`

## Tests

Executer la suite de tests :

```bash
.\venv\Scripts\pytest.exe -q
```

Les tests couvrent notamment :

- l'extraction des features URL ;
- l'extraction des features HTML ;
- l'assemblage du feature vector ;
- la prediction ;
- la sante de l'API.


## Limites actuelles

- les excellentes metriques offline ne garantissent pas le meme niveau de performance sur des URLs nouvelles et adversariales ;
- le fetch HTML repose sur `requests` avec `verify=False`, utile pour certains cas mais moins strict d'un point de vue TLS ;
- l'allowlist et la surcharge VirusTotal modifient le verdict du modele, ce qui doit etre connu lors de l'interpretation ;
- l'export PDF du frontend depend d'un script CDN externe ;
- il n'y a pas encore de pipeline CI/CD, de conteneurisation Docker ou de jeu de tests d'integration complet.

## Pistes d'amelioration

- ajouter une pipeline CI avec linting, tests et generation automatique des rapports ;
- conteneuriser l'application avec Docker ;
- versionner les artefacts de modele et les jeux d'evaluation ;
- renforcer le monitoring avec historisation temporelle, KPIs de drift et alerting ;
- internaliser les assets front pour supprimer la dependance CDN de l'export PDF.
