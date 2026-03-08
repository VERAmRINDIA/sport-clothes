# Cartographie CI – sport-clothes

## Objectif
Ce document décrit la structure du projet et les commandes nécessaires pour configurer une pipeline CI (Jenkins) reproductible.

---

## Structure du projet
- **Backend** : Node/Express  
  - Fichier d’entrée : `server.js`
- **Frontend** : statique (HTML + images)  
  - Dossier : `public/`
  - Servi par le backend via :
    - `app.use(express.static('public'));`

---

## Scripts npm (package.json)
- **start** : `node server.js`
- **dev** : `node server.js`
- **test** : `node -e "console.log('No tests yet')"` (pas de vrais tests pour le moment)

---

## Commandes CI (à exécuter dans Jenkins)
### Installation
- `npm ci`

### Tests
- `npm test`  
  > Actuellement, ce script affiche seulement "No tests yet".

### Notes CI
- Il n’y a pas de build React à exécuter dans ce repo (frontend déjà statique dans `public/`).

---

## Configuration (variables d’environnement)
Le serveur vérifie la présence de :
- `MONGODB_URI` : URI de connexion à MongoDB  
  - Warning si non défini : `MONGODB_URI not set`
- `SESSION_SECRET` : secret pour sécuriser les sessions  
  - Warning si non défini : `SESSION_SECRET not set`

### Port
- `PORT` est optionnel. Par défaut :
  - `const PORT = process.env.PORT || 3000;`
- Le serveur démarre sur :
  - `http://localhost:3000` (si `PORT` non défini)

---

## Services externes
- **Base de données** : MongoDB (via `MONGODB_URI`)

---

## État actuel / améliorations recommandées
- ✅ Pipeline CI possible : `npm ci` + `npm test`
- ⚠️ Aucun vrai test automatisé pour le moment  
  → Ajouter des tests (ex: Jest + Supertest) pour rendre la CI utile.
- (Optionnel) Ajouter un linter (ESLint) pour améliorer la qualité du code.

---

## Jenkinsfile MVP (exemple)
```groovy
pipeline {
  agent any

  stages {
    stage('Checkout') {
      steps { checkout scm }
    }

    stage('Install') {
      steps { sh 'npm ci' }
    }

    stage('Test') {
      steps { sh 'npm test' }
    }
  }
}
