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

---

## Plan de travail – Jour 2 (objectif : CI Jenkins stable, sans déploiement)

### Objectif fin de journée (DoD)
- Un push sur GitHub (ou un scan Multibranch) déclenche un build Jenkins
- La pipeline exécute : `npm ci` + `npm test`
- Les logs Jenkins confirment le checkout + les versions Node/npm
- Une PR/branche CI existe (si modifications) + issues créées pour les améliorations (tests/lint)

---

### Personne 1 (Ilias)
**Tâches**
1. Vérifier le `Jenkinsfile` dans le dépôt (lisibilité + conformité)
   - Checkout réel (`checkout scm`)
   - `npm ci` utilisé (pas `npm install`)
2. Créer/mettre à jour une branche `feature/ci-mvp` si une modification est nécessaire
3. Ouvrir une PR vers `develop` (ou `main` si vous n’avez pas `develop`)
4. Créer 2 issues GitHub :
   - `CI - Ajouter de vrais tests (Jest + Supertest)`
   - `CI - Ajouter lint (ESLint) + script npm run lint`
5. Mettre à jour ce fichier `docs/ci.md` avec le suivi Jour 2 (fait / à faire / blocages)

**Livrables**
- PR (si changements) + 2 issues créées + doc à jour

---

### Personne 2 (Jenkins / Intégration GitHub) – (Amine)
**Tâches**
1. Configurer le job Jenkins (Multibranch recommandé) sur le repo
2. Vérifier que Jenkins récupère bien la bonne branche et les derniers commits
3. Mettre en place le déclenchement automatique (si possible) :
   - Webhook GitHub → Jenkins (`/github-webhook/`) **ou**
   - Scan automatique/périodique du Multibranch (si webhook bloquant)
4. Vérifier/ajouter les credentials nécessaires (accès repo si privé)

**Livrables**
- Build déclenché automatiquement (ou scan multibranch OK) + preuve (capture/log)

---

### Personne 3 (Stabilisation CI / Debug) – (Abdessamad)
**Tâches**
1. Reproduire localement (ou sur l’agent Jenkins) les commandes CI :
   - `npm ci`
   - `npm test`
2. Corriger les erreurs qui font échouer la CI (si elles apparaissent) :
   - dépendances, permissions, version Node, chemins, etc.
3. Proposer une amélioration “valeur CI” pour Jour 3 :
   - soit ajouter ESLint (`npm run lint`)
   - soit ajouter 1 vrai test Jest minimal (smoke/API)

**Livrables**
- Pipeline Jenkins qui passe (SUCCESS) + note “blocages & fixes” + plan Jour 3

---

## Jenkinsfile MVP (exemple)
```groovy
pipeline {
  agent any

  stages {
    stage('Checkout') {
      steps {
        checkout scm
        echo 'Code fetched from GitHub'
      }
    }

    stage('Verify Environment') {
      steps {
        script {
          if (isUnix()) {
            sh 'node --version'
            sh 'npm --version'
          } else {
            bat 'node --version'
            bat 'npm --version'
          }
        }
      }
    }

    stage('Install Dependencies') {
      steps {
        script {
          if (isUnix()) {
            sh 'npm ci'
          } else {
            bat 'npm ci'
          }
        }
      }
    }

    stage('Tests (optional)') {
      steps {
        script {
          if (isUnix()) {
            sh 'npm test --if-present'
          } else {
            bat 'npm test --if-present'
          }
        }
      }
    }

    stage('Build (optional)') {
      steps {
        script {
          if (isUnix()) {
            sh 'npm run build --if-present'
          } else {
            bat 'npm run build --if-present'
          }
        }
      }
    }
  }
}

  }
}
