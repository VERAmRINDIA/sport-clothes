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
            bat 'npm install --legacy-peer-deps'
          }
        }
      }
    }

    stage('Quality Gate: Linting') {
            steps {
                script {
                    echo 'Starting Static Code Analysis...'
                    if (isUnix()) {
                      sh 'npx eslint .'
                    } else {
                      bat 'npx eslint .'
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
  }
}
