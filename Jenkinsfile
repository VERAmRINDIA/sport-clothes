pipeline {
    agent any

    stages {
        stage('Checkout') {
            steps {
                echo 'Code fetched from GitHub'
            }
        }

        stage('Install Dependencies') {
            steps {
                bat 'npm install'
            }
        }

        stage('Verify Environment') {
            steps {
                bat 'node --version'
                bat 'npm --version'
            }
        }

        stage('Optional Tests') {
            steps {
                bat 'npm test --if-present'
            }
        }

        stage('Optional Build') {
            steps {
                bat 'npm run build --if-present'
            }
        }
    }
}
