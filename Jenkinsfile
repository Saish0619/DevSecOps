pipeline {
    agent any

    // Define parameters for the pipeline, allowing the user to specify the target URL
    parameters {
        string(name: 'TARGET_URL', defaultValue: 'google.com', description: 'The URL to perform the SSL scan on (e.g., google.com)')
    }

    stages {
        stage('Build Docker Image') {
            steps {
                script {
                    // Define a tag for the Docker image using the Jenkins build number
                    def dockerImage = "sslyze-scanner:${env.BUILD_NUMBER}"
                    
                    // Build the Docker image from the Dockerfile in the current directory
                    sh "docker build -t ${dockerImage} ."
                    
                    // Set an environment variable with the image name for use in later stages
                    env.DOCKER_IMAGE = dockerImage
                }
            }
        }

        stage('Run SSL Scan') {
            steps {
                script {
                    // Run the Docker container, passing the parameterized URL to the Python script
                    // The script's output will be captured in the Jenkins console
                    sh "docker run --rm ${env.DOCKER_IMAGE} ${params.TARGET_URL} > scan_results.txt"
                }
            }
        }

        stage('Archive Results') {
            steps {
                // Archive the scan results file so it can be downloaded from the Jenkins UI
                archiveArtifacts artifacts: 'scan_results.txt', fingerprint: true
            }
        }
    }
}
