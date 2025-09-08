pipeline {
    agent any

    // Define parameters for the pipeline, allowing the user to specify the target URL
    parameters {
        string(name: 'TARGET_URL', defaultValue: 'google.com', description: 'The URL to perform the SSL scan on (e.g., google.com)')
    }

    stages {
        options {
        // This step cleans the workspace before the build starts.
        cleanWs()
        }
        // stage('Build Docker Image') {
        //     steps {
        //         script {
        //             // Define a tag for the Docker image using the Jenkins build number
        //             def dockerImage = "sslyze-scanner:${env.BUILD_NUMBER}"
                    
        //             // Build the Docker image from the Dockerfile in the current directory
        //             sh "docker build -t ${dockerImage} ."
                    
        //             // Set an environment variable with the image name for use in later stages
        //             env.DOCKER_IMAGE = dockerImage
        //         }
        //     }
        // }

        // stage('Run SSL Scan') {
        //     steps {
        //         script {
        //             // Run the Docker container, passing the parameterized URL to the Python script
        //             // The script's output will be captured in the Jenkins console
        //             sh "docker run --rm ${env.DOCKER_IMAGE} ${params.TARGET_URL} > scan_results.txt"
        //         }
        //     }
        // }

        stage('Build and Scan with Docker') {
            steps {
                // The 'bat' command is used here for Windows agents.
                // Replace any 'sh' commands in your existing pipeline with 'bat'.

                // 1. Build the Docker image using the provided Dockerfile.
                // The 'docker build' command is a native Windows command if Docker Desktop is installed.
                bat 'docker build -t devsecops-ssl-scanner .'

                // 2. Run the Docker container to execute the SSL scan.
                // The '-v' flag mounts the current directory into the container,
                // and the '--rm' flag automatically removes the container after it exits.
                // The container will run the SSLyze_DevSecOps.py script with a target URL.
                // Make sure to replace 'https://www.example.com' with the actual URL you want to scan.
                bat 'docker run -v "%cd%":/app devsecops-ssl-scanner %TARGET_URL%'
            }
        }
        
        
        stage('Archive Results') {
            steps {
                // Archive the scan results file so it can be downloaded from the Jenkins UI
                archiveArtifacts artifacts: 'scan_file.json', fingerprint: true
            }
        }
    }
}
