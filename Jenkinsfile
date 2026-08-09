pipeline {
    agent none

    parameters {
        string(
            name: 'CI_AGENT_LABEL',
            defaultValue: 'linux && bsdm-ci',
            description: 'Agent with Rust 1.88+, Node.js 24+, Python 3, and cargo-audit'
        )
        string(
            name: 'DOCKER_AGENT_LABEL',
            defaultValue: 'linux && docker',
            description: 'Agent with Docker Buildx, Compose, curl, and wrk'
        )
        string(
            name: 'AMD64_AGENT_LABEL',
            defaultValue: 'linux && amd64 && bsdm-ci',
            description: 'Native linux/amd64 package builder'
        )
        string(
            name: 'ARM64_AGENT_LABEL',
            defaultValue: 'linux && arm64 && bsdm-ci',
            description: 'Native linux/arm64 package builder'
        )
        booleanParam(
            name: 'RUN_UI_TESTS',
            defaultValue: true,
            description: 'Run the Chromium Admin Console smoke tests'
        )
        booleanParam(
            name: 'RUN_LOAD_TESTS',
            defaultValue: false,
            description: 'Run the Docker-based lite and hybrid load-test profile'
        )
        booleanParam(
            name: 'BUILD_PACKAGES',
            defaultValue: false,
            description: 'Build a native package on a non-tag build; tag builds always package amd64'
        )
        booleanParam(
            name: 'BUILD_ARM64_PACKAGE',
            defaultValue: false,
            description: 'Also build a native package on the configured arm64 agent'
        )
        booleanParam(
            name: 'PUBLISH_GITHUB_RELEASE',
            defaultValue: false,
            description: 'For tag builds only: create a GitHub Release from package artifacts'
        )
        booleanParam(
            name: 'PUBLISH_GHCR_IMAGE',
            defaultValue: false,
            description: 'For tag builds only: publish the multi-platform image to GHCR'
        )
        string(
            name: 'GITHUB_TOKEN_CREDENTIALS_ID',
            defaultValue: 'bsdm-github-token',
            description: 'Jenkins secret-text credential used by gh release create'
        )
        string(
            name: 'GHCR_CREDENTIALS_ID',
            defaultValue: 'bsdm-ghcr',
            description: 'Jenkins username/password credential used for ghcr.io'
        )
        string(
            name: 'GHCR_IMAGE',
            defaultValue: 'ghcr.io/onixus/bsdm-proxy',
            description: 'Fully qualified image repository'
        )
        string(
            name: 'GHCR_PLATFORMS',
            defaultValue: 'linux/amd64,linux/arm64',
            description: 'Buildx target platforms'
        )
    }

    options {
        buildDiscarder(logRotator(numToKeepStr: '30', artifactNumToKeepStr: '10'))
        timeout(time: 120, unit: 'MINUTES')
        timestamps()
        skipDefaultCheckout(true)
        parallelsAlwaysFailFast()
        preserveStashes(buildCount: 5)
    }

    environment {
        CARGO_TERM_COLOR = 'always'
        RUST_BACKTRACE = '1'
    }

    stages {
        stage('Preflight') {
            agent { label "${params.CI_AGENT_LABEL}" }
            steps {
                deleteDir()
                checkout scm
                sh './scripts/ci/run.sh preflight'
                sh 'git rev-parse HEAD'
            }
        }

        stage('Quality gates') {
            parallel {
                stage('Rust') {
                    agent { label "${params.CI_AGENT_LABEL}" }
                    steps {
                        deleteDir()
                        checkout scm
                        sh './scripts/ci/run.sh rust-all'
                    }
                }

                stage('Security audit') {
                    agent { label "${params.CI_AGENT_LABEL}" }
                    steps {
                        deleteDir()
                        checkout scm
                        sh './scripts/ci/run.sh security-audit'
                    }
                }

                stage('Documentation') {
                    agent { label "${params.CI_AGENT_LABEL}" }
                    steps {
                        deleteDir()
                        checkout scm
                        sh './scripts/ci/run.sh docs'
                    }
                }

                stage('Admin Console') {
                    agent { label "${params.CI_AGENT_LABEL}" }
                    steps {
                        deleteDir()
                        checkout scm
                        withEnv([
                            "RUN_UI_TESTS=${params.RUN_UI_TESTS ? '1' : '0'}",
                            'UI_TEST_SCREENSHOTS=1'
                        ]) {
                            sh './scripts/ci/run.sh admin-console'
                        }
                    }
                    post {
                        always {
                            archiveArtifacts(
                                artifacts: 'admin-console/test/local/screenshots/**',
                                allowEmptyArchive: true
                            )
                        }
                    }
                }

                stage('Trust UI') {
                    agent { label "${params.CI_AGENT_LABEL}" }
                    steps {
                        deleteDir()
                        checkout scm
                        sh './scripts/ci/run.sh trust-ui'
                    }
                }
            }
        }

        stage('Load test') {
            when {
                beforeAgent true
                expression { params.RUN_LOAD_TESTS }
            }
            agent { label "${params.DOCKER_AGENT_LABEL}" }
            steps {
                deleteDir()
                checkout scm
                sh './scripts/ci/run.sh load-test'
            }
            post {
                always {
                    archiveArtifacts(
                        artifacts: 'load-test-results/**',
                        allowEmptyArchive: true
                    )
                }
            }
        }

        stage('Release metadata') {
            when {
                beforeAgent true
                anyOf {
                    buildingTag()
                    expression { params.BUILD_PACKAGES }
                    expression { params.PUBLISH_GITHUB_RELEASE }
                    expression { params.PUBLISH_GHCR_IMAGE }
                }
            }
            agent { label "${params.CI_AGENT_LABEL}" }
            steps {
                deleteDir()
                checkout scm
                withEnv(["CI_RELEASE_TAG=${env.TAG_NAME ?: ''}"]) {
                    sh './scripts/ci/run.sh release-validate'
                }
            }
        }

        stage('Packages') {
            when {
                beforeAgent true
                anyOf {
                    buildingTag()
                    expression { params.BUILD_PACKAGES }
                }
            }
            parallel {
                stage('Package amd64') {
                    agent { label "${params.AMD64_AGENT_LABEL}" }
                    steps {
                        deleteDir()
                        checkout scm
                        withEnv(['EXPECTED_ARCH=x86_64']) {
                            sh './scripts/ci/run.sh package'
                        }
                        archiveArtifacts(
                            artifacts: 'dist/*.tar.gz,dist/*.tar.gz.sha256',
                            fingerprint: true
                        )
                        stash(
                            name: 'package-amd64',
                            includes: 'dist/*.tar.gz,dist/*.tar.gz.sha256'
                        )
                    }
                }

                stage('Package arm64') {
                    when {
                        beforeAgent true
                        expression { params.BUILD_ARM64_PACKAGE }
                    }
                    agent { label "${params.ARM64_AGENT_LABEL}" }
                    steps {
                        deleteDir()
                        checkout scm
                        withEnv(['EXPECTED_ARCH=aarch64']) {
                            sh './scripts/ci/run.sh package'
                        }
                        archiveArtifacts(
                            artifacts: 'dist/*.tar.gz,dist/*.tar.gz.sha256',
                            fingerprint: true
                        )
                        stash(
                            name: 'package-arm64',
                            includes: 'dist/*.tar.gz,dist/*.tar.gz.sha256'
                        )
                    }
                }
            }
        }

        stage('Publish GitHub Release') {
            when {
                beforeAgent true
                allOf {
                    buildingTag()
                    expression { params.PUBLISH_GITHUB_RELEASE }
                }
            }
            agent { label "${params.CI_AGENT_LABEL}" }
            steps {
                deleteDir()
                checkout scm
                unstash 'package-amd64'
                script {
                    if (params.BUILD_ARM64_PACKAGE) {
                        unstash 'package-arm64'
                    }
                }
                withCredentials([
                    string(
                        credentialsId: params.GITHUB_TOKEN_CREDENTIALS_ID,
                        variable: 'GH_TOKEN'
                    )
                ]) {
                    sh './scripts/ci/publish-github-release.sh "$TAG_NAME"'
                }
            }
        }

        stage('Publish GHCR image') {
            when {
                beforeAgent true
                allOf {
                    buildingTag()
                    expression { params.PUBLISH_GHCR_IMAGE }
                }
            }
            agent { label "${params.DOCKER_AGENT_LABEL}" }
            steps {
                deleteDir()
                checkout scm
                withCredentials([
                    usernamePassword(
                        credentialsId: params.GHCR_CREDENTIALS_ID,
                        usernameVariable: 'REGISTRY_USER',
                        passwordVariable: 'REGISTRY_PASSWORD'
                    )
                ]) {
                    withEnv([
                        "IMAGE_NAME=${params.GHCR_IMAGE}",
                        "PLATFORMS=${params.GHCR_PLATFORMS}"
                    ]) {
                        sh '''
                            set +x
                            trap 'docker logout ghcr.io >/dev/null 2>&1 || true' EXIT
                            printf '%s' "$REGISTRY_PASSWORD" |
                                docker login ghcr.io \
                                    --username "$REGISTRY_USER" \
                                    --password-stdin
                            ./scripts/ci/publish-image.sh "$TAG_NAME"
                        '''
                    }
                }
            }
        }
    }

    post {
        success {
            echo 'BSDM-Proxy CI/CD pipeline completed successfully'
        }
        failure {
            echo 'BSDM-Proxy CI/CD pipeline failed; inspect the first failed stage'
        }
    }
}
