pipeline {
  agent any

  environment {
    IO_POC_PROJECT_NAME = "IO-POC-insecure-bank"
    IO_POC_PROJECT_VERSION = "1.0"
    POLARIS_ACCESS_TOKEN = credentials('polaris-token')
    BLACKDUCK_ACCESS_TOKEN = credentials('BlackDuck-AuthToken')
    IO_ACCESS_TOKEN = credentials('IO-AUTH-TOKEN')
    GTIHUB_ACCESS_TOKEN = credentials('Github-AuthToken')
    CODEDX_ACCESS_TOKEN = credentials('CODEDX_API_KEY')
    IS_SAST_ENABLED = "false"
    IS_SCA_ENABLED = "false"
    IS_DAST_ENABLED = "false"
    IS_IMAGE_SCAN_ENABLED = "false"
    IS_CODE_REVIEW_ENABLED = "false"
    IS_PEN_TESTING_ENABLED = "false"
  }

  stages {
    stage('Get CodeDx Project ID') {
      steps {
        sh '''
          wget -q https://raw.githubusercontent.com/jones6951/io-scripts/main/getProjectID.sh
          chmod +x getProjectID.sh
          CODEDX_PROJECT_ID=$(getProjectID.sh --url=${CODEDX_SERVER_URL} --apikey=${CODEDX_TOKEN} --project=${IO_POC_PROJECT_NAME})
          echo "CodeDx Project ID = $CODEDX_PROJECT_ID"
        '''
        script {
          env.CODEDX_PROJECT_ID = sh(getProjectID.sh --url=${CODEDX_SERVER_URL} --apikey=${CODEDX_TOKEN} --project=${IO_POC_PROJECT_NAME})
        }
      }
    }
    stage('IO Prescription') {
      steps {
        echo "Getting IO Prescription"
        sh '''
          echo "CODEDX_PROJECT_ID = ${env.CODEDX_PROJECT_ID}"
          rm -fr prescription.sh
          wget "https://raw.githubusercontent.com/synopsys-sig/io-artifacts/${WORKFLOW_CLIENT_VERSION}/prescription.sh"
          sed -i -e 's/\r$//' prescription.sh
          chmod a+x prescription.sh
          ./prescription.sh \
          --stage="IO" \
          --persona="devsecops" \
          --io.url="${IO_URL}" \
          --io.token="${IO_ACCESS_TOKEN}" \
          --manifest.type="json" \
          --project.name="${IO_POC_PROJECT_NAME}" \
          --workflow.url="${WORKFLOW_URL}" \
          --workflow.version="${WORKFLOW_CLIENT_VERSION}" \
          --scm.type="github" \
          --scm.owner="sigiodemo" \
          --scm.repo.name="${IO_POC_PROJECT_NAME}" \
          --scm.branch.name="main" \
          --github.username="sigiodemo" \
          --github.token="${GTIHUB_ACCESS_TOKEN}" \
          --polaris.project.name="${IO_POC_PROJECT_NAME}" \
          --polaris.url="${POLARIS_SERVER_URL}" \
          --polaris.token="${POLARIS_ACCESS_TOKEN}" \
          --blackduck.project.name="${IO_POC_PROJECT_NAME}:${IO_POC_PROJECT_VERSION}" \
          --blackduck.url="${BLACKDUCK_URL}" \
          --blackduck.api.token="${BLACKDUCK_ACCESS_TOKEN}" \
          --jira.enable="false" \
          --codedx.url="${CODEDX_SERVER_URL}" \
          --codedx.api.key="${CODEDX_ACCESS_TOKEN}" \
          --codedx.project.id="${CODEDX_PROJECT_ID}" \
          --IS_SAST_ENABLED="${IS_SAST_ENABLED}" \
          --IS_SCA_ENABLED="${IS_SCA_ENABLED}" \
          --IS_DAST_ENABLED="${IS_DAST_ENABLED}"
        '''
        sh 'mv result.json io-presciption.json'
        sh '''
          echo "==================================== IO Risk Score =======================================" > io-risk-score.txt
          echo "Business Criticality Score - $(jq -r '.riskScoreCard.bizCriticalityScore' io-presciption.json)" >> io-risk-score.txt
          echo "Data Class Score - $(jq -r '.riskScoreCard.dataClassScore' io-presciption.json)" >> io-risk-score.txt
          echo "Access Score - $(jq -r '.riskScoreCard.accessScore' io-presciption.json)" >> io-risk-score.txt
          echo "Open Vulnerability Score - $(jq -r '.riskScoreCard.openVulnScore' io-presciption.json)" >> io-risk-score.txt
          echo "Change Significance Score - $(jq -r '.riskScoreCard.changeSignificanceScore' io-presciption.json)" >> io-risk-score.txt
          export bizScore=$(jq -r '.riskScoreCard.bizCriticalityScore' io-presciption.json | cut -d'/' -f2) 
          export dataScore=$(jq -r '.riskScoreCard.dataClassScore' io-presciption.json | cut -d'/' -f2)
          export accessScore=$(jq -r '.riskScoreCard.accessScore' io-presciption.json | cut -d'/' -f2)
          export vulnScore=$(jq -r '.riskScoreCard.openVulnScore' io-presciption.json | cut -d'/' -f2)
          export changeScore=$(jq -r '.riskScoreCard.changeSignificanceScore' io-presciption.json | cut -d'/' -f2)
          echo -n "Total Score - " >> io-risk-score.txt && echo "$bizScore + $dataScore + $accessScore + $vulnScore + $changeScore" | bc >> io-risk-score.txt
        '''
        sh 'cat io-risk-score.txt'
        sh '''
          echo "IS_SAST_ENABLED = $(jq -r '.security.activities.sast.enabled' io-presciption.json)" > io-prescription.txt
          echo "IS_SCA_ENABLED = $(jq -r '.security.activities.sca.enabled' io-presciption.json)" >> io-prescription.txt
          echo "IS_DAST_ENABLED = $(jq -r '.security.activities.dast.enabled' io-presciption.json)" >> io-prescription.txt
          echo "IS_IMAGE_SCAN_ENABLED = $(jq -r '.security.activities.imageScan.enabled' io-presciption.json)" >> io-prescription.txt
          echo "IS_CODE_REVIEW_ENABLED = $(jq -r '.security.activities.sastplusm.enabled' io-presciption.json)" >> io-prescription.txt
          echo "IS_PEN_TESTING_ENABLED = $(jq -r '.security.activities.dastplusm.enabled' io-presciption.json)" >> io-prescription.txt
        '''
        sh 'cat io-prescription.txt'
      }
    }
    stage('SAST - Coverity') {
      steps {
        echo "Stage - Coverity on Polaris"
        sh '''
          IS_SAST_ENABLED=$(jq -r '.security.activities.sast.enabled' io-presciption.json)
          echo "IS_SAST_ENABLED = ${IS_SAST_ENABLED}"
          '''
      }
    }
    stage('SCA - Blackduck') {
      steps {
        echo "Stage - Blackduck"
        sh '''
          IS_SCA_ENABLED=$(jq -r '.security.activities.sca.enabled' io-presciption.json)
          echo "IS_SCA_ENABLED = ${IS_SCA_ENABLED}"
          '''
      }
    }
    stage('Schedule Manual Activities') {
      steps {
        echo "Check for Scheduling of Manual Actviities"
        echo "Manual Code Review"
        sh '''
          IS_CODE_REVIEW_ENABLED=$(jq -r '.security.activities.sastplusm.enabled' io-presciption.json)
          echo "IS_CODE_REVIEW_ENABLED = ${IS_CODE_REVIEW_ENABLED}"
          if [ ${IS_CODE_REVIEW_ENABLED} = "true" ]; then
            echo "Sending Notification for Manual Code Review based on IO Precription"
            # Put code to send notification here
          else
            echo "Skipping Manual Code Review based on IO Precription"
          fi
          '''
        echo "Manual Penetration Testing"
        sh '''
          IS_PEN_TESTING_ENABLED=$(jq -r '.security.activities.dastplusm.enabled' io-presciption.json)
          echo "IS_PEN_TESTING_ENABLED = ${IS_PEN_TESTING_ENABLED}"
          if [ ${IS_PEN_TESTING_ENABLED} = "true" ]; then
            echo "Sending Notification for Manual Penetration Testing based on IO Precription"
            # Put code to send notification here
          else
            echo "Skipping Manual Penetration Testing based on IO Precription"
          fi
          '''
      }
    }
    stage('Break the Build') {
      steps {
        echo "add Build Breaker parts here"
        sh '''
          echo "Breaker Status - $(jq -r '.breaker.status' wf-output.json)"
          # Put code to break the build here
        '''
      }
    }
    stage('Clean Workspace') {
      steps {
        cleanWs()
      }
    }
  }
}
