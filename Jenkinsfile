node{
  stage('SCM') { 
    git branch: 'main', credentialsId: 'thanh1072004-github', url: 'https://github.com/thanh1072004/ProjectII.git' 
  } 
  stage('SonarQube Analysis') { 
   def scannerHome = tool 'SonarQube Scanner'; 
    withSonarQubeEnv() { 
      sh "${scannerHome}/bin/sonar-scanner -Dsonar.projectKey=Project2 -Dsonar.sources=backend,frontend -Dsonar.login=sqa_3f92071d48088ab9c4e45e87c6ed43da22bd0ce3" 
    } 
  } 
}
