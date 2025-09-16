# Example runner (local)
param(
  [string]$ProjectKey = "your_org_your_project",
  [string]$Organization = "your_org",
  [string]$Branch = "master",
  [string]$OutFile = ".\SonarCloud-Executive-Report.html"
)

if (-not $env:SONARCLOUD_TOKEN) {
  throw "Please set env var SONARCLOUD_TOKEN with your SonarCloud Personal Access Token."
}

.\Export-SonarCloudSecurityReport.ps1 `
  -ProjectKey $ProjectKey `
  -Organization $Organization `
  -Token $env:SONARCLOUD_TOKEN `
  -Branch $Branch `
  -OutFile $OutFile
