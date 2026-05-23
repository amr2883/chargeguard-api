# deploy.ps1 - ‰‘— ChargeGuard Landing Page
$sourceFile = "C:\Users\Future\chargeguard-landing\index.html"
$distDir = "$PSScriptRoot\dist"

#  ÃÂÌ“ „Ã·œ dist
if (Test-Path $distDir) { Remove-Item $distDir -Recurse -Force }
New-Item -ItemType Directory -Path $distDir -Force | Out-Null

# ‰”Œ «·„·› «·’ÕÌÕ „‰ „Ã·œ chargeguard-landing
Copy-Item -Path $sourceFile -Destination "$distDir\index.html" -Force

# ‰‘— ⁄»— Wrangler
wrangler pages deploy dist --project-name=chargeguard-landing --branch=master

Write-Host "?  „ «·‰‘—! «›Õ’: https://master.chargeguard-landing.pages.dev"
