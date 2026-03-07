@echo off
setlocal
title Launch Nuclear Scanner Token Listener
echo ==============================================
echo Installing Nuclear Scanner Listener to Startup
echo ==============================================

set "VBS_FILE=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\nuclear_listener.vbs"
set "PYTHON_PATH=pythonw"
set "SCRIPT_PATH=%~dp0listener.py"

echo Creating silent startup script...
echo Set WshShell = CreateObject("WScript.Shell") ^> "%VBS_FILE%" > "%TEMP%\create_listener_vbs.bat"
echo echo WshShell.Run "%PYTHON_PATH% """%SCRIPT_PATH%"""", 0, False ^>^> "%VBS_FILE%" >> "%TEMP%\create_listener_vbs.bat"
call "%TEMP%\create_listener_vbs.bat"
del "%TEMP%\create_listener_vbs.bat"

echo [+] Added to Windows Startup folder:
echo     %VBS_FILE%
echo.
echo [+] Starting listener now in the background...
start "" %PYTHON_PATH% "%SCRIPT_PATH%"

echo.
echo Setup Complete! 
echo The listener is now running in the background and will start with Windows.
echo When you plug in the ESP32-CAM flashed with the nuclear token, the GUI will appear.
echo.
pause
