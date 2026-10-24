@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"

net session >nul 2>&1
if not "%errorlevel%"=="0" (
    echo Solicitando privilegios de administrador...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

echo Iniciando NetWatch...
python app.py %*
echo.
echo O monitor foi encerrado.
pause
