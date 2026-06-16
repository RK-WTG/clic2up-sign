@echo off
echo === Construction de l'installeur clic2up-sign ===
echo.

set JAVA="C:\Program Files\Eclipse Adoptium\jdk-17.0.18.8-hotspot\bin\java.exe"
set ISCC="%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe"

echo [1/3] Generation de l'icone...
cd /d "%~dp0installer"
%JAVA% generate-icon.java
if %ERRORLEVEL% NEQ 0 (
    echo ERREUR: Impossible de generer l'icone
    pause
    exit /b 1
)
echo.

echo [2/3] Construction de l'app-image avec jpackage...
cd /d "%~dp0"
call build-exe.bat
echo.

echo [3/3] Creation de l'installeur avec Inno Setup...
if not exist %ISCC% (
    echo.
    echo ERREUR: Inno Setup 6 n'est pas installe.
    echo Telechargez-le ici : https://jrsoftware.org/isdl.php
    echo.
    pause
    exit /b 1
)

%ISCC% installer\clic2up-sign.iss
if %ERRORLEVEL% EQU 0 (
    echo.
    echo === Succes ! ===
    echo Installeur cree : dist\clic2up-sign-setup.exe
    echo.
) else (
    echo.
    echo === Erreur lors de la creation de l'installeur ===
)
pause
