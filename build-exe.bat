@echo off
echo === Construction de clic2up-sign.exe ===

set JPACKAGE="C:\Program Files\Eclipse Adoptium\jdk-17.0.18.8-hotspot\bin\jpackage.exe"
set INPUT_DIR=C:\RK\clic2up\source\clic2up-sign\packaging\input
set DEST_DIR=C:\RK\clic2up\source\clic2up-sign\dist
set ICON_FILE=C:\RK\clic2up\source\clic2up-sign\installer\clic2up-sign.ico

rem Copier le JAR depuis target vers packaging/input
copy /Y "%~dp0target\clic2up-sign.jar" "%INPUT_DIR%\clic2up-sign.jar" >nul

rem Supprimer l'ancien build si existant
if exist "%DEST_DIR%\clic2up-sign" rmdir /s /q "%DEST_DIR%\clic2up-sign"

rem Modules Java necessaires (detectes avec jdeps)
set MODULES=java.base,java.compiler,java.desktop,java.instrument,java.management,java.naming,java.security.jgss,java.sql,java.xml.crypto,jdk.crypto.cryptoki

echo Lancement de jpackage avec runtime optimise...
%JPACKAGE% --type app-image --name clic2up-sign --input "%INPUT_DIR%" --main-jar clic2up-sign.jar --main-class com.clic2up.Main --icon "%ICON_FILE%" --dest "%DEST_DIR%" --java-options "-Xmx256m" --add-modules %MODULES% --jlink-options "--strip-debug --no-header-files --no-man-pages"
if %ERRORLEVEL% EQU 0 (
    echo.
    echo === Succes ! ===
    echo Executable cree dans : %DEST_DIR%\clic2up-sign\clic2up-sign.exe
    echo.
    echo Pour lancer : %DEST_DIR%\clic2up-sign\clic2up-sign.exe
) else (
    echo.
    echo === Erreur lors du packaging ===
)
pause
