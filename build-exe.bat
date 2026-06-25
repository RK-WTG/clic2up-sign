@echo off
rem Version a packager (doit correspondre a la version du pom.xml et du .iss)
set VERSION=1.0
set APPNAME=clic2up-sign-%VERSION%
echo === Construction de %APPNAME%.exe ===

set JPACKAGE="C:\Program Files\Eclipse Adoptium\jdk-17.0.18.8-hotspot\bin\jpackage.exe"
set INPUT_DIR=C:\RK\clic2up\source\clic2up-sign\packaging\input
set DEST_DIR=C:\RK\clic2up\source\clic2up-sign\dist
set ICON_FILE=C:\RK\clic2up\source\clic2up-sign\installer\clic2up-sign.ico

rem Copier le JAR versionne (en nettoyant les anciens jars de packaging/input)
del /Q "%INPUT_DIR%\*.jar" >nul 2>&1
copy /Y "%~dp0target\%APPNAME%.jar" "%INPUT_DIR%\%APPNAME%.jar" >nul

rem Supprimer l'ancien build si existant
if exist "%DEST_DIR%\%APPNAME%" rmdir /s /q "%DEST_DIR%\%APPNAME%"

rem Modules Java necessaires (detectes avec jdeps)
set MODULES=java.base,java.compiler,java.desktop,java.instrument,java.management,java.naming,java.security.jgss,java.sql,java.xml.crypto,jdk.crypto.cryptoki

echo Lancement de jpackage avec runtime optimise...
%JPACKAGE% --type app-image --name %APPNAME% --input "%INPUT_DIR%" --main-jar %APPNAME%.jar --main-class com.clic2up.Main --icon "%ICON_FILE%" --dest "%DEST_DIR%" --java-options "-Xmx256m" --add-modules %MODULES% --jlink-options "--strip-debug --no-header-files --no-man-pages"
if %ERRORLEVEL% EQU 0 (
    echo.
    echo === Succes ! ===
    echo Executable cree dans : %DEST_DIR%\%APPNAME%\%APPNAME%.exe
    echo.
    echo Pour lancer : %DEST_DIR%\%APPNAME%\%APPNAME%.exe
) else (
    echo.
    echo === Erreur lors du packaging ===
)
pause
