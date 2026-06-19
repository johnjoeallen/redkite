@echo off
setlocal

mvn --no-transfer-progress clean package -DskipTests
if %errorlevel% neq 0 exit /b %errorlevel%

for %%f in ("%~dp0red-kite-server\target\red-kite-*.jar") do (
    echo %%f | findstr /i "shaded" >nul && goto :continue
    copy /y "%%f" "%~dp0scripts\red-kite.jar" >nul
    echo Built: scripts\red-kite.jar
    exit /b 0
    :continue
)

echo Build succeeded but no JAR found in red-kite-server\target\ >&2
exit /b 1
