@echo off
setlocal

set SLN=%~dp0libgriffin.sln
set CONFIG=%1
if "%CONFIG%"=="" set CONFIG=Release

:: Find MSBuild via vswhere
set VSWHERE="%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist %VSWHERE% set VSWHERE="%ProgramFiles%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist %VSWHERE% (
    echo [!] vswhere not found. Install Visual Studio 2017 or later.
    if "%NOPAUSE%"=="" pause
    exit /b 1
)

for /f "usebackq delims=" %%i in (`%VSWHERE% -latest -requires Microsoft.Component.MSBuild -find MSBuild\**\Bin\MSBuild.exe`) do set MSBUILD=%%i
if not defined MSBUILD (
    echo [!] MSBuild not found. Install "Desktop development with C++" workload.
    if "%NOPAUSE%"=="" pause
    exit /b 1
)

"%MSBUILD%" "%SLN%" /p:Configuration=%CONFIG% /p:Platform=x64 /v:minimal /nologo
if errorlevel 1 exit /b 1
echo [+] Build successful: build\%CONFIG%\libgriffin.exe
if "%NOPAUSE%"=="" pause
