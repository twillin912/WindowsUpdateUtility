@ECHO OFF
PUSHD "%~dp0"

start powershell.exe -executionpolicy bypass -STA -Nologo -File WUU.ps1

POPD

ping -n 300 127.0.0.1 > nul