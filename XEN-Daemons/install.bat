echo "Install Module from "%~dp0
powershell -executionpolicy bypass -command "& {set-location %~dp0; .\Install.ps1}"