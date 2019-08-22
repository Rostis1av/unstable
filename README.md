## unstable
#Tools under construction.

docker-install.ps1 - powershell script for install docker in 2k19. Aggregate info from MS & Docker into one script for automatic install.
For install on 2k19 ServerCore use next command to download:

Start-BitsTransfer -Source "https://raw.githubusercontent.com/Rostis1av/unstable/master/docker-install.ps1" -Destination $env:USERPROFILE\Downloads

and next for execute:

$env:USERPROFILE\Downloads\docker-install.ps1
