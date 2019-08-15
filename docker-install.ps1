function Install-Docker {
    $CurrentBuild = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    Write-Verbose "OS Build Version $($CurrentBuild.CurrentBuildNumber).$($CurrentBuild.UBR)"
    Write-Verbose "OS Release Version $($CurrentBuild.ReleaseId)"

# prepare machine environment & stop docker service

    if ([Environment]::GetEnvironmentVariable("PATH",[EnvironmentVariableTarget]::Machine) -notmatch "docker") {
        [System.Environment]::SetEnvironmentVariable("DOCKER_FIPS", "1", "Machine")
        $NewPath = [Environment]::GetEnvironmentVariable("PATH",[EnvironmentVariableTarget]::Machine)+";$env:ProgramFiles\docker"
        [Environment]::SetEnvironmentVariable("PATH", $newPath,[EnvironmentVariableTarget]::Machine)
        $env:path += ";$env:ProgramFiles\docker"
        Get-Service *docker* | Stop-Service -Force -Confirm:$false
    }

#install conatiners
    Install-WindowsFeature Containers

# install DockerMicrosoftProvider
    Install-PackageProvider -Name nuget -MinimumVersion 2.8.5.201 -Force
    Find-Module dockermsftprovider -Repository psgallery | Install-Module -Force -Confirm:$false

# download info about Docker Versions from MS site
    $DockerResource = Invoke-WebRequest -Uri 'https://dockermsft.blob.core.windows.net/dockercontainer/DockerMsftIndex.json' | ConvertFrom-Json
    $DockerCurrentVersion=$DockerResource.versions.($DockerResource.channels.($DockerResource.channels.cs.alias).version)
    $DockerVersion=($DockerCurrentVersion.url).Split("/")[-1]
    $DockerSource=$DockerCurrentVersion.url
    $FilePath="$env:userprofile\Downloads\$DockerVersion"

# download last version
    Start-BitsTransfer -Source $DockerSource -Destination "$env:userprofile\Downloads\$DockerVersion"

# clean or create file structure
    if (Test-Path "$env:ProgramFiles\docker") {
        Get-Item "$env:ProgramFiles\docker"  | Remove-Item -Force -Recurse -Confirm:$false
        New-Item "$env:ProgramFiles\docker" -ItemType Directory
        New-Item "$env:ProgramFiles\docker\cli-plugins" -ItemType Directory
    } else {
        New-Item "$env:ProgramFiles\docker" -ItemType Directory
        New-Item "$env:ProgramFiles\docker\cli-plugins" -ItemType Directory
    }

# extract docker archive
    Expand-Archive -Path $FilePath -DestinationPath $env:ProgramFiles -Force -Confirm:$false

# register service
    & "$env:ProgramFiles\docker\dockerd.exe" --register-service

# set service autostart
    Set-Service docker -StartupType Automatic

# restart cmp
    Restart-Computer -Force -Confirm:$false
}
Install-Docker
