# Don't forget creat cpecify folder for your script module in folder #
# C:\Windows\System32\WindowsPowerShell\v1.0\Modules\%modulename%    #
# and put there are psm1-file
# Change $env:PSModulePath
<#
 For Machines
 $path = [System.Environment]::GetEnvironmentVariable("PSModulePath", "Machine")
 $path -split ";"
 
 [System.Environment]::SetEnvironmentVariable("PSModulePath", $path + ";D:\RGBronzov\PSModules", "Machine")
 $path -split ";"
 
 $path = [System.Environment]::GetEnvironmentVariable("PSModulePath", "User")
 [System.Environment]::SetEnvironmentVariable("PSModulePath", $path + ";$home\Documents\Fabrikam\Modules", "User")

 #>

<# Prompt change
function global:prompt{
    # change prompt text
    Write-Host "XEN " -NoNewLine -ForegroundColor Green
    Write-Host ((Get-Date -f "HH:mm:ss")+">") -NoNewLine -ForegroundColor Yellow
    return " "
}
#>
<#
function global:prompt{
    # change prompt text
    Write-Host ((Get-Date -f "HH:mm:ss")+" "+(cat Env:\USERDOMAIN)+"\"+(cat Env:\USERNAME)+" "+(Get-Location)) -ForegroundColor Yellow
    return "PS"+">>"
}
#>

# $host.ui.RawUI.WindowTitle="XEN Daemons"

function Search-WmiObject {
<#
.SYNOPSIS
Show WMI by name.
.DESCRIPTION
Show process by name or by mask of name. Use WMIObject win32_process. Work in env PS 1.0 and later.
.PARAMETER ComputerName
The name of the service to query.
.PARAMETER PartOfServiceName
.EXAMPLE
.\search-WmiObject -WmiObjectName chrome
#>
[CmdletBinding()]
Param(
    [Parameter(Mandatory=$false,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
    [string[]]$WmiObjectName="*"
    )

begin{}

process{
        Write-Verbose "Seek WmiObject for $WmiObjectName"
        foreach ($WON in $WmiObjectName) {
<#
            Get-WmiObject -List -Namespace root\cimv2 | Where-Object {$_.name -like "*$WON*"} |select -name
            $properties=@{
                "ProcessName"=[string]$process.Caption;
                "CommandLine"=[string]$process.CommandLine;
                "Path"=[string]$process.Path;
                "Handle"=[string]$process.Handle
                }
            $obj=New-Object -TypeName psobject -Property $properties
#>
            $obj=Get-WmiObject -List -Namespace root\cimv2 | Where-Object {$_.name -like "win32_*$WON*"} |select -Property @{n="Class";e={$_.name}}
            Write-Output $obj
        }
    }
end{}
}

function Show-Process {
<#
.SYNOPSIS
Show service by name.
.DESCRIPTION
Show process by name or by mask of name. Use WMIObject win32_process. Work in env PS 1.0 and letter.
.PARAMETER ComputerName
The name of the service to query.
.PARAMETER PartOfServiceName
.EXAMPLE
.\show-Process -PartOfServiceName chrome
#>
[CmdletBinding()]
Param(
    [Parameter(Mandatory=$false,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
    [string[]]$ProcessName="*"
    )

begin{}

process{
        Write-Verbose "Seek process $ProcessName"
#       $process_match=(Get-WmiObject -Class win32_process | Where-Object {$_.name -like "note*"})
        $process_match=(Get-WmiObject -Class win32_process | Where-Object {$_.name -like "*$ProcessName*"})
        foreach ($process in $process_match) {
            $properties=@{
                "ProcessName"=[string]$process.Caption;
                "CommandLine"=[string]$process.CommandLine;
                "Path"=[string]$process.Path;
                "Handle"=[string]$process.Handle
                }
            $obj=New-Object -TypeName psobject -Property $properties 
            Write-Output $obj
        }
    }
end{}
}

function Kill-Process {
<#
.SYNOPSIS
Kill service by name.
.DESCRIPTION
Kill process by handle of name. Use WMIObject win32_process. Work in env PS 1.0 and letter.
.PARAMETER ComputerName
The name of the service to query. 
.PARAMETER PartOfServiceName
.EXAMPLE
.\kill-Process -PartOfServiceName chrome
#>
[CmdletBinding()]
Param(
#    [Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
    [Parameter(Mandatory=$True,ValueFromPipeline=$True)]
    $ProcessObject
    )

begin {}

process {
#    Write-host "Seek && destroy: ",$ProcessObject.handle,$ProcessObject.ProcessName
    Get-WmiObject -Class win32_process | Where-Object {$_.Handle -eq $ProcessObject.handle} | Invoke-WmiMethod -Name terminate | Out-Null
    Write-host "Destroy process name",$ProcessObject.ProcessName,"with ID",$ProcessObject.handle,"Succefull"
    }
end {}
}

function Send-WOL { 
<#  
  .SYNOPSIS   
    Send a WOL packet to a broadcast address 
  .PARAMETER mac 
   The MAC address of the device that need to wake up 
  .PARAMETER ip 
   The IP address where the WOL packet will be sent to 
  .EXAMPLE  
   Send-WOL -mac 00:11:32:21:2D:11 -ip 192.168.8.255  
  .EXAMPLE  
   Send-WOL -mac 00:11:32:21:2D:11  
 
#> 
 
[CmdletBinding()] 
param( 
[Parameter(Mandatory=$True,Position=1)] 
[string]$mac, 
[string]$ip="255.255.255.255",  
[int]$port=9 
) 
$broadcast = [Net.IPAddress]::Parse($ip) 
  
$mac=(($mac.replace(":","")).replace("-","")).replace(".","") 
$target=0,2,4,6,8,10 | % {[convert]::ToByte($mac.substring($_,2),16)} 
$packet = (,[byte]255 * 6) + ($target * 16) 
  
$UDPclient = new-Object System.Net.Sockets.UdpClient 
$UDPclient.Connect($broadcast,$port) 
[void]$UDPclient.Send($packet, 102)  
 
}

function Show-NetIPAddress {
<#
.SYNOPSIS
Show IPAdress
.DESCRIPTION
 For each network intefaces list info consists of InterfaceAlias, IPAddress, PrefixLength. Work in env PS 2.0 and letter.
.PARAMETER ComputerName
No parameter need.
.PARAMETER PartOfServiceName
.EXAMPLE
.\Show-NetIPAddress
#>
    Get-NetIPAddress | select -Property InterfaceAlias, IPAddress, PrefixLength
    }

function Set-RDP {
<#
.SYNOPSIS
Wake Up Remote Desktop Services.
.DESCRIPTION
 For localhost set service TermService parameters to StartupType automatic, Status running. Set firewall rules for bypass input RDP connection over TCP/UDP. Work in env PS 2.0 and letter.
.PARAMETER ComputerName
No parameter need.
.PARAMETER PartOfServiceName
.EXAMPLE
.\set-RDP
#>
    Get-Service | Where-Object {$_.Name -Match "TermService"} | Set-Service -StartupType Automatic -Status Running
    Get-NetFirewallRule | Where-Object {$_.name -match "remotedesktop"} | Set-NetFirewallRule -Enabled true
    }

function Get-HardwareInfo ($computers = ".") {
    $OS = gwmi  Win32_OperatingSystem -ComputerName $computers | Select Caption, OSArchitecture, OtherTypeDescription, ServicePackMajorVersion, CSName, TotalVisibleMemorySize
    $CPU = gwmi  Win32_Processor -ComputerName $computers | Select Architecture, DeviceID, Name
    $RAM = gwmi  Win32_MemoryDevice -ComputerName $computers | Select DeviceID, StartingAddress, EndingAddress
    $MB = gwmi  Win32_BaseBoard -ComputerName $computers | Select Manufacturer, Product, Version
    $VGA = gwmi  Win32_VideoController -ComputerName $computers | Select Name, AdapterRam
    $HDD = gwmi  Win32_DiskDrive -ComputerName $computers | select Model, Size
    $Volumes = gwmi  Win32_LogicalDisk -Filter "MediaType = 12" -ComputerName $computers | Select DeviceID, Size, FreeSpace
    $CD = gwmi Win32_CDROMDrive | Select Id, Name, MediaType
    $NIC = gwmi Win32_NetworkAdapter -ComputerName $computers | ?{$_.NetConnectionID -ne $null}
    Write-Host "Computer Name: `n`t" $OS.CSName `
    `n"Operating System: `n`t" $OS.Caption " " $OS.OtherTypeDescription $OS.OSArchitecture `
    `n"Service Pack: `n`t" "Service Pack " $OS.ServicePackMajorVersion " installed" `
    `n"Processors:"
    $CPU | ft DeviceID, @{
        Label = "Architecture"; Expression = {
            switch ($_.Architecture) {
                "0" {"x86"}; "1" {"MIPS"}; "2" {"Alpha"}; "3" {"PowerPC"}; "6" {"Intel Itanium"}; "9" {"x64"}
            }
        }
    }, @{Label = "Model"; Expression = {$_.name}} -AutoSize
    Write-Host "Physical Memory: "
    $RAM | ft DeviceID, @{Label = "Module Size(MB)"; Expression = {
        (($_.endingaddress - $_.startingaddress) / 1KB).tostring("F00")}} -AutoSize
    Write-Host "Total Memory: `n`t" ($OS.TotalVisibleMemorySize / 1KB).tostring("F00") " MB" `
    `n"MotherBoard: " `
    `n"`tVendor: " $MB.Manufacturer `
    `n"`tModel:  " $MB.Product `
    `n"`tVersion: " $MB.Version `
    `n"Videocontroller:" `
    `n"`tModel: " $VGA.Name `
    `n"`tVideo RAM: " ($VGA.AdapterRam/1MB).tostring("F00") " MB`n" `
    `n"HarddDisks:"
    $HDD | ft Model, @{Label="Disk Size(GB)"; Expression = {($_.Size/1GB).tostring("F01")}} -AutoSize
    Write-Host "Disk Partitions:"
    $Volumes | ft DeviceID, @{Label="TotalSize(GB)"; Expression={($_.Size/1GB).ToString("F01")}},
        @{Label="FreeSize(GB)"; Expression={($_.FreeSpace/1GB).tostring("F01")}} -AutoSize
    $CD | ft Id, @{Label = "Media Type"; Expression = {$_.MediaType}},
        @{Label = "Model"; Expression = {$_.Name}} -AutoSize
    Write-Host "Netwok Adapters:"
    $NIC | ft NetConnectionID, @{
        Label="Media Status"; Expression = {
            switch ($_.NetConnectionStatus) {
                "0" {"Disconnected"}
                "1" {"Connecting"}
                "2" {"Connected"}
                "3" {"Disconnecting"}
                "4" {"Hardware not present"}
                "5" {"Hardware disabled"}
                "6" {"Hardware malfunction"}
                "7" {"Media disconnected"}
                "8" {"Authenticating"}
                "9" {"Authentication succeeded"}
                "10" {"Authentication failed"}
                "11" {"Invalid address"}
                "12" {"Credentials required"}
            }
        }
    }, @{Label="NIC"; Expression={$_.name}}
}

function Add-ModulePath {
<#
.SYNOPSIS
Add powershell module path to system object.
.DESCRIPTION
Add powershell module path to system object.
.PARAMETER Path4Module
Path to module.
.EXAMPLE
.\Add-ModulePath -Path4Module D:\MyModule
#>
[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
    [string[]]$Path4Module=""
    )

begin{}

process{
        Write-Verbose "Try add path:$Path4Module"
        foreach ($NewPath in $Path4Module) {
            $path = [System.Environment]::GetEnvironmentVariable("PSModulePath", "Machine")
#            $path -split ";"
            [System.Environment]::SetEnvironmentVariable("PSModulePath", $path + ";"+"$NewPath", "Machine")
#            $path -split ";"
        }
    }
end{}
}

function Remove-ModulePath {
<#
.SYNOPSIS
Remove powershell module path from system object.
.DESCRIPTION
Remove powershell module path from system object.
.PARAMETER Path4Module
Path to module.
.EXAMPLE
.\Remove-ModulePath -Path4Module D:\MyModule
#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
    [string[]]$Path4Module=""
    )

begin{}

process{
<#
    $removepath="D:\RGBronzov\PSModules"
#>
    Write-Verbose "Try remove path:$Path4Module"
    foreach ($RemovePath in $Path4Module) {
        $path = [System.Environment]::GetEnvironmentVariable("PSModulePath", "Machine")
#        write-host "Remove path $RemovePath" -ForegroundColor Red
        $NewPath=($path.Replace($removepath,"")).Replace(";;",";")
        if (($path.Replace($removepath,""))[-1] -eq ";") {$NewPath=$NewPath.Remove(($NewPath.Length-1))}
#        $path
#        $NewPath
        [System.Environment]::SetEnvironmentVariable("PSModulePath", $NewPath, "Machine")
        }
    }
end{}
}

function List-ModulePath {
<#
.SYNOPSIS
List path for system powershell modules.
.DESCRIPTION
Show system object thouse contains list of all powershell module path.
.EXAMPLE
.\List-ModulePath
#>
[CmdletBinding()]
Param()

begin{}

process{
            $obj=[System.Environment]::GetEnvironmentVariable("PSModulePath", "Machine")
            Write-Output $obj
    }
end{}
}

function Get-TeamViewer {
<#
.SYNOPSIS
Download TeamViewer to path.
.DESCRIPTION
Download TeamViewer to local path %userprofile%\Downloads.
.PARAMETER Path4Module
Path to module.
.EXAMPLE
.\Remove-ModulePath -Path4Module D:\MyModule
#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$false,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
    [string]$Path=$home+"\Downloads\TeamViewer_Setup.exe"
    )

begin{}

process{
    Invoke-WebRequest -Uri "https://download.teamviewer.com/download/TeamViewer_Setup.exe" -OutFile $Path
#    Invoke-WebRequest -Uri ((Invoke-WebRequest -Uri "https://www.teamviewer.com").links.href | Where-Object {$_ -like "*setup*.exe"} | select -Unique) -OutFile $Path
    }
end {}
}

function Set-ShellName {
<#
.SYNOPSIS
Set powershell window title.
.DESCRIPTION
Set powershell window title.
.PARAMETER ShellName
Name
.EXAMPLE
.\Set-ConsoleName -ShellName "Monitoring Console"
#>
[CmdletBinding()]
Param(
    [Parameter(Mandatory=$false,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
    [string]$ShellName=$Host.UI.RawUI.WindowTitle
    )

begin{}

process{
    $Host.UI.RawUI.WindowTitle=$ShellName
    }
end {}
}

function Set-SystemProxy {
<#
.SYNOPSIS
Change status system proxy on/off/status
.DESCRIPTION
Turn on or turn off system proxy. Without parametr get status.
.PARAMETER ShellName
Name
.EXAMPLE
.\Set-SystemProxy
#>

[CmdletBinding()]
param(
    [ValidateSet("On","Off","Status")]
    [string]$ProxyState="Status"
)
    Switch ($ProxyState) {
        "On" { Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -Name "ProxyEnable" -Value "1" }
        "Off" { Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -Name "ProxyEnable" -Value "0" }
        Default { if ((get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -Name "ProxyEnable").ProxyEnable) {write-host "Proxy is On"} else {Write-Host "Proxy is Off"}  }

    }
}

function Add-ModulePathCentralRepository {
<#
.SYNOPSIS
Add powershell module path to system object.
.DESCRIPTION
Add powershell module path to system object.
.PARAMETER Path4Module
Path to module.
.EXAMPLE
.\Add-ModulePath -Path4Module D:\MyModule
#>
[CmdletBinding()]
Param(
    [Parameter(Mandatory=$false,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
    [string[]]$Path4Module
    )

begin{
#    [string[]]$Path4Module="C:\Program Files\WindowsPowerShell\Modules"
}

process{
        if (!($Path4Module)) {$Path4Module="C:\Program Files\WindowsPowerShell\Modules"}
        Write-Verbose "Try add path:$Path4Module"
#        $NewPath=$Path4Module
        foreach ($NewPath in $Path4Module) {
            $path = [System.Environment]::GetEnvironmentVariable("PSModulePath", "Machine")
            if (!($path.Split(";") | ? {($_ -contains $NewPath)}) -and (Test-Path -LiteralPath $NewPath)) {
                Write-Host "Work with $NewPath" -ForegroundColor Green
#                [System.Environment]::SetEnvironmentVariable("PSModulePath", $path + ";"+"$NewPath", "Machine")
            } else {
                Write-Host "$NewPath always include in $path" -ForegroundColor Red
            }
        }
    }
end{}
}

function Set-Host {
[CmdletBinding()]

Param(
    [Parameter(Mandatory=$false,ValueFromPipeline=$false,ValueFromPipelineByPropertyName=$false)]
    [string]$Height=70,
    [Parameter(Mandatory=$false,ValueFromPipeline=$false,ValueFromPipelineByPropertyName=$false)]
    [string]$Width=210
    )

begin {}
process {
    if (($Host.ui.RawUI.WindowSize.Width) -gt $Width) {
        $Host.ui.RawUI.WindowSize=New-Object -TypeName System.Management.Automation.Host.Size -ArgumentList $Width,$Height
        $Host.ui.RawUI.BufferSize=New-Object -TypeName System.Management.Automation.Host.Size -ArgumentList $Width,3000
    } else {
        $Host.ui.RawUI.BufferSize=New-Object -TypeName System.Management.Automation.Host.Size -ArgumentList $Width,3000
        $Host.ui.RawUI.WindowSize=New-Object -TypeName System.Management.Automation.Host.Size -ArgumentList $Width,$Height
    }
}
end{}
}