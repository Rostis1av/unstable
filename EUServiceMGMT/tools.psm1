function Set-ServiceLogonName {
[CmdletBinding()]
PARAM (
    [parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
    [string[]]$ServiceName,
    [string]$LogonName="LocalSystem",
    [string]$LogonPassword=$null,
    [parameter(Mandatory=$false,ValueFromPipeline=$false,ValueFromPipelineByPropertyName=$false)]
    [string]$ComputerName="localhost"
)

BEGIN {}

PROCESS {
    foreach ($service in $ServiceName) {
        $Parameters=@{
            'StartName'="$LogonName";
            'StartPassword'="$LogonPassword"
        }
        Invoke-CimMethod -Query "SELECT * FROM Win32_Service WHERE Name=`'$service`'" -Method Change -Arguments $Parameters -Computername $ComputerName | Out-Null
        $result = Get-CimInstance win32_service -Filter "name like `"$service`"" -ComputerName $ComputerName | select -Property Name,SystemName,StartName
        return $result
    } 
}

END {}
}