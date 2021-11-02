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