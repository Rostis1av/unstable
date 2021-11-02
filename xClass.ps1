class Xenios {
}

enum xHostType {
    Unknown = 1
    Client = 2
    Server = 3
}

class xHost : Xenios {
    [parameter()]
    [string]$HostName = "Unknown"
    [XHostType]$HostType = "Unknown"
    [string]$HostStatus = "Unknown"
    # Constructors
    
    xHost () {
#        $this.HostName="Localhost"
    }

    xHost ([String]$HostName) {
        $this.HostName=$HostName
    }

} #class abstact host

class xHostSession : xHost {

    # Properties
    [parameter()]
    [string]$HostName = "localhost"
    [string]$FQDN = [System.Net.Dns]::Resolve($this.HostName).hostname
#    [string]$FQDN
    hidden [Microsoft.Management.Infrastructure.CimSession]$CIMSession
    hidden [System.Management.Automation.Runspaces.PSSession]$PSSession
    [string]$PSSID="undefine"
    [string]$CIMSID="undefine"
    [string]$CIMState="undefine"
    [string]$PSState="undefine"

    # Constructors
    xHostSession () {
        # define in param block
    }

    xHostSession ([string]$HostName) {
        $this.HostName=$HostName
        #        $cmp_FQDN = [System.Net.Dns]::Resolve($ComputerName).hostname        
        $this.FQDN = [System.Net.Dns]::Resolve($this.HostName).hostname
        $cmp_PSSession = New-PSSession -ComputerName $this.FQDN -Name $HostName
        $this.PSSession= $cmp_PSSession
        $this.PSSID = ($cmp_PSSession).InstanceId
        $this.PSState = ($cmp_PSSession).state
        $protocol = "WSMAN"     
        do {
            try {
                $cmp_CIMOption = New-CimSessionOption -Protocol $protocol
                $cmp_CIMSession = New-CimSession -SessionOption $cmp_CIMOption -ComputerName $this.FQDN -ErrorAction Stop -Name $HostName
                $this.CIMSID = ($cmp_CIMSession).InstanceId
                if ($cmp_CIMSession.TestConnection()) {
                    $this.CIMState = "Opened" 
                    }
                else {
                    $this.CIMState = "Failed" 
                    }
                $this.CIMSession = $cmp_CIMSession
                $protocol = "STOP" 
            } catch {
                switch ($protocol) {
                    "WSMAN" { $protocol = "DCOM" }
                    "DCOM" { $protocol = "STOP" }
                } # switch
            } finally { }# try
        } until ($protocol -like "STOP")

#        $this.HostName = $HostName
#        $this.FQDN = $cmp_fqdn
    } #construct without credentials

    xHostSession ([string]$HostName,[System.Management.Automation.PSCredential]$Credential) {
        $this.HostName = $HostName
        #        $cmp_FQDN = [System.Net.Dns]::Resolve($ComputerName).hostname
        $this.FQDN = [System.Net.Dns]::Resolve($this.HostName).hostname
        $cmp_PSSession = New-PSSession -ComputerName $this.FQDN -Credential $Credential -Name $HostName
        $this.PSSession = $cmp_PSSession
        $this.PSSID = ($cmp_PSSession).InstanceId
        $this.PSState = ($cmp_PSSession).state

        $protocol = "WSMAN"     
        do {
            try {
                $cmp_CIMOption = New-CimSessionOption -Protocol $protocol
                $cmp_CIMSession = New-CimSession -SessionOption $cmp_CIMOption -ComputerName $this.FQDN -Credential $Credential -ErrorAction Stop -Name $HostName
                $this.CIMSID = ($cmp_CIMSession).InstanceId
                if ($cmp_CIMSession.TestConnection()) {
                    $this.CIMState = "Opened" 
                    }
                else {
                    $this.CIMState = "Failed" 
                    }
                $this.CIMSession = $cmp_CIMSession
                $protocol = "STOP" 
            } catch {
                switch ($protocol) {
                    "WSMAN" { $protocol = "DCOM" }
                    "DCOM" { $protocol = "STOP" }
                } # switch
            } finally { }# try
        } until ($protocol -like "STOP")

        $this.HostName = $HostName
#        $this.FQDN = $cmp_fqdn
    } # construct with credentials

    [XHost]State () {
        try {
            $result = (Get-CimSession -InstanceId $this.CIMSID -ErrorAction stop).TestConnection()
            $this.CIMState = "Opened"
        } catch {
            $this.CIMState = "Fialed"
        }
        $this.PSState = (Get-PSSession -InstanceId $this.PSSID).State
        return $this
    } # method state

    [XHost]Repair () {
        Connect-PSSession -InstanceId $this.PSSID
        Remove-CimSession -InstanceId $this.CIMSID
#        $this.CIMSession = $this.CIMSession | New-CimSession
#        $this.CIMSID = ($this.CIMSession).InstanceId

        $this.CIMSID
        $cmp_CIMSession = Get-CimSession -InstanceId $this.CIMSID | New-CimSession
        $cmp_CIMSession
        $this.CIMSession = $cmp_CIMSession
        $this.CIMSID = ($cmp_CIMSession).InstanceId

        $this.CIMState = "Opened"
        $this.PSState = (Get-PSSession -InstanceId $this.PSSID).State
        return $this
    }
} #class Computer

class xHardware : Xenios {
} #class abstact hardware

enum xHWCPUType {
    x86 = 0
    MIPS = 1
    Alpha = 2
    PowerPC = 3
    IntelItanium = 6
    x64 = 9
    Other = 999

<#
    "0" {"x86"}
    "1" {"MIPS"}
    "2" {"Alpha"}
    "3" {"PowerPC"}
    "6" {"Intel Itanium"}
    "9" {"x64"}
#>
} 

class xOS : xHardware {
    [parameter()]
    [string]$Caption=$null
    [string]$Architecture=$null

    xOS () {}

    xOS ($OS) {
        $this.Caption=$OS.Caption
        if ($OS.OSArchitecture) {
            $this.Architecture=$OS.OSArchitecture
        } else {
            $this.Architecture=$OS.Architecture
        }
    }
}

class xCPU : xHardware {
    [parameter()]
    [string]$DeviceID=$null
    [xHWCPUType]$Architecture = 999
    [string]$Model=$null

    xCPU () {}

    xCPU ($CPU) {
        $this.DeviceID = $CPU.DeviceID
        $this.Architecture = $CPU.Architecture
        if ($CPU.Name) {
            $this.Model=$CPU.Name
        } else {
            $this.Model=$CPU.Model
        }
    }
}

class xRAM : xHardware {
    [parameter()]
    [string]$DeviceID
    [Double]${Size MB}

    xRAM () {}

    xRAM ($RAM) {
        $this.DeviceID = $RAM.DeviceID
        if ($RAM.startingaddress -or $RAM.endingaddress) {
             $this.'Size MB' = [math]::round((($RAM.EndingAddress - $RAM.StartingAddress) / 1024), 2)
        }else {
            $this.'Size MB' = $RAM.'Size MB'
        }
    }
}

class xBaseBoard : xHardware {
    [parameter()]
    [string]$Manufacturer
    [string]$Product
    [string]$Version
    [string]$SerialNumber

    xBaseBoard () {}

    xBaseBoard ($BaseBoard) {
        $this.Manufacturer = $BaseBoard.Manufacturer
        $this.Product = $BaseBoard.Product
        $this.Version = $BaseBoard.Version
        $this.SerialNumber = $BaseBoard.SerialNumber
    }
}

class xVGA : xHardware {
    [parameter()]
    [string]$Manufacturer
    [string]$Product
    [string]$GPU
    [Double]${Size MB}

    xVGA () {}
#$vga | select AdapterCompatibility,AdapterRAM,Name
    xVGA ($VGA) {
        if ($VGA.AdapterCompatibility) {
            $this.Manufacturer = $VGA.AdapterCompatibility
        } else {
            $this.Manufacturer = $VGA.Manufacturer
        }

        if ($VGA.Name) {
            $this.Product = $VGA.Name
        } else {
            $this.Product = $VGA.Product
        }

        if ($VGA.VideoProcessor) {
            $this.GPU = $VGA.VideoProcessor
        } else {
            $this.GPU = $VGA.GPU
        }

        if ($VGA.AdapterRAM) {
             $this.'Size MB' = [math]::round((($VGA.AdapterRAM) / 1024 /1024), 2)
        }else {
            $this.'Size MB' = $VGA.'Size MB'
        }

    }
}

class xHDD : xHardware {
    [parameter()]
    [string]$Manufacturer
    [string]$InterfaceType
    [Double]${Size TB}
    [string]$SerialNumber

    xHDD () {}
#$hdd | select model,InterfaceType,Size,SerialNumber
    xHDD ($HDD) {
        if ($HDD.Model) {
            $this.Manufacturer = $HDD.Model
        } else {
            $this.Manufacturer = $HDD.Manufacturer
        }

        $this.InterfaceType = $HDD.InterfaceType

        if ($HDD.Size) {
             $this.'Size TB' = [math]::round((($HDD.Size) / 1024 /1024 / 1024 /1024), 3)
        }else {
            $this.'Size TB' = $HDD.'Size MB'
        }

        $this.SerialNumber = $HDD.SerialNumber

    }
}

class xPartition : xHardware {
    [parameter()]
    [string]$DeviceID
    [string]$FileSystem
    [Double]${Size TB}
    [Double]${Free TB}

    xPartition () {}

    xPartition ($Partition) {

        $this.DeviceID = $Partition.DeviceID

        $this.FileSystem = $Partition.FileSystem

        if ($Partition.Size) {
             $this.'Size TB' = [math]::round((($Partition.Size) / 1024 /1024 / 1024 /1024), 3)
        }else {
            $this.'Size TB' = $Partition.'Size MB'
        }

        if ($Partition.FreeSpace) {
             $this.'Free TB' = [math]::round((($Partition.FreeSpace) / 1024 /1024 / 1024 /1024), 3)
        }else {
            $this.'Free TB' = $Partition.'Free MB'
        }
    }
}

class xCD : xHardware {
    [parameter()]
    [string]$DeviceID
    [string]$MediaType
    [string]$Manufacturer
    [string]$SerialNumber

    xCD () {}

    xCD ($CD) {

        if ($CD.ID) {
            $this.DeviceID = $CD.ID
        }else {
            $this.DeviceID = $CD.DeviceID
        }

        $this.MediaType = $CD.MediaType

        if ($CD.Name) {
             $this.Manufacturer = $CD.Name
        }else {
            $this.Manufacturer = $CD.Manufacturer
        }

        $this.SerialNumber = $CD.SerialNumber

    }
}

enum xNetStatus {

    Disconnected = 0
    Connecting = 1
    Connected = 2
    Disconnecting = 3
    HardwareNotPresent = 4
    HardwareDisabled = 5
    HardwareMalfunction = 6
    MediaDisconnected = 7
    Authenticating = 8
    AuthenticationSucceeded = 9
    AuthenticationFailed = 10
    InvalidAddress = 11
    CredentialsRequired = 12
}

class xEthernet : xHardware {
    [parameter()]
    [string]$Manufacturer
    [string]$ProductName
    [string]$NetConnectionID
    [string]$MACAddress
    [boolean]$PhysicalAdapter
    [string]$Speed
    [xNetStatus]$Status

    xEthernet () {}

    xEthernet ($Ethernet) {


# NetConnectionStatus
        $this.Manufacturer = $Ethernet.Manufacturer
        $this.ProductName = $Ethernet.ProductName

        $this.NetConnectionID = $Ethernet.NetConnectionID

        $this.MACAddress = $Ethernet.MACAddress

        $this.PhysicalAdapter = $Ethernet.PhysicalAdapter

#        $this.Speed = $Ethernet.Speed
        $this.Speed = [math]::round((($Ethernet.Speed) / 1024 /1024 ), 3)

        if ($Ethernet.NetConnectionStatus) {
            $this.Status = $Ethernet.NetConnectionStatus
        } else {
            $this.Status = $Ethernet.Status
        }
    }
}

class xHostHardware : xHardware {
    [parameter()]
    [string]$HostName
    [string]$FQDN
    [string]$OS
    hidden[xOS]$OperatingSystem
    [string[]]$CPU
    hidden[xCPU[]]$Processors  = $null
    [string[]]$MEM
    hidden[xRAM[]]$PhysicalMemory = $null
#    [string]$TotalMemory = $null
    [string]$MB
    hidden[xBaseBoard]$MotherBoard = $null
    [string[]]$VGA
    hidden[xVGA[]]$Videocontroller  = $null
    [string[]]$HDD
    hidden[xHDD[]]$HardDisks  = $null
    [string[]]$Volume
    hidden[xPartition[]]$DiskPartitions = $null
    [string[]]$MediaDrive
    hidden[xCD]$MediaType = $null
    [string[]]$Ethernet
    hidden[xEthernet[]]$NetwokAdapters = $null

    xHostHardware () {}

#    xHostHardware ([Microsoft.Management.Infrastructure.CimSession]$CimSession) {
#        $CimSession=$CMP01.CIMSession
    xHostHardware ([xHostSession]$HostSession) {
        $CimSession=$HostSession.CIMSession
        $this.HostName = $HostSession.hostname
        $this.FQDN = $HostSession.FQDN
        $this.OperatingSystem = (Get-CimInstance Win32_OperatingSystem -Property * -CimSession $CimSession)
        $this.OS = $this.OperatingSystem.Caption + " " + $this.OperatingSystem.Architecture
        $this.Processors = Get-CimInstance  Win32_Processor -Property * -CimSession $CimSession
        $this.CPU = $this.Processors | % {$_.DeviceID + " - " + $_.Model + " " + $_.Architecture}
        $this.PhysicalMemory = Get-CimInstance  Win32_MemoryDevice -Property * -CimSession $CimSession
        $this.MEM = $this.PhysicalMemory | % {$_.deviceid + " - " + $_.'Size MB' + "MB"}
        $this.MotherBoard = Get-CimInstance  Win32_BaseBoard -Property * -CimSession $CimSession
        $this.MB = $this.MotherBoard.Manufacturer + " " + $this.MotherBoard.Product + " " + $this.MotherBoard.Version
        $this.Videocontroller = Get-CimInstance  Win32_VideoController -Property * -CimSession $CimSession
        $this.VGA = $this.Videocontroller | % {$_.Product + " " + $_.'Size MB' + "MB" }
        $this.HardDisks = Get-CimInstance  Win32_DiskDrive -Property * -CimSession $CimSession
        $this.HDD = $this.HardDisks | % {$_.Manufacturer + " " + $_.'Size TB' + "TB"}
        $this.DiskPartitions = Get-CimInstance  Win32_LogicalDisk -Filter "MediaType = 12" -Property * -CimSession $CimSession
        $this.Volume = $this.DiskPartitions | % {$_.DeviceID + " " + $_.FileSystem + " / " + $_.'Size TB' + ":" + $_.'Free TB'}
        $this.MediaType = Get-CimInstance Win32_CDROMDrive -Property * -CimSession $CimSession
        $this.MediaDrive = $this.MediaType | % {$_.DeviceID + " " + $_.Manufacturer}
        $this.NetwokAdapters = Get-CimInstance Win32_NetworkAdapter -Property * -CimSession $CimSession | ?{$_.NetConnectionID -ne $null}
        $this.Ethernet = $this.NetwokAdapters | % {$_.Manufacturer + " " + $_.MACAddress + " " + $_.Speed}
#        $Properties=@{}
    }
}

$cmp_Session=[xhostsession]"localhost"
$cmp_Hardware=[xHostHardware]$cmp_Session