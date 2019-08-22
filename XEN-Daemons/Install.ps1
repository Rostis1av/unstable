function Injection-Module {
[CmdletBinding()]
Param(
    [Parameter(Mandatory=$false,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
    [string]$Path="C:\Windows\System32\WindowsPowerShell\v1.0\Modules\XEN-Daemons\"
    )

begin{}
process{
<#
    [string]$Path="C:\Windows\System32\WindowsPowerShell\v1.0\Modules\XEN-Daemons\"
    Get-ChildItem Cert:\LocalMachine -Recurse | ? {$_.Subject -like "E=RBronzov@gmail.com, CN=Rostislav G. Bronzov"} | Remove-Item
    Get-Item $Path | Remove-Item -Recurse -Force -Confirm:$false
#>
    New-Item -ItemType Directory -Path $Path -Force
#    Set-Location D:\RGBronzov\PSModules\XEN-Daemons
    Get-ChildItem .\XEN-Daemons* | Copy-Item -Destination $Path -Force 
#    $cert=New-SelfSignedCertificate -Subject "EMail=RBronzov@gmail.com, CN=Rostislav G. Bronzov"  -Type CodeSigningCert -KeyAlgorithm RSA -KeyLength 4096 -CertStoreLocation "Cert:\LocalMachine\My" -TestRoot
#    Get-ChildItem $Path | Set-AuthenticodeSignature -Certificate $cert
#    Get-ChildItem Cert:\LocalMachine -Recurse | ? {$_.Subject -like "E=RBronzov@gmail.com, CN=Rostislav G. Bronzov"} | Move-Item -Destination Cert:\LocalMachine\Trust -Force
    Set-ExecutionPolicy -ExecutionPolicy Bypass -Confirm:$false -Force
    }
end {}
}
Injection-Module