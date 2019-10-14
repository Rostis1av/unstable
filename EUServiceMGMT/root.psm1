function global:prompt{
    Write-Host ((Get-Date -f "HH:mm:ss")+" $env:USERDNSDOMAIN\$env:USERNAME") -ForegroundColor Yellow
    Write-Host (Get-Location)">>>" -NoNewLine
    $Host.UI.RawUI.WindowTitle=((Get-Date -f "HH:mm:ss")+" $env:USERDNSDOMAIN\$env:USERNAME")
    return " "
}