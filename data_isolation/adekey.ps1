param(
    [Parameter(Mandatory=$true)]
    [array]$VMNames,
    [Parameter(Mandatory=$true)]
    [string]$ResourceGroup,
    [Parameter(Mandatory=$true)]
    [array]$SnapshotSources,
    [Parameter(Mandatory=$true)]
    [string]$KeyvaultName,
    [Parameter(Mandatory=$true)]
    [string]$EncryptionKey,
    [bool]$AzureOutput = $false
)

if($AzureOutput){
    $outputArg=""
} else{
    $outputArg = "-o"+"none"
}

<# Create snapshot of managed disks based on the articles
https://docs.microsoft.com/en-us/azure/security/azure-security-disk-encryption-windows
https://docs.microsoft.com/en-us/azure/security/azure-security-disk-encryption-linux #>
Write-Host "Running snapshot.ps1 to snapshot VMs $($VMNames -join ",") on disks $($SnapshotSources -join ",")"
.$PSScriptRoot\snapshot.ps1 -VMNames $VMNames -ResourceGroup $ResourceGroup -SnapshotSources $SnapshotSources -AzureOutput $AzureOutput

# Loop through array of VMs to encrypt
foreach ($VMName in $VMNames){
    # Begin VM Encryption
    Write-Host "Enabling Azure Disk Encryption on VM $VMName"
    az vm encryption enable --resource-group $ResourceGroup --name $VMName --disk-encryption-keyvault $KeyvaultName --key-encryption-key $EncryptionKey --volume-type All $outputArg
}