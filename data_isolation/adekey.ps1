param(
    [Parameter(Mandatory=$true)]
    [array]$VMNames,
    [Parameter(Mandatory=$true)]
    [string]$ResourceGroup,
    [Parameter(Mandatory=$true)]
    [string]$NsgName,
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

<# Modify NSG to allow VM to reach internet to grab package manager files for dm-crypt based on articles
https://docs.microsoft.com/en-us/azure/security/azure-security-disk-encryption-tsg
https://docs.microsoft.com/en-us/azure/security/azure-security-disk-encryption-linux #>
az network nsg rule create --resource-group $ResourceGroup --nsg-name $NsgName --name "TemporaryRuleforADEPackageInstall" --priority 100 --access Allow --direction Outbound --destination-address-prefixes Internet --destination-port-ranges "*" $outputArg

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

# Reverse NSG rule to allow reachability to package managers
az network nsg rule delete --resource-group $ResourceGroup --nsg-name $NsgName --name "TemporaryRuleforADEPackageInstall" $outputArg