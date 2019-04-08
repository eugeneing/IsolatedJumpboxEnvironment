<#

.SYNOPSIS

This is a Powershell script that enables Azure Disk Encryption on the VMNames provided.

.DESCRIPTION

This is a Powershell script that enables Azure Disk Encryption on the VMNames provided.

Prior to doing so it calls a snapshot script to snapshot the VMs as outlined by the articles 
https://docs.microsoft.com/en-us/azure/security/azure-security-disk-encryption-windows
https://docs.microsoft.com/en-us/azure/security/azure-security-disk-encryption-linux
prior to being able to enable Azure Disk Encryption.

There are three required parameters of ResourceGroup, VMNames, SnapshotSources, KeyvaultName, and EncryptionKey.
These are named parameters. ResourceGroup should be a string for the resouce group this is being applied to.
VMNames should be a list of all the VMs that need to be snapshot. SnapshotSources 
should be a list of all the sources that need to be snapshot. KeyvaultName should be the name of the Keyvault 
with the EncryptionKey in it.

.PARAMETER AzureOutput
This is a boolean for whether the results of the AZ CLI calls are displayed. The default is for the
output to be suppressed.

.PARAMETER VMNames
This is a string array for a list of VMs that need to be snapshotted

.PARAMETER ResourceGroup
This is a string for the resource group which it will be applied.

.PARAMETER SnapshotSources
This is a string array for a list of all the sources(i.e. disks) that will be snapshotted.

.PARAMETER EncryptionKey
This is a string of the encryption key with which to run Azure Disk Encryption.

.PARAMETER KeyvaultName
This is a string of the name of the Keyvault where the EncryptionKey is stored.

#>

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