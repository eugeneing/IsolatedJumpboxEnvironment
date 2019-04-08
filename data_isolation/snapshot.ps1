<#

.SYNOPSIS

This is a Powershell script that turns off the VMNames provided, then snapshots the sources (i.e. disks) provided, and 
finally turns on the VMs again once the snapshots are completed.

.DESCRIPTION

This is a Powershell script that turns off the VMNames provided, then snapshots the sources (i.e. disks) provided, and 
finally turns on the VMs again once the snapshots are completed.

There are three required parameters of ResourceGroup, VMNames, and SnapshotSources. These are named parameters. 
ResourceGroup should be the resource group which the user wants this script applied.
VMNames should be a list of all the VMs that need to be snapshot. SnapshotSources should be a list of all the 
sources that need to be snapshot.

.PARAMETER AzureOutput
This is a boolean for whether the results of the AZ CLI calls are displayed. The default is for the
output to be suppressed.

.PARAMETER VMNames
This is a string array for a list of VMs that need to be snapshotted

.PARAMETER ResourceGroup

.PARAMETER SnapshotSources
This is a string array for a list of all the sources(i.e. disks) that will be snapshotted. 

#>
param(
    [Parameter(Mandatory=$true)]
    [array]$VMNames,
    [Parameter(Mandatory=$true)]
    [string]$ResourceGroup,
    [Parameter(Mandatory=$true)]
    [array]$SnapshotSources,
    [bool]$AzureOutput = $false
)

if($AzureOutput){
    $outputArg=""
} else{
    $outputArg = "-o"+"none"
}


# Loop Through All VMs
foreach ($VMName in $VMNames){
    # Turn off VM for best practice in snapshotting
    Write-Host "Stopping VM $VMName"
    az vm stop --resource-group $ResourceGroup --name $VMName $outputArg
}

#Loop through all Snapshot sources
foreach ($SnapshotSource in $SnapshotSources){
    # Make snapshot name based on Source and Date
    $snapName = $SnapshotSource  + "_" + (Get-Date).ToString('MMMddyyyy') + "_Snap"

    # Create the actual snapshot
    Write-Host "Snapshotting $SnapshotSource and saved to snapshot $snapName"
    az snapshot create --resource-group $ResourceGroup --name $snapName --source $SnapshotSource $outputArg
}

# Loop Through All VMs
foreach ($VMName in $VMNames){
    # Turn VM back on after snapshotting
    Write-Host "Starting VM $VMName"
    az vm start --resource-group $ResourceGroup --name $VMName $outputArg
}