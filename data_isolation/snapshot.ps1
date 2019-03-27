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