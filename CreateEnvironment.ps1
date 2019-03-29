param(
    [bool]$AzureOutput = $false
)

if($AzureOutput){
    $outputArg=""
} else{
    $outputArg = "-o"+"none"
}

# Create Objects for User Prompts
$usernameObj = @{"value"="";"prompt"="Enter User Name"}
$resourceGroupObj = @{"value"="";"prompt"="Enter Resource Group Name"}
$locationObj = @{"value"="";"prompt"="Enter Azure Location"}
$subObj = @{"value"="";"prompt"="Enter Subscription name you would like to work in. Hit enter to work in your default subscription"}

# Add all object Prompts to Prompt Hash Table
$custom_variables_list = @{"username"=$usernameObj;"resourceGroup"=$resourceGroupObj;"location"=$locationObj;"sub"=$subObj}

# Loop through user prompt objects
foreach ($custom_variable in $custom_variables_list.GetEnumerator()){
    $input = Read-Host -Prompt $custom_variable.Value.Item("prompt")
    if($input){
        $custom_variable.Value.Item("value")=$input
    }
}


# Gather general information from prompts to begin
$username = $custom_variables_list.username.value
$resourceGroup = $custom_variables_list.resourceGroup.value
$location = $custom_variables_list.location.value
$sub = $custom_variables_list.sub.value
$jbSecretName = "jumpboxAdminPass"
$strgKey = "StrgEncKey1"

Write-Host "Setting Cloud Environment to AzureUSGovernment and logging in with username $username"
az cloud set -n AzureUSGovernment $outputArg
az login -u "$username" $outputArg
if($sub){
    Write-Host "Setting subscription to $sub with username $username"
    az account set -s $sub $outputArg
}

Write-Host "Creating Resource Group $resourceGroup in the location $location"
az group create -g $resourceGroup -l $location $outputArg

#Runs the Network Isolation File Locally or from GitHub Depending on Arguments (Still need to work on that)
Write-Host "Deploying network isolation template to resource group $resourceGroup"
$network_outputs = az group deployment create -g $resourceGroup --template-file "$PSScriptRoot\network_isolation\network_isolation.json" --parameters "$PSScriptRoot\network_isolation\network_isolation.parameters.json" --query "properties.outputs"
$strg = ([string]$network_outputs | ConvertFrom-Json).storageAccountName.value
$wksp = ([string]$network_outputs | ConvertFrom-Json).workspaceName.value

# Gets the object ID based on username
$objectID = (az ad user show --upn-or-object-id "$username" --query "objectId")

#Runs the Network Isolation File Locally or from GitHub Depending on Arguments (Still need to work on that)
Write-Host "Deploying data isolation template to resource group $resourceGroup"
$data_outputs =  az group deployment create -g $resourceGroup --template-file "$PSScriptRoot\data_isolation\data_isolation.json" --parameters "$PSScriptRoot\data_isolation\data_isolation.parameters.json" --parameters objectId="$objectID" --parameters storageAccountName="$strg" --parameters workspaceName="$wksp" --query "properties.outputs"
$keyVN = ([string]$data_outputs | ConvertFrom-Json).keyVaultName.value

Write-Host "Running enckey.ps1 script to create encryption key in Keyvault $keyVN under resource group $resourceGroup and allow storage account $strg"
.$PSScriptRoot\data_isolation\enckey.ps1 -ResourceGroup $resourceGroup -StorageAccountName $strg -KeyvaultName $keyVN -AzureOutput $AzureOutput

# Get key vault ID vice just the name of the keyvault
$keyID = az keyvault list -g $resourceGroup --query "[].id" -o tsv

<# Grab parameters from a file. Modify them to be able to pass back as a json object as inline parameter #>
$tempUpdate = Get-Content "$PSScriptRoot\compute_isolation\compute_isolation.parameters.json" -raw | ConvertFrom-Json
$tempUpdate.parameters.pwdOrssh.reference.keyVault.id = $keyID
$tempUpdate.parameters.pwdOrssh.reference.secretName = $jbSecretName
$new_params = $tempUpdate.parameters | ConvertTo-Json -Depth 20 -Compress | % {$_ -replace '"', "'"}
#######$tempUpdate | ConvertTo-Json -Depth 20 | Set-Content "$PSScriptRoot\compute_isolation\compute_isolation3.parameters.json"

#######$compute_outputs = az group deployment create -g $resourceGroup --template-file "$PSScriptRoot\compute_isolation\compute_isolation.json" --parameters "$PSScriptRoot\compute_isolation\compute_isolation3.parameters.json" --parameters storageAccountName=$strg --parameters platform=$platform --query "properties.outputs"
Write-Host "Deploying compute isolation template to resource group $resourceGroup"
$compute_outputs = az group deployment create -g $resourceGroup --template-file "$PSScriptRoot\compute_isolation\compute_isolation.json" --parameters $new_params --parameters storageAccountName=$strg --parameters platform=WinSrv --query "properties.outputs"

#NSG to Update to handle ADE
$nsgToUpdateforADE = ([string]$compute_outputs | ConvertFrom-Json).nsgToUpdateName.value

#Need to extend for Data Disks?????
$disksToEncrypt = @(([string]$compute_outputs | ConvertFrom-Json).osDiskName.value)

#Created VM Name
$createdVMName = @(([string]$compute_outputs | ConvertFrom-Json).vmName.value)

Write-Host "Running Azure Disk Encryption on VMs $($createdVMName -join ",") on disks $($disksToEncrypt -join ",") using Azure Keyvault $keyVN's encryption key $strgKey"
.$PSScriptRoot\data_isolation\adekey.ps1 -VMNames $createdVMName -ResourceGroup $resourceGroup  -NsgName $nsgToUpdateforADE -SnapshotSources $disksToEncrypt -KeyvaultName $keyVN -EncryptionKey $strgKey -AzureOutput $AzureOutput

# Apply Monitor Policy to DENY the creation of VMs outside of SKUs in .\monitor_policy\allowedvmskus.parameters.json and the creation of new VMs with Public IP resource.
az policy definition create --name "allowed-vmskus-def" --display-name "Allowed VM SKUs Definitions" --description "This policy defines a white list of VM SKUs can only be deployed." --rules "$PSScriptRoot\monitor_policy\allowedvmskus.rules.json" --params "$PSScriptRoot\monitor_policy\allowedvmskus.parameters.json" --mode All
az policy assignment create --name "allowed-vmskus-assign" --policy "allowed-vmskus-def" --scope "/subscriptions/$sub/resourcegroups/$resourceGroup"
az policy definition create --name "deny-publicips-def" --display-name "Deny Public IPs Definitions" --description "This policy defines a rule to deny deployment of public ips." --rules "$PSScriptRoot\monitor_policy\denypublicips.rules.json" --mode All
az policy assignment create --name "deny-publicips-assign" --policy "deny-publicips-def" --scope "/subscriptions/$sub/resourcegroups/$resourceGroup"