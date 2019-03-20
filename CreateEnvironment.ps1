#Write-Host $PSScriptRoot


#gather general information to begin
$username = Read-Host -Prompt "Enter User Name"
$tenant = Read-Host -Prompt "Enter Tenant Id"
$resourceGroup = Read-Host -Prompt "Enter Resource Group Name"
$location = Read-Host -Prompt "Enter Azure Location"
$sub = Read-Host -Prompt "Enter Subscription ID if you don't know press enter"

az cloud set -n AzureUSGovernment
az login -u "$username@$tenant.onmicrosoft.com"
Write-Host $sub
if(!$sub){
    Write-Host "Getting Subscription Id"
    $sub = az account show --query "id"
}
az account set -s $sub

$objectID = (az ad user show --upn-or-object-id "$username@$tenant.onmicrosoft.com" --query "objectId")

az group create -g $resourceGroup -l $location

#Runs the Network Isolation File Locally or from GitHub Depending on Arguments (Still need to work on that)
$network_outputs = az group deployment create -g $resourceGroup --template-file "$PSScriptRoot\network_isolation\network_isolation.json" --parameters "$PSScriptRoot\network_isolation\network_isolation.parameters.json" --query "properties.outputs"
$strg = ([string]$network_outputs | ConvertFrom-Json).storageAccountName.value
$wksp = ([string]$network_outputs | ConvertFrom-Json).workspaceName.value

#Runs the Network Isolation File Locally or from GitHub Depending on Arguments (Still need to work on that)
$data_outputs =  az group deployment create -g testARM --template-file "$PSScriptRoot\data_isolation\data_isolation.json" --parameters "$PSScriptRoot\data_isolation\data_isolation.parameters.json" --parameters objectId="$objectID" --parameters storageAccountName="$strg" --parameters workspaceName="$wksp" --query "properties.outputs"
$keyVN = ([string]$data_outputs | ConvertFrom-Json).keyVaultName.value

$strgKey = "StrgEncKey1"

$key = az keyvault key list-versions --vault-name $keyVN -n $strgKey --query "[?contains(kid, '$strgKey') ].kid" -o tsv

if (!$key){
    az keyvault key create --vault-name $keyVN -n $strgKey --protection software

    $key = az keyvault key list-versions --vault-name $keyVN -n $strgKey --query "[?contains(kid, '$strgKey') ].kid" -o tsv
}

$strgPrin = az storage account list -g $resourceGroup --query "[].identity.principalId" -o tsv

$keysplit = $key.Split('/')

az keyvault set-policy -g $resourceGroup -n $keyVN --object-id "$strgPrin" --key-permissions get unwrapkey wrapkey
az storage account update -g $resourceGroup -n $strg --encryption-key-source "Microsoft.Keyvault" --encryption-key-vault "https://$($keysplit[2])/" --encryption-key-name $keysplit[4] --encryption-key-version $keysplit[5]

$keyID = az keyvault list -g $resourceGroup --query "[].id" -o tsv

$tempUpdate = Get-Content "$PSScriptRoot\compute_isolation\compute_isolation.parameters.json" -raw | ConvertFrom-Json
$tempUpdate.parameters.pwdOrssh.reference.keyVault.id = $keyID
$tempUpdate | ConvertTo-Json -Depth 20 | Set-Content "$PSScriptRoot\compute_isolation\compute_isolation3.parameters.json"

az group deployment create -g $resourceGroup --template-file "$PSScriptRoot\compute_isolation\compute_isolation.json" --parameters "$PSScriptRoot\compute_isolation\compute_isolation3.parameters.json" --parameters storageAccountName=$strg --parameters platform=Linux

az policy definition create --name "allowed-vmskus-def" --display-name "Allowed VM SKUs Definitions" --description "This policy defines a white list of VM SKUs can only be deployed." --rules "$PSScriptRoot\monitor_policy\allowedvmskus.rules.json" --params "$PSScriptRoot\monitor_policy\allowedvmskus.parameters.json" --mode All
az policy assignment create --name "allowed-vmskus-assign" --policy "allowed-vmskus-def" --scope "/subscriptions/$sub/resourcegroups/$resourceGroup"
az policy definition create --name "deny-publicips-def" --display-name "Deny Public IPs Definitions" --description "This policy defines a rule to deny deployment of public ips." --rules "$PSScriptRoot\monitor_policy\denypublicips.rules.json" --mode All
az policy assignment create --name "deny-publicips-assign" --policy "deny-publicips-def" --scope "/subscriptions/$sub/resourcegroups/$resourceGroup"