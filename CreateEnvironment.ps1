#Write-Host $PSScriptRoot
#$username = @{"value"="b-eung";"prompt"="Enter User Name"}
#$tenant = @{"value"="fieldinternaltrials";"prompt"="Enter Tenant Id"}
#$resourceGroup = @{"value"="test";"prompt"="Enter Resource Group Name"}
#$location = @{"value"="usgovvirginia";"prompt"="Enter Azure Location"}
#$sub = @{"value"="";"prompt"="Enter Subscription ID if you don't know press enter"}
#
#
#$custom_variables_list = @{"username"=$username;"tenant"=$tenant;"resourceGroup"=$resourceGroup;"location"=$location;"sub"=$sub}
#
#foreach ($custom_variable in $custom_variables_list.GetEnumerator()){
#    $input = Read-Host -Prompt $custom_variable.Value.Item("prompt")
#    if($input){
#        $custom_variable.Value.Item("value")=$input
#    }
#}


#gather general information to begin
$username = Read-Host -Prompt "Enter User Name"
$tenant = Read-Host -Prompt "Enter Tenant Id"
$resourceGroup = Read-Host -Prompt "Enter Resource Group Name"
$location = Read-Host -Prompt "Enter Azure Location"
$sub = Read-Host -Prompt "Enter Subscription Name if you don't know press enter"

az cloud set -n AzureUSGovernment
az login -u "$username@$tenant.onmicrosoft.com"
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

#SHOULDN'T NEED THE BELOW SINCE WE ALREADY HAVE SECRETS OBJECTS IN THE PARAMETERS FILES THAT MATCH OUR NEEDS
$jbSecretName = "jumpboxAdminPass"

<# CREATING A KEY FOR USE TO USE AS STROAGE ENCRYPTION. BEGINS BY LISTING IF THERE ARE ANY KEYS WITH OUR STORAGE KEY NAME TAKE THE FIRST VERSION IF MORE THAN ONE
IF NONE THEN CREATE A KEY. LATER WILL BE SPLITTING KEY TO USE TO UPDATE STORAGE ACCOUNT. #>
$key = az keyvault key list-versions --vault-name $keyVN -n $strgKey --query "[?contains(kid, '$strgKey') ].kid" -o tsv
if (!$key){
    az keyvault key create --vault-name $keyVN -n $strgKey --protection software

    $key = az keyvault key list-versions --vault-name $keyVN -n $strgKey --query "[?contains(kid, '$strgKey') ].kid" -o tsv
}

#need to have stuff to create jumpbox Secrets and also to do the snapshot as well as create the script to handle the ade to be run post this script
#$jbSecret = az keyvault secret list --vault-name $keyVN --query "[?contains(id, '$jbSecretName') ].id" -o tsv
#while (!$jbSecret) {
    az keyvault secret set --vault-name $keyVN -n $jbSecretName --value $(Read-Host -Prompt "Enter desired password")
#    $jbSecret = az keyvault secret list --vault-name $keyVN --query "[?contains(id, '$jbSecretName') ].id" -o tsv
#}

# Get storage principal for use in data_isolation
$strgPrin = az storage account list -g $resourceGroup --query "[].identity.principalId" -o tsv

# Splitting key for use with storage account update
$keysplit = $key.Split('/')

# Allow storage principal to retrieve keys, unwrap keys, and wrap keys
az keyvault set-policy -g $resourceGroup -n $keyVN --object-id "$strgPrin" --key-permissions get unwrapkey wrapkey


az storage account update -g $resourceGroup -n $strg --encryption-key-source "Microsoft.Keyvault" --encryption-key-vault "https://$($keysplit[2])/" --encryption-key-name $keysplit[4] --encryption-key-version $keysplit[5]

# Get key vault ID vice just the name of the keyvault
$keyID = az keyvault list -g $resourceGroup --query "[].id" -o tsv

<# Grab parameters from a file. We want to be able to pass this eventually as a JSON object so we don't have to write to a new file to be read as well.
Currently replacing keyVault id from Computer Isolation parametes file. Also replacing the secrets name. NEED TO FIGURE OUT WHAT TO DO TO ROTATE SECRETS AND HAVE 
VMs UPDATE WITH THE ROTATED SECRET. CURRENTLY THAT DOESN'T WORK YET. #>
$tempUpdate = Get-Content "$PSScriptRoot\compute_isolation\compute_isolation.parameters.json" -raw | ConvertFrom-Json
$tempUpdate.parameters.pwdOrssh.reference.keyVault.id = $keyID
$tempUpdate.parameters.pwdOrssh.reference.secretName = $jbSecretName
#######$tempUpdate.parameters | ConvertTo-Json -Depth 20 -Compress | % {$_ -replace '"', "'"}
$tempUpdate | ConvertTo-Json -Depth 20 | Set-Content "$PSScriptRoot\compute_isolation\compute_isolation3.parameters.json"

$compute_outputs = az group deployment create -g $resourceGroup --template-file "$PSScriptRoot\compute_isolation\compute_isolation.json" --parameters "$PSScriptRoot\compute_isolation\compute_isolation3.parameters.json" --parameters storageAccountName=$strg --parameters platform=$platform --query "properties.outputs"
#######az group deployment create -g $resourceGroup --template-file "$PSScriptRoot\compute_isolation\compute_isolation.json" --parameters $($tempUpdate.parameters | ConvertTo-Json -Depth 20 -Compress | % {$_ -replace '"', "'"}) --parameters storageAccountName=$strg --parameters platform=Linux

#NSG to Update to handle ADE
$nsgToUpdateforADE = ([string]$compute_outputs | ConvertFrom-Json).nsgToUpdateName.value

#Need to extend for Data Disks?????
$osDiskToEncrypt = ([string]$compute_outputs | ConvertFrom-Json).osDiskName.value

#Created VM Name
$createdVMName = ([string]$compute_outputs | ConvertFrom-Json).vmName.value

#Snapshot name to create
$snapName = $createdVMName + "-SNAP"

<# Modify NSG to allow VM to reach internet to grab package manager files for dm-crypt based on articles
https://docs.microsoft.com/en-us/azure/security/azure-security-disk-encryption-tsg
https://docs.microsoft.com/en-us/azure/security/azure-security-disk-encryption-linux #>
az network nsg rule create --resource-group $resourceGroup --nsg-name $nsgToUpdateforADE --name "TemporaryRuleforADEPackageInstall" --priority 100 --access Allow --direction Outbound --destination-address-prefixes Internet --destination-port-ranges "*"

<# Create snapshot of managed disks based on the articles
https://docs.microsoft.com/en-us/azure/security/azure-security-disk-encryption-windows
https://docs.microsoft.com/en-us/azure/security/azure-security-disk-encryption-linux #>
az snapshot create --resource-group $resourceGroup --name $snapName --source $osDiskToEncrypt

#Enable encryption on VM
az vm encryption enable --resource-group $resourceGroup --name $createdVMName --disk-encryption-keyvault $keyVN --key-encryption-key $strgKey --volume-type All

<# ##Check Loop while az vm encryption show doesn't show encryption succeeded?
$encStatus = az vm encryption show -g $resourceGroup --name $createdVMName --query "substatus[?contains(message, 'Encrypted') ].message" -o tsv
while (!$encStatus){
    #some sort of count timer up for time elapsed for encryption and count and check encryption show for however long

} #>

# Modify NSG to disallow reaching the internet to reverse need for pacakge installation
az network nsg rule delete --name "TemporaryRuleforADEPackageInstall" --resource-group $resourceGroup --nsg-name $nsgToUpdateforADE

# Apply Monitor Policy to DENY the creation of VMs outside of SKUs in .\monitor_policy\allowedvmskus.parameters.json and the creation of new VMs with Public IP resource.
az policy definition create --name "allowed-vmskus-def" --display-name "Allowed VM SKUs Definitions" --description "This policy defines a white list of VM SKUs can only be deployed." --rules "$PSScriptRoot\monitor_policy\allowedvmskus.rules.json" --params "$PSScriptRoot\monitor_policy\allowedvmskus.parameters.json" --mode All
az policy assignment create --name "allowed-vmskus-assign" --policy "allowed-vmskus-def" --scope "/subscriptions/$sub/resourcegroups/$resourceGroup"
az policy definition create --name "deny-publicips-def" --display-name "Deny Public IPs Definitions" --description "This policy defines a rule to deny deployment of public ips." --rules "$PSScriptRoot\monitor_policy\denypublicips.rules.json" --mode All
az policy assignment create --name "deny-publicips-assign" --policy "deny-publicips-def" --scope "/subscriptions/$sub/resourcegroups/$resourceGroup"