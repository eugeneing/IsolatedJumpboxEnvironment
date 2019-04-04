[CmdletBinding(DefaultParameterSetName='none')]
param(
    [bool]$AzureOutput = $false,
    [Parameter(ParameterSetName='CustomPrompt',Mandatory=$true)]
    [Parameter(ParameterSetName='SecretPrompt',Mandatory=$true)]
    [Parameter(ParameterSetName='SecretPromptKeyName',Mandatory=$true)]
    [switch]$CustomSecret,
    [Parameter(ParameterSetName='CustomPrompt',Mandatory=$true)]
    [Parameter(ParameterSetName='KeyPrompt',Mandatory=$true)]
    [Parameter(ParameterSetName='KeyPromptSecretName',Mandatory=$true)]
    [switch]$CustomKey,
    [Parameter(ParameterSetName='SecretName',Mandatory=$true)]
    [Parameter(ParameterSetName='CustomNamed',Mandatory=$true)]
    [Parameter(ParameterSetName='KeyPromptSecretName',Mandatory=$true)]
    [string]$CustomSecretName,
    [Parameter(ParameterSetName='KeyName',Mandatory=$true)]
    [Parameter(ParameterSetName='CustomNamed',Mandatory=$true)]
    [Parameter(ParameterSetName='SecretPromptKeyName',Mandatory=$true)]
    [string]$CustomKeyName,
    [Parameter(ParameterSetName='BYOK')]
    [string]$BYOKFile,
    [Parameter(ParameterSetName='PEM')]
    [string]$PEMFile,
    [Parameter(ParameterSetName='SPEM')]
    [string]$ProtectedPEMFile,
    [Parameter(ParameterSetName="AZURE")]
    [switch]$AzureCreatedKey,
    [switch]$NoJumpbox,
    [switch]$NoPolicy
)

$jbSecretName = ""
$jbSecretValue = ""
$strgKey = ""

if($AzureOutput){
    $outputArg=""
} else{
    $outputArg = "-o"+"none"
}

# Create Objects for User Prompts
$usernameObj = @{"value"="b-eung@fieldinternaltrials.onmicrosoft.com";"prompt"="Enter User Name"}
$resourceGroupObj = @{"value"="testSplit";"prompt"="Enter Resource Group Name to create or apply this script to"}
$locationObj = @{"value"="usgovvirginia";"prompt"="Enter Azure Location"}
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

if (!$CustomSecret -and !$CustomSecretName){ # If a custom secret is not requested
    $jbSecretName = "jumpboxAdminPass"
    Do{
        # Get the password as a secure string
        $jbSecretValue = Read-Host -Prompt "Please enter your password you wish to use for secret `"$jbSecretName`"" -AsSecureString
        if(!($jbSecretValue.Length -gt 0)) { # Check for null input otherwise just accept. Later should extend to do a confirm password setting
            Write-Host "Cannot have a null password"
        }
    } while (!($jbSecretValue.Length -gt 0))
} elseif ($CustomSecretName) { # If the custom secret name is provided as a named parameter
    $jbSecretName = $CustomSecretName
    Do{
        # Get the password as a secure string
        $jbSecretValue = Read-Host -Prompt "Please enter your password you wish to use for secret `"$jbSecretName`"" -AsSecureString
        if(!($jbSecretValue.Length -gt 0)) { # Check for null input otherwise just accept. Later should extend to do a confirm password setting
            Write-Host "Cannot have a null password"
        }
    } while (!($jbSecretValue.Length -gt 0))
} else { # Handle that a custom secret was requested
    Do{
        # Get new secret name
        $jbSecretName = Read-Host -Prompt "Please enter the name of your secret"
        if (!$jbSecretName) { # Check for null input
            Write-Host "You did not enter a valid name"
        }
    } while (!$jbSecretName)
    Do {
        # Get the password as a secure string
        $jbSecretValue = Read-Host -Prompt "Please enter your password you wish to use for secret `"$jbSecretName`"" -AsSecureString
        if (!($jbSecretValue.Length -gt 0)) { # Check for null input otherwise just accept. Later should extend to do a confirm password setting
            Write-Host "Cannot have a null password"
        }
    } while (!($jbSecretValue.Length -gt 0))
}

if (!$CustomKey -and !$CustomKeyName){ # If a custom key is not requested
    $strgKey = "StrgEncKey1"
} elseif ($CustomKeyName){
    $strgKey = $CustomKeyName
}else { # Handle that a custom key was requested
    Do{
        # Get new storage key name
        $strgKey = Read-Host -Prompt "Please enter the name of your storage encryption key"
        if (!$strgKey) { # Check for null input
            Write-Host "You did not enter a valid name"
        }
    } while (!$strgKey)
}

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

# Modify the parameters for data isolation inline. This mainly handles the passwords section of data isolation
$tempUpdate = Get-Content "$PSScriptRoot\data_isolation\data_isolation.parameters.json" -raw | ConvertFrom-Json
if ($tempUpdate.parameters.secretsObject.value.secrets.ForEach({$_.secretName.contains($jbSecretName)}).contains($true)){
    # Find the entry and modify the corresponding secretValue
    foreach ($secret in $tempUpdate.parameters.secretsObject.value.secrets) {
        if ($secret.secretName -eq $jbSecretName){
            $secret.secretValue = $([Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($jbSecretValue)))
        }   
    }
} else {
    # Create the new json object to handle a new secret for custom secret
    $newJSON = [PSCustomObject]@{
        'secretName' = $jbSecretName
        'secretValue' = $([Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($jbSecretValue)))
    }
    # Update the parameters with the new object
    $tempUpdate.parameters.secretsObject.value.secrets += $newJSON
}

# Filter out all other secret objects that aren't $jbSecretName
$tempUpdate.parameters.secretsObject.value.secrets = [array]($tempUpdate.parameters.secretsObject.value.secrets | where {$_.secretName -eq $jbSecretName})

# Convert the parameters to use on az cli
$new_params = $tempUpdate.parameters | ConvertTo-Json -Depth 20 -Compress | ForEach-Object {$_ -replace '"', "'"}

#Runs the Data Isolation File Locally or from GitHub Depending on Arguments (Still need to work on that)
Write-Host "Deploying data isolation template to resource group $resourceGroup"
$data_outputs =  az group deployment create -g $resourceGroup --template-file "$PSScriptRoot\data_isolation\data_isolation.json" --parameters $new_params --parameters objectId="$objectID" --parameters storageAccountName="$strg" --parameters workspaceName="$wksp" --query "properties.outputs"
$keyVN = ([string]$data_outputs | ConvertFrom-Json).keyVaultName.value

$command = "$PSScriptRoot\data_isolation\enckey.ps1 -ResourceGroup $resourceGroup -StorageAccountName $strg -KeyvaultName $keyVN -AzureOutput $AzureOutput -AzureCreatedKey"

<# # Build a command string with all the named parameters
if ($CustomKeyName -or $CustomKey){
    $command += " -StorageKey $strgKey" 
} elseif () #>

Write-Host "Running enckey.ps1 script to create encryption key in Keyvault $keyVN under resource group $resourceGroup and allow storage account $strg"
.$PSScriptRoot\data_isolation\enckey.ps1 -ResourceGroup $resourceGroup -StorageAccountName $strg -KeyvaultName $keyVN -AzureOutput $AzureOutput -AzureCreated

# Get key vault ID vice just the name of the keyvault
$keyID = az keyvault list -g $resourceGroup --query "[].id" -o tsv

if (!$NoJumpbox){
    <# Grab parameters from a file. Modify them to be able to pass back as a json object as inline parameter #>
    $tempUpdate = Get-Content "$PSScriptRoot\compute_isolation\compute_isolation.parameters.json" -raw | ConvertFrom-Json
    $tempUpdate.parameters.pwdOrssh.reference.keyVault.id = $keyID
    $tempUpdate.parameters.pwdOrssh.reference.secretName = $jbSecretName
    $new_params = $tempUpdate.parameters | ConvertTo-Json -Depth 20 -Compress | ForEach-Object {$_ -replace '"', "'"}

    Write-Host "Deploying compute isolation template to resource group $resourceGroup"
    $compute_outputs = az group deployment create -g $resourceGroup --template-file "$PSScriptRoot\compute_isolation\compute_isolation.json" --parameters $new_params --parameters storageAccountName=$strg --parameters platform=WinSrv --query "properties.outputs"

    #NSG to Update to handle ADE
    $nsgToUpdateforADE = ([string]$compute_outputs | ConvertFrom-Json).nsgToUpdateName.value

    #Need to extend for Data Disks?????
    $disksToEncrypt = @(([string]$compute_outputs | ConvertFrom-Json).osDiskName.value)

    #Created VM Name
    $createdVMName = @(([string]$compute_outputs | ConvertFrom-Json).vmName.value)

    $command = "$PSScriptRoot\data_isolation\adekey.ps1"

    Write-Host "Running Azure Disk Encryption on VMs $($createdVMName -join ",") on disks $($disksToEncrypt -join ",") using Azure Keyvault $keyVN's encryption key $strgKey"
    .$PSScriptRoot\data_isolation\adekey.ps1 -VMNames $createdVMName -ResourceGroup $resourceGroup  -NsgName $nsgToUpdateforADE -SnapshotSources $disksToEncrypt -KeyvaultName $keyVN -EncryptionKey $strgKey -AzureOutput $AzureOutput
}

if(!$NoPolicy){
    # Apply Monitor Policy to DENY the creation of VMs outside of SKUs in .\monitor_policy\allowedvmskus.parameters.json and the creation of new VMs with Public IP resource.
    az policy definition create --name "allowed-vmskus-def" --display-name "Allowed VM SKUs Definitions" --description "This policy defines a white list of VM SKUs can only be deployed." --rules "$PSScriptRoot\monitor_policy\allowedvmskus.rules.json" --params "$PSScriptRoot\monitor_policy\allowedvmskus.parameters.json" --mode All
    az policy assignment create --name "allowed-vmskus-assign" --policy "allowed-vmskus-def" --scope "/subscriptions/$sub/resourcegroups/$resourceGroup"
    az policy definition create --name "deny-publicips-def" --display-name "Deny Public IPs Definitions" --description "This policy defines a rule to deny deployment of public ips." --rules "$PSScriptRoot\monitor_policy\denypublicips.rules.json" --mode All
    az policy assignment create --name "deny-publicips-assign" --policy "deny-publicips-def" --scope "/subscriptions/$sub/resourcegroups/$resourceGroup"
}