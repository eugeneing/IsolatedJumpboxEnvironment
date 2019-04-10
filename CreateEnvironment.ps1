<#

.SYNOPSIS

This is a Powershell script that allows the uesr to create a network, data, and compute isolated environment
with tailored ARM templates and AZ CLI calls. Due to limitations of Powershell parameters sets could not be 
created to limit possible usage syntax. The below description will attempt to outline most flags and valid
usage.

.DESCRIPTION

This is a Powershell script that allows the uesr to create a network, data, and compute isolated environment
with tailored ARM templates and AZ CLI calls. Due to limitations of Powershell parameters sets could not be 
created to limit possible usage syntax. The below description will attempt to outline most flags and valid
usage.

Using -AzureOutput $false will suppress all AZ CLI output. Using -AzureOutput $true will allow all of the
AZ CLI output to be dsiplayed other than the outputs of the deployment calls which variables consume and
utilize for later within the script. The default is that the output is suppressed.

Using -NoPolicy swicth the script will not deploy policy assignments and definitions.

Effectively all subnets in a virtual network are isolated to only allow communication within each individual
subnet. This is defined by the NSG rules.

Data Isolation is achieved with Secrets and Encryption Keys placed in an Azure Keyvault. Can provide your own
key with -BYOKFile, -PEMFile, or -ProtectedPEMFile flags along with the path to the files. -AzureCreatedKey
will have Azure create the key. Only one of "-BYOKFile, -PEMFile, -ProtectedPEMFile, and -AzureCreatedKey"
may be used at a time. If more than one of those is used at time the script will fail midway through and 
exit. -CustomSecret will prompt the user to name their secret to be used in the Keyvault. -CustomKey will 
prompt the user to name their key to be used in the Keyvault. -CustomSecretName will use the name provided 
as the argument as the name of the secret to be placed in the Keyvault. -CustomKeyName will use the name 
provided as the argument as teh name of the key to be placed in the Keyvault. -CustomSecretName and 
-CustomSecret cannot be used simultaneously and will generate an error. Likewise, -CustomKeyName and 
-CustomKey cannot be used simultaneously and will generate an error. The default Key name is StrgEncKey1 and 
the default secret name is jumpboxAdminPass.

Compute Isolation is achieved by the creation of a jumpbox which utilizes a full physical host and has Azure
Disk Encryption enabled. Use this jumpbox to administer the rest of the environement. If you do not wish to 
use our created jumpbox then using the -NoJumpbox switch will not deploy the jumpbox. Default settings create a 
Windows Server 2016 Datacenter. If the -Platform flag is used type WinSrv or Linux. If Linux the jumpbox
created will be Canonical's Ubuntu 16.04 LTS to provide Azure Disk Encryption. Currently 18.04 LTS does not
support Azure Disk Encryption yet. To change the image types please modify the compute_isolation.json file.
Look in the variables section and change the Publisher, Offer, and sku values. 
See https://docs.microsoft.com/en-us/cli/azure/vm/image?view=azure-cli-latest on running the query to
find available publishers, offers, and skus in your location.

NOTE: The individual ARM templates and Powershell scripts can be run independently of this script. Users
will just need to provide the required parameters to execute them.

.PARAMETER AzureOutput
This is a boolean for whether the results of the AZ CLI calls are displayed. The default is for the
output to be suppressed.

.PARAMETER Platform
This takes in a string but will only execute correctly on the values of WinSrv and Linux

.PARAMETER CustomSecret
This is a switch which will cause the user to be prompted for the name of the Secret to be placed in
Keyvault.

.PARAMETER CustomKey
This is a switch which will cause the user to be prompted for the name of the Key to be placed in
Keyvault.

.PARAMETER CustomSecretName
This takes in a string for the name of the Secret to placed in Keyvault

.PARAMETER CustomKeyName
This takes in a string for the name of the Key to placed in Keyvault

.PARAMETER CustomSecretName
This is a switch which will cause the script to prompt for the name of the Secret to placed in Keyvault

.PARAMETER CustomKeyName
This is a switch which will cause the script to prompt for the name of the Key to placed in Keyvault

.PARAMETER AzureCreatedKey
This is a switch which will cause the script to allow Azure to create the Key for the Keyvault

.PARAMETER BYOKFile
This takes a string which will point to a file that will be used for the Key in the Keyvault

.PARAMETER PEMFile
This takes a string which will point to a file that will be used for the Key in the Keyvault

.PARAMETER ProtectedPEMFile
This takes a string which will point to a file that will be used for the Key in the Keyvault

.PARAMETER NoPolicy
This is a switch which will ensure policies are not assigned nor defined.

.PARAMETER NoJumpbox
This is a switch which will not deploy the jumpbox.

#>

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
    [Parameter(ParameterSetName='SecretPrompt',Mandatory=$false)]
    [Parameter(ParameterSetName='KeyPrompt',Mandatory=$false)]
    [Parameter(ParameterSetName='CustomPrompt',Mandatory=$false)]
    [Parameter(ParameterSetName='SecretName',Mandatory=$false)]
    [Parameter(ParameterSetName='KeyName',Mandatory=$false)]
    [Parameter(ParameterSetName='CustomNamed',Mandatory=$false)]
    [Parameter(ParameterSetName='SecretPromptKeyName',Mandatory=$false)]
    [Parameter(ParameterSetName='KeyPromptSecretName',Mandatory=$false)]
    [string]$BYOKFile,
    [Parameter(ParameterSetName='PEM')]
    [Parameter(ParameterSetName='SecretPrompt',Mandatory=$false)]
    [Parameter(ParameterSetName='KeyPrompt',Mandatory=$false)]
    [Parameter(ParameterSetName='CustomPrompt',Mandatory=$false)]
    [Parameter(ParameterSetName='SecretName',Mandatory=$false)]
    [Parameter(ParameterSetName='KeyName',Mandatory=$false)]
    [Parameter(ParameterSetName='CustomNamed',Mandatory=$false)]
    [Parameter(ParameterSetName='SecretPromptKeyName',Mandatory=$false)]
    [Parameter(ParameterSetName='KeyPromptSecretName',Mandatory=$false)]
    [string]$PEMFile,
    [Parameter(ParameterSetName='SPEM')]
    [Parameter(ParameterSetName='SecretPrompt',Mandatory=$false)]
    [Parameter(ParameterSetName='KeyPrompt',Mandatory=$false)]
    [Parameter(ParameterSetName='CustomPrompt',Mandatory=$false)]
    [Parameter(ParameterSetName='SecretName',Mandatory=$false)]
    [Parameter(ParameterSetName='KeyName',Mandatory=$false)]
    [Parameter(ParameterSetName='CustomNamed',Mandatory=$false)]
    [Parameter(ParameterSetName='SecretPromptKeyName',Mandatory=$false)]
    [Parameter(ParameterSetName='KeyPromptSecretName',Mandatory=$false)]
    [string]$ProtectedPEMFile,
    [Parameter(ParameterSetName="AZURE")]
    [Parameter(ParameterSetName='SecretPrompt',Mandatory=$false)]
    [Parameter(ParameterSetName='KeyPrompt',Mandatory=$false)]
    [Parameter(ParameterSetName='CustomPrompt',Mandatory=$false)]
    [Parameter(ParameterSetName='SecretName',Mandatory=$false)]
    [Parameter(ParameterSetName='KeyName',Mandatory=$false)]
    [Parameter(ParameterSetName='CustomNamed',Mandatory=$false)]
    [Parameter(ParameterSetName='SecretPromptKeyName',Mandatory=$false)]
    [Parameter(ParameterSetName='KeyPromptSecretName',Mandatory=$false)]
    [switch]$AzureCreatedKey,
    [switch]$NoJumpbox,
    [switch]$NoPolicy,
    [ValidateSet("WinSrv","Linux")]
    [string]$Platform
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
} else{
    $sub = az account list --query "[].id" --output tsv | Select-Object -First 1
    Write-Host "Operating in the subscription: $sub"
}

Write-Host "Creating Resource Group $resourceGroup in the location $location"
az group create -g $resourceGroup -l $location $outputArg

#Runs the Network Isolation File Locally or from GitHub Depending on Arguments (Still need to work on that)
Write-Host "Deploying network isolation template to resource group $resourceGroup"
$network_outputs = az group deployment create -g $resourceGroup --template-file "$PSScriptRoot\network_isolation\network_isolation.json" --parameters "$PSScriptRoot\network_isolation\network_isolation.parameters.json" --query "properties.outputs"

if (!$network_outputs) {
    Write-Host -ForegroundColor Red "It appears that the az cli call failed for deploying the network isolation template to return a null result. Please see the above error return from the az cli call or check your Azure portal."
    Write-Host "Exiting Script now due to errors"
    Return
}

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
$tempUpdate.parameters.secretsObject.value.secrets = [array]($tempUpdate.parameters.secretsObject.value.secrets | Where-Object {$_.secretName -eq $jbSecretName})

# Convert the parameters to use on az cli
$new_params = $tempUpdate.parameters | ConvertTo-Json -Depth 20 -Compress | ForEach-Object {$_ -replace '"', "'"}

#Runs the Data Isolation File Locally or from GitHub Depending on Arguments (Still need to work on that)
Write-Host "Deploying data isolation template to resource group $resourceGroup"
$data_outputs =  az group deployment create -g $resourceGroup --template-file "$PSScriptRoot\data_isolation\data_isolation.json" --parameters $new_params --parameters objectId="$objectID" --parameters storageAccountName="$strg" --parameters workspaceName="$wksp" --query "properties.outputs"

if (!$data_outputs) {
    Write-Host -ForegroundColor Red "It appears that the az cli call failed for deploying the data isolation template to return a null result. Please see the above error return from the az cli call or check your Azure portal."
    Write-Host "Exiting Script now due to errors"
    Return
}

$keyVN = ([string]$data_outputs | ConvertFrom-Json).keyVaultName.value

# Base Command String to run the encryption key 
$command = "$PSScriptRoot\data_isolation\enckey.ps1 -ResourceGroup $resourceGroup -StorageAccountName $strg -KeyvaultName $keyVN -AzureOutput `$$AzureOutput"

# Build a command string with all the named parameters
if ($CustomKeyName -or $CustomKey){
    $command += " -StorageKey $strgKey" 
}

# Block to Check what the parameters were for keys
if ($BYOKFile -or $AzureOutput -or $PEMFile -or $ProtectedPEMFile){
    if ($BYOKFile -and !($AzureCreatedKey -or $PEMFile -or $ProtectedPEMFile)){
        $command += " -BYOKFile $BYOKFile"
    } elseif ($PEMFile -and !($AzureCreatedKey -or $BYOKFile -or $ProtectedPEMFile)) {
        $command += " -PEMFile $PEMFile"
    } elseif ($ProtectedPEMFile -and !($AzureCreatedKey -or $PEMFile -or $BYOKFile)) {
        $command += " -ProtectedPEMFile $ProtectedPEMFile"
    } elseif ($AzureCreatedKey -and !($BYOKFile -or $PEMFile -or $ProtectedPEMFile)) {
        $command += " -AzureCreatedKey"
    } else {
        Write-Host -ForegroundColor Red "There appears to be an error on your parameters. Most likely you have simultaneously selected multiple ways of providing or creating the encryption key. Only one is allowed despite `"Get-Help`" saying otherwise. This is due to a limitation in the number of parameter sets allowed in Powershell that the options are not better enumerated in `"Get-Help`""
        Return
    }
}

Write-Host "Running enckey.ps1 script to create encryption key in Keyvault $keyVN under resource group $resourceGroup and allow storage account $strg"
Invoke-Expression $command

# Get key vault ID vice just the name of the keyvault
$keyID = az keyvault list -g $resourceGroup --query "[].id" -o tsv

if (!$NoJumpbox){
    <# Grab parameters from a file. Modify them to be able to pass back as a json object as inline parameter #>
    $tempUpdate = Get-Content "$PSScriptRoot\compute_isolation\compute_isolation.parameters.json" -raw | ConvertFrom-Json
    $tempUpdate.parameters.pwdOrssh.reference.keyVault.id = $keyID
    $tempUpdate.parameters.pwdOrssh.reference.secretName = $jbSecretName
    $new_params = $tempUpdate.parameters | ConvertTo-Json -Depth 20 -Compress | ForEach-Object {$_ -replace '"', "'"}

    Write-Host "Deploying compute isolation template to resource group $resourceGroup"
    $compute_outputs = az group deployment create -g $resourceGroup --template-file "$PSScriptRoot\compute_isolation\compute_isolation.json" --parameters $new_params --parameters storageAccountName=$strg --parameters platform=$Platform --query "properties.outputs"

    if (!$compute_outputs) {
        Write-Host -ForegroundColor Red "It appears that the az cli call failed for deploying the compute isolation template to return a null result. Please see the above error return from the az cli call or check your Azure portal."
        Write-Host "Exiting Script now due to errors"
        Return
    }

    #NSG to Update to handle ADE
    $nsgToUpdateforADE = ([string]$compute_outputs | ConvertFrom-Json).nsgToUpdateName.value

    #Need to extend for Data Disks?????
    $disksToEncrypt = @(([string]$compute_outputs | ConvertFrom-Json).osDiskName.value)

    #Created VM Name
    $createdVMName = @(([string]$compute_outputs | ConvertFrom-Json).vmName.value)

    <# Modify NSG to allow VM to reach internet to grab package manager files for dm-crypt based on articles
    https://docs.microsoft.com/en-us/azure/security/azure-security-disk-encryption-tsg
    https://docs.microsoft.com/en-us/azure/security/azure-security-disk-encryption-linux #>
    Write-Host "Creating a temporary rule in NSG $nsgToUpdateforADE named `"TemporaryRuleforADEPackageInstall`""
    az network nsg rule create --resource-group $ResourceGroup --nsg-name $nsgToUpdateforADE --name "TemporaryRuleforADEPackageInstall" --priority 100 --access Allow --direction Outbound --destination-address-prefixes Internet --destination-port-ranges "*" $outputArg

    Write-Host "Running Azure Disk Encryption on VMs $($createdVMName -join ",") on disks $($disksToEncrypt -join ",") using Azure Keyvault $keyVN's encryption key $strgKey"
    $command = "$PSScriptRoot\data_isolation\adekey.ps1 -VMNames $createdVMName -ResourceGroup $resourceGroup -SnapshotSources $disksToEncrypt -KeyvaultName $keyVN -EncryptionKey $strgKey -AzureOutput `$$AzureOutput"
    Invoke-Expression $command

    # Reverse NSG rule to allow reachability to package managers
    Write-Host "Deleting a temporary rule in NSG $nsgToUpdateforADE named `"TemporaryRuleforADEPackageInstall`""
    az network nsg rule delete --resource-group $ResourceGroup --nsg-name $nsgToUpdateforADE --name "TemporaryRuleforADEPackageInstall" $outputArg
}

if(!$NoPolicy){
    Write-Host "Applying Policies to resource group $ResourceGroup"
    # Apply Monitor Policy to DENY the creation of VMs outside of SKUs in .\monitor_policy\allowedvmskus.parameters.json and the creation of new VMs with Public IP resource.
    az policy definition create --name "allowed-vmskus-def" --display-name "Allowed VM SKUs Definitions" --description "This policy defines a white list of VM SKUs can only be deployed." --rules "$PSScriptRoot\monitor_policy\allowedvmskus.rules.json" --params "$PSScriptRoot\monitor_policy\allowedvmskus.parameters.json" --mode All
    az policy assignment create --name "allowed-vmskus-assign" --policy "allowed-vmskus-def" --scope "/subscriptions/$sub/resourcegroups/$resourceGroup"
    az policy definition create --name "deny-publicips-def" --display-name "Deny Public IPs Definitions" --description "This policy defines a rule to deny deployment of public ips." --rules "$PSScriptRoot\monitor_policy\denypublicips.rules.json" --mode All
    az policy assignment create --name "deny-publicips-assign" --policy "deny-publicips-def" --scope "/subscriptions/$sub/resourcegroups/$resourceGroup"
}