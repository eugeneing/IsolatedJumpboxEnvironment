param(
    [Parameter(Mandatory=$true)]
    [string]$ResourceGroup,
    [Parameter(Mandatory=$true)]
    [string]$StorageAccountName,
    [Parameter(Mandatory=$true)]
    [string]$KeyvaultName,
    [bool]$AzureOutput = $false,
    [string]$StorageKey
)

if($AzureOutput){
    $outputArg=""
} else{
    $outputArg = "-o"+"none"
}

if (!$StorageKey){
    $StorageKey = "StrgEncKey1"
}

# List Versions of Key and store based on name of $StorageKey and $KeyvaultName
$key = az keyvault key list-versions --vault-name $KeyvaultName -n $StorageKey --query "[?contains(kid, '$StorageKey') ].kid" -o tsv

# If a key does not exist then create key based on the informatio provided by $stroagekey 
if (!$key){
    Write-Host "Creating key $StorageKey in Keyvault $KeyvaultName"
    az keyvault key create --vault-name $KeyvaultName -n $StorageKey --protection software $outputArg

    $key = az keyvault key list-versions --vault-name $KeyvaultName -n $StorageKey --query "[?contains(kid, '$StorageKey') ].kid" -o tsv
}

# Get storage principal for use in data_isolation
$strgPrin = az storage account list -g $ResourceGroup --query "[].identity.principalId" -o tsv | select -first 1

# Splitting key for use with storage account update
$keysplit = $key.Split('/')

# Allow storage principal to retrieve keys, unwrap keys, and wrap keys
Write-Host "Setting policy for Keyvault $KeyvaultName to allow storage account"
az keyvault set-policy -g $ResourceGroup -n $KeyvaultName --object-id "$strgPrin" --key-permissions get unwrapkey wrapkey $outputArg

#Update stroage account settings with keyvault information
Write-Host "Updating storage account with Keyvault $KeyvaultName information"
az storage account update -g $ResourceGroup -n $StorageAccountName --encryption-key-source "Microsoft.Keyvault" --encryption-key-vault "https://$($keysplit[2])/" --encryption-key-name $keysplit[4] --encryption-key-version $keysplit[5] $outputArg