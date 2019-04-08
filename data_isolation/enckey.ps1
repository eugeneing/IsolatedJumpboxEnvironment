<#

.SYNOPSIS

This is a Powershell script that places an encryption key into Keyvault. The user can have Azure create the 
key or provide their own key file. Then it modifies the Keyvault permissions to allow the Storage Account
provided.

.DESCRIPTION

This is a Powershell script that places an encryption key into Keyvault. The user can have Azure create the 
key or provide their own key file.

There are three required parameters of ResourceGroup, StorageAccountName, and KeyvaultName. These are named 
parameters. ResourceGroup should be the resource group to apply this script to. StorageAccount is the 
storage account which keyvault should allow. KeyvaultName should be the name of the Keyvault where the user
would like to place or use the encryption key.

.PARAMETER AzureOutput
This is a boolean for whether the results of the AZ CLI calls are displayed. The default is for the
output to be suppressed.

.PARAMETER KeyvaultName
This is a string of the name of the Keyvault in which to check for or place the Encryption key

.PARAMETER StorageAccountName
This is a string of the name of the storage account for which needs permission to the Keyvault

.PARAMETER StorageKey
This is a string of the storage encryption key to be placed or checked for.

.PARAMETER ResourceGroup
This is a string of the name of the resource group which the script applies to.

.PARAMETER AzureCreatedKey
This is a switch which will cause the script to allow Azure to create the Key for the Keyvault

.PARAMETER BYOKFile
This takes a string which will point to a file that will be used for the Key in the Keyvault

.PARAMETER PEMFile
This takes a string which will point to a file that will be used for the Key in the Keyvault

.PARAMETER ProtectedPEMFile
This takes a string which will point to a file that will be used for the Key in the Keyvault


#>

[CmdletBinding(DefaultParameterSetName='none')]
param(
    [Parameter(Mandatory=$true)]
    [string]$ResourceGroup,
    [Parameter(Mandatory=$true)]
    [string]$StorageAccountName,
    [Parameter(Mandatory=$true)]
    [string]$KeyvaultName,
    [bool]$AzureOutput = $false,
    [string]$StorageKey,
    [Parameter(ParameterSetName='BYOK')]
    [string]$BYOKFile,
    [Parameter(ParameterSetName='PEM')]
    [string]$PEMFile,
    [Parameter(ParameterSetName='SPEM')]
    [string]$ProtectedPEMFile,
    [Parameter(ParameterSetName="AZURE")]
    [switch]$AzureCreatedKey
)

if($AzureOutput){
    $outputArg=""
} else{
    $outputArg = "-o"+"none"
}

$keyType = ""
$custKeyType = ""
$filename = ""
$PEMPass = ""

if (!$StorageKey){
    $StorageKey = "StrgEncKey1"
}

# List Versions of Key and store based on name of $StorageKey and $KeyvaultName
$key = az keyvault key list-versions --vault-name $KeyvaultName -n $StorageKey --query "[?contains(kid, '$StorageKey') ].kid" -o tsv

# If a key does not exist then create key based on the information provided by $stroagekey 
if (!$key){
    Write-Host "Key $StorageKey was not found in the Keyvault $KeyvaultName"
    
    Do {
        # Check if any of our flags for imported keys are present. 
        if ($BYOKFile -or $PEMFile -or $ProtectedPEMFile){
            $keyType = "2"
        }elseif($AzureCreatedKey){ # Check if we just want an Azure Created Key
            $keyType = "1"
        }
        else{ # Case where we are not provided information about type of key desired.
            $keyType = Read-Host -Prompt "Would you like $StorageKey to be [1] Azure created or [2] Import a key?"
        }

        # Invalid input case
        if(!(($keyType -eq "1") -or ($keyType -eq "2") -or (!$keyType))){
            Write-Host "Invalid Input of `"$keyType`" provided.`n`n Valid input is either 1 or 2.`n"
        } elseif ($keyType -eq "1"){ # If we want an Azure Created Key
            Write-Host "Creating key $StorageKey in Keyvault $KeyvaultName"
            az keyvault key create --vault-name $KeyvaultName -n $StorageKey --protection software $outputArg
        } elseif ($keyType -eq "2"){ # If one of the imported keys is parameterized or user selected to import keys
            Do{ 
                # If one of the parameters provided
                if ($BYOKFile -or $PEMFile -or $ProtectedPEMFile){
                    if ($BYOKFile){
                        $custKeyType = "1"
                        $filename = $BYOKFile
                    } elseif ($PEMFile){
                        $custKeyType = "2"
                        $filename = $PEMFile
                    } elseif ($ProtectedPEMFile){
                        $custKeyType = "3"
                        $filename = $ProtectedPEMFile
                    }
                } else { # Not one of the preselected parameters so prompt user for information.
                    $custKeyType = Read-Host -Prompt "Are you importing a [1] Non-password protected BYOK file [2]  Non-password protected PEM file or [3] Password protected PEM?"
                }

                if (!(($custKeyType -eq "1") -or ($custKeyType -eq "2") -or ($custKeyType -eq "3"))){ # Check for invalid input
                    Write-Host "Invalid Input of `"$custKeyType`" provided.`n`n Valid input is either 1,2,3.`n"
                } elseif ($custKeyType -eq "1"){ # Selected 1 based on prompt for a non-pass protected BYOK file
                    while(!$filename){
                        $filename = Read-Host -Prompt "Please enter the non-password protected BYOK's full filename including the path"
                        if(!$filename){
                            Write-Host "Filename cannot be an empty string"
                        }
                    }

                    Write-Host "Importing non-password protected key file `'$filename`' as key `'$StorageKey`' in Keyvault `'$KeyvaultName`'"
                    az keyvault key import --vault-name $KeyvaultName -n $StorageKey --byok-file $filename --protection software $outputArg
                } elseif ($custKeyType -eq "2"){ # Selected 2 based on prompt for a non-pass protected PEM file
                    while(!$filename){
                        $filename = Read-Host -Prompt "Please enter non-password protected PEM's full filename including the path"
                        if(!$filename){
                            Write-Host "Filename cannot be an empty string"
                        }
                    }
    
                    Write-Host "Importing non-password protected PEM file `'$filename`' as key `'$StorageKey`' in Keyvault `'$KeyvaultName`'"
                    az keyvault key import --vault-name $KeyvaultName -n $StorageKey --pem-file $filename --protection software $outputArg
                } elseif ($custKeyType -eq "3"){ # Selected 3 based on prompt for a pass protected PEM file
                    while(!$filename){
                        $filename = Read-Host -Prompt "Please enter the password protected PEM's full filename including the path"
                        if(!$filename){
                            Write-Host "Filename cannot be an empty string"
                        }
                    }
                    
                    while(!$PEMPass){ # Get User to input password for the password protected PEM file
                        $PEMPass = Read-Host -Prompt "Please enter password for the PEM file $filename" -AsSecureString
                        if(!($PEMPass.Length -gt 0)){
                            Write-Host "Passowrd cannot be an empty string"
                        }
                    }

                    Write-Host "Importing password protected PEM file `'$filename`' as key `'$StorageKey`' in Keyvault `'$KeyvaultName`'"
                    az keyvault key import --vault-name $KeyvaultName -n $StorageKey --pem-file $filename --pem-password $([Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($PEMPass))) --protection software $outputArg
                }
            } while(!(($custKeyType -eq "1") -or ($custKeyType -eq "2") -or ($custKeyType -eq "3")))
        }
    } while(!(($keyType -eq "1") -or ($keyType -eq "2")))
    $key = az keyvault key list-versions --vault-name $KeyvaultName -n $StorageKey --query "[?contains(kid, '$StorageKey') ].kid" -o tsv
}

# Get storage principal for use in data_isolation
$strgPrin = az storage account list -g $ResourceGroup --query "[].identity.principalId" -o tsv | Select-Object -first 1

# Splitting key for use with storage account update
$keysplit = $key.Split('/')

# Allow storage principal to retrieve keys, unwrap keys, and wrap keys
Write-Host "Setting policy for Keyvault $KeyvaultName to allow storage account"
az keyvault set-policy -g $ResourceGroup -n $KeyvaultName --object-id "$strgPrin" --key-permissions get unwrapkey wrapkey $outputArg

#Update stroage account settings with keyvault information
Write-Host "Updating storage account with Keyvault $KeyvaultName information"
az storage account update -g $ResourceGroup -n $StorageAccountName --encryption-key-source "Microsoft.Keyvault" --encryption-key-vault "https://$($keysplit[2])/" --encryption-key-name $keysplit[4] --encryption-key-version $keysplit[5] $outputArg