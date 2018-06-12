<#
 .Example 
  Deploy to existing resource group
cd 'C:\source\NM\Network\Deployments'

#Test
.\deploy.ps1 -subscriptionName 'Visual Studio Enterprise' -resourceGroupName 'NetworkTestRG' -resourceGroupLocation 'eastus2' -templateFilePath ..\Templates\network-template.json -parametersFilePath ..\parameters\network-test-parameters.json -storageAccountResourceGroup 'vseLocal' -storageAccountName 'jlockedevopssource' -storageAccountSubscriptionName 'Visual Studio Enterprise'


 .SYNOPSIS
    Deploys a template to Azure

 .DESCRIPTION
    Deploys an Azure Resource Manager template

 .PARAMETER subscriptionId
    The subscription id where the template will be deployed.

 .PARAMETER resourceGroupName
    The resource group where the template will be deployed. Can be the name of an existing or a new resource group.

 .PARAMETER resourceGroupLocation
    Optional, a resource group location. If specified, will try to create a new resource group in this location. If not specified, assumes resource group is existing.

 .PARAMETER deploymentName
    The deployment name.

 .PARAMETER templateFilePath
    Optional, path to the template file. Defaults to template.json.

 .PARAMETER parametersFilePath
    Optional, path to the parameters file. Defaults to parameters.json. If file is not found, will prompt for parameter values based on template.
#>

param(
 [Parameter(Mandatory=$True)]
 [string]
 $subscriptionName,

 [Parameter(Mandatory=$True)]
 [string]
 $resourceGroupName,
 
 [string]
 $resourceGroupLocation,

 [string]
 $templateFilePath = "template.json",

 [string]
 $parametersFilePath = "parameters.json",

 [string]
 $storageAccountResourceGroup = "",

 [string]
 $storageAccountName = "",

 [string]
 $storageAccountSubscriptionName = ""
)

<#
.SYNOPSIS
    Registers RPs
#>
Function RegisterRP {
    Param(
        [string]$ResourceProviderNamespace
    )

    Write-Host "Registering resource provider '$ResourceProviderNamespace'";
    Register-AzureRmResourceProvider -ProviderNamespace $ResourceProviderNamespace;
}

#******************************************************************************
# Script body
# Execution begins here
#******************************************************************************
$ErrorActionPreference = "Stop"

# sign in
#Write-Host "Logging in...";
#Login-AzureRmAccount;

# select subscription
Write-Host "Selecting subscription '$subscriptionName'";
Select-AzureRmSubscription -SubscriptionName $subscriptionName;

# Register RPs
$resourceProviders = @("microsoft.compute","microsoft.keyvault","microsoft.network","microsoft.servicefabric","microsoft.storage");
if($resourceProviders.length) {
    Write-Host "Registering resource providers"
    foreach($resourceProvider in $resourceProviders) {
        RegisterRP($resourceProvider);
    }
}

#Create or check for existing resource group
$resourceGroup = Get-AzureRmResourceGroup -Name $resourceGroupName -ErrorAction SilentlyContinue
if(!$resourceGroup)
{
    Write-Host "Resource group '$resourceGroupName' does not exist. To create a new resource group, please enter a location.";
    if(!$resourceGroupLocation) {
        $resourceGroupLocation = Read-Host "resourceGroupLocation";
    }
    Write-Host "Creating resource group '$resourceGroupName' in location '$resourceGroupLocation'";
    New-AzureRmResourceGroup -Name $resourceGroupName -Location $resourceGroupLocation
}
else{
    Write-Host "Using existing resource group '$resourceGroupName'";
}

if ($storageAccountName -ne '' -and $storageAccountResourceGroup -ne '' -and (Test-Path $parametersFilePath))
{
    write-output "SA found"
    $parameters = Get-Content -Raw -Path $parametersFilePath | ConvertFrom-Json
    if ($parameters.parameters.sasToken -ne $null)
    {
        Select-AzureRmSubscription -SubscriptionName $storageAccountSubscriptionName
        
        ### Obtain the Storage Account authentication keys using Azure Resource Manager (ARM)
        $keys = Get-AzureRmStorageAccountKey -ResourceGroupName $storageAccountResourceGroup -Name $storageAccountName;

        ### Use the Azure.Storage module to create a Storage Authentication Context
        $storageContext = New-AzureStorageContext -StorageAccountName $storageAccountName -StorageAccountKey $keys[0].Value;
        $storageContext

        ### Create a SAS token for the armtemplates conatiner
        $sasToken = New-AzureStorageContainerSASToken -Name armtemplates -Permission r -Context $storageContext -StartTime (Get-Date) -ExpiryTime (Get-Date).AddHours(1) -Protocol HttpsOnly
        $sasToken

        $parameters.parameters.sasToken.value = $sasToken
        $parameters | ConvertTo-Json -depth 100 | Out-File $parametersFilePath -Encoding 'UTF8'

        Select-AzureRmSubscription -SubscriptionName $subscriptionName;
    }
}

# Start the deployment
Write-Host "Starting deployment...";
if(Test-Path $parametersFilePath) {
    New-AzureRmResourceGroupDeployment -ResourceGroupName $resourceGroupName -TemplateFile $templateFilePath -TemplateParameterFile $parametersFilePath -Verbose;
} else {
    New-AzureRmResourceGroupDeployment -ResourceGroupName $resourceGroupName -TemplateFile $templateFilePath;
}