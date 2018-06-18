#!/bin/bash
set storageAccountName="jlockeStorage1"
set resourceGroup="StorageRG"
set location="eastus"
set sku="Standard_LRS"
set fileToUpload="DeleteAllWafResourcesByRegion.sh"
set conatiner="jlockeContainer"
set blob="jlockeBlob"
set tableName="jlockeTable"
if [-z "$storageAccountName"]; then
    echo "Storage account name is required";
    exit 1;
fi
if [-z "$resourceGroup"]; then
    echo "Resource group is required";
    exit 1;
fi
if [-z "$location"]; then
    echo "Location is required";
    exit 1;
fi
if [-z "$sku"]; then
    sku="Standard_LRS";
fi
echo "Check Storage account";
az storage account check-name --name $storageAccountName;
#TODO: Add logic to handle storage account name validation. Throw error if name already exists. Else continue.
echo "Creating Storage Account";
az storage account create -n $storageAccountName -g $resourceGroup -l $location --sku $sku;
#TODO: Generate SAS token
echo "Uploading data to the storage account";
az storage blob upload -f $fileToUpload -c $container -n $blob;
echo "Creating Azure Table";
az storage table create --name $tableName;
