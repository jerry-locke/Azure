#!/bin/sh
resourceGroup=$1
location=$2
deploymentName=$3
templateFile=$4
parameters=$5

az group create --name $resourceGroup --location $location
az group deployment create \
    --name $deploymentName \
    --resource-group $resourceGroup \
    --template-file $templateFile \
    --parameters $parameters