#!/bin/bash
echo "deleting first waf"
az vm delete --name wafpreprodsc-0 --resource-group wafpreprodrg --yes; 
echo "deleting second waf"
az vm delete --name wafpreprodsc-1 --resource-group wafpreprodrg --yes;
echo "deleting first nic"
az network nic delete --resource-group wafpreprodrg --name wafpreprodsc-nic-0;
echo "deleting second nic"
az network nic delete --resource-group wafpreprodrg --name wafpreprodsc-nic-1;
echo "deleting storage account"
az storage account delete --name wafpreprodscuswafsa --resource-group wafpreprodrg --yes;
echo "deleting availability set"
az vm availability-set delete --name wafpreprodsc-AvSet --resource-group wafpreprodrg;
echo "deleting load balancer"
az network lb delete --name southcentralus-waf-lb --resource-group wafpreprodrg;



