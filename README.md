# Azure ARM Templates
- Holds all Azure Resource Manager templates for the Network and VMs
- All VMs that need to be encrypted are stored under VmEncryption
- All ARM templates are developed to be used against pre production and production environments
- Under each ARM Template category there are three directories: Deployments, Parameters, and Templates. This is to make it easy for the engineer to know what type of files they are working with without seeing the content and more importantly make it a consistent and easy way to find the files you are looking for.

# Azure Shell Scripts
- These are a few examples of Azure Shell Scripts that can be used for a wide array of items including:
* deleteing specific resources by region
* deploying ARM Templates
* storage exercizes

# AzureAutomation
- This is where DSC Configurations live.
- Under DSC Configurations we have Modules and nodes. 
- companyComputerManagement primary function is for AD joining virtual machines
- companyIis primary function is to install IIS
- companyNetCore primary function is to install .Net Core
- companyNginx primary function is to install Nginx
- companyOps primary function is to install Operation components on virtual machines such as OMS agents
- copmanyOpsFirewallConfig is to configure virtual machines with the proper firewall rules to be able to communicate with the proper operations systems.
## Nodes:
### IisServer:
- Here we define where the website is going to live on the vm ($websiteFolder)
- Then we define the domain and ops info. Also we can set any additional administrators groups to be added at this time. 
- From there we call to the companyComputer management resource to join to AD, copmanyOpsFirewallConfig to set the default firewall rules, companyOps to setup the agents to OMS, IIS to install IIS, .Net Core and .Net 3.5 (to show that we can do both). In this example we are requiring that .Net 3.5 is present. Additionally we are making sure that the folder where the website file are to be deployed exists and if it doesn't exist - then add it. 
- From there we add the AppPool and site bindings.
- Last we add the AzureRM powershell module so that we can execute AzureRM commands from that VM if need be.
### Nginx install
- This is a standard install of nginx that uses an Ubuntu Linux box. Also nginx configs are not held here. The idea is that we would keep the configuration files in source control and deploy any config changes through the build and deployment pipeline.
