Configuration CompanyIis
{
    Import-DscResource -ModuleName 'companyOps';
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration';
    Import-DscResource -ModuleName 'companyOpsFirewallConfig';
    Import-DscResource -Module xWebAdministration
    Import-DSCResource -Module companyIis
    Import-DSCResource -Module companyNetCore
    Import-DscResource -Name 'xFirewall';	
    Import-DscResource -ModuleName 'PowerShellModule';
    Import-DscResource -ModuleName 'companyComputerManagement';

    Node IisServer
    {
        $websiteFolder = "C:\Websites\CompanyIis"

        $netBiosDomain = Get-AutomationVariable -Name 'AzureAdNetBIOSDomain'
        $domain = Get-AutomationVariable -Name 'AzureAdDomain'
        $creds = Get-AutomationPSCredential -Name 'ADJoinCreds'
        $OpsInsightsWsId = Get-AutomationVariable -Name 'OpsInsightsWsId'
        $OpsInsightsWsKey = Get-AutomationVariable -Name 'OpsInsightsWsKey'
        $AdditionalAdministratorGroup = Get-AutomationVariable -Name 'AdditionalAdministratorGroup'

        companyComputerManagement JoinDomain
        {
            NetBiosDomain = $netBiosDomain
            Domain = $domain
            Creds = $creds
            AdditionalComputerAdministrators = "$netBiosDomain\$AdditionalAdministratorGroup"
        }

        companyOpsFirewallConfig fw
        {

        }

        companyOps Ops
        {
            OpsInsightsWsId = $OpsInsightsWsId
            OpsInsightsWsKey = $OpsInsightsWsKey
        }

        companyIis IIS
        {
        }

        companyNetCore20 NetCore20WindowsHosting
        {
        }

        WindowsFeature NetFramework35
        { 
          Name = "NET-Framework-Features"
          Ensure = "Present"
        }

        File WebsiteFolder
        {
            Ensure = "Present"
            DestinationPath = $websiteFolder
            Type = "Directory"
        }

        xWebAppPool CompanyIisAppPool
        {
            Name = "CompanyIis"
            DependsOn = "[companyIis]IIS"
            Ensure = "Present"
            State = "Started"
            managedRuntimeVersion = ""
        }

        xWebsite CompanyIisWebsite
        {
            Name = "CompanyIis"
            DependsOn = "[xWebAppPool]CompanyIisAppPool", "[File]WebsiteFolder"
            PhysicalPath = $websiteFolder
            State = "Started"
            BindingInfo =   MSFT_xWebBindingInformation 
                            { 
                                Protocol = "HTTP" 
                                Port = 80
                            } 
            ApplicationPool = "CompanyIis"
            Ensure = "Present"
        }
        
        PSModuleResource AzureRM
        {
            Module_Name = 'AzureRM'
            Ensure = 'Present'
        }
    }
}


