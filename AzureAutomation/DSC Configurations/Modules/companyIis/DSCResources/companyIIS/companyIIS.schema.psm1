Configuration CompanyIis
{
    WindowsFeature IIS 
    { 
      Name = "Web-Server"
      Ensure = "Present"
    }

    WindowsFeature IIS-ManagementConsole
    {
        Name = "Web-Mgmt-Console"
        DependsOn = "[WindowsFeature]IIS"
        Ensure = "Present"
    }

    WindowsFeature IIS-ManagementService
    {
        Name = "Web-Mgmt-Service"
        DependsOn = "[WindowsFeature]IIS"
        Ensure = "Present"
    }

    WindowsFeature IIS-CustomLogging
    {
        Name = "Web-Custom-Logging"
        DependsOn = "[WindowsFeature]IIS"
        Ensure = "Present"
    }

    WindowsFeature IIS-HttpCompressionStatic
    {
        Name = "Web-Stat-Compression"
        DependsOn = "[WindowsFeature]IIS"
        Ensure = "Present"
    }

    WindowsFeature IIS-HttpCompressionDynamic
    {
        Name = "Web-Dyn-Compression"
        DependsOn = "[WindowsFeature]IIS"
        Ensure = "Present"
    }

    WindowsFeature ASPNet45 
    { 
      Name = "Web-Asp-Net45"
      DependsOn = "[WindowsFeature]IIS"
      Ensure = "Present"
    }

    WindowsFeature WebNetExt45 
    { 
      Name = "Web-Net-Ext45"
      DependsOn = "[WindowsFeature]IIS"
      Ensure = "Present"
    }

    xWebsite DefaultWebsite
    {
        Name = "Default Web Site"
        DependsOn = "[WindowsFeature]IIS"
        Ensure = "Absent"
    }

    xWebAppPool DefaultAppPool
    {
        Name = "DefaultAppPool"
        DependsOn = "[WindowsFeature]IIS"
        Ensure = "Absent"
    }

    xWebAppPool Net45
    {
        Name = ".NET v4.5"
        DependsOn = "[WindowsFeature]IIS"
        Ensure = "Absent"
    }

    xWebAppPool Net45Classic
    {
        Name = ".NET v4.5 Classic"
        DependsOn = "[WindowsFeature]IIS"
        Ensure = "Absent"
    }
}
