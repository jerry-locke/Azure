Configuration companyComputerManagement
{
    param
    (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String[]] $NetBiosDomain,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String] $Domain,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [PSCredential] $Creds,

        [Parameter()]
        [String[]] $AdditionalComputerAdministrators
    )

    Import-DscResource -Name xComputer
    Import-DscResource -Name xPendingReboot

    xComputer JoinDomain
    {
        Name = 'localhost'
        DomainName = $Domain
        Credential = $Creds
    }

    xPendingReboot DomainJoinReboot
    { 
        Name = 'BeforeSoftwareInstall'
        SkipComponentBasedServicing = $True
        SkipWindowsUpdate = $True
        SkipPendingFileRename = $True
        SkipPendingComputerRename = $False
        SkipCcmClientSDK = $True
        DependsOn = "[xComputer]JoinDomain"
    }
    LocalConfigurationManager
    {
        RebootNodeIfNeeded = $True
    }

    $AdminArray = @("$NetBiosDomain\CloudOperations", "$NetBiosDomain\AAD DC Administrators")

    if ($AdditionalComputerAdministrators)
    {
        $AdminArray = $AdminArray + $AdditionalComputerAdministrators
    }

    Group AddADUserToLocalAdminGroup
    {
        GroupName='Administrators'   
        Ensure= 'Present'             
        MembersToInclude= $AdminArray
        Credential = $Creds  
        DependsOn = "[xPendingReboot]DomainJoinReboot"
    }
    