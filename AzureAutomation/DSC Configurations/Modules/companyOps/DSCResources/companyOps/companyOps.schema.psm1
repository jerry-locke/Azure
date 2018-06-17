Configuration companyOps
{
	param
	(
		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[String[]] $OpsInsightsWsId,

		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[String[]] $OpsInsightsWsKey
	)

	$installFiles = 'c:\Install Files';
	$OIPackageLocalPath = "$installFiles\MMASetup-AMD64.exe";
	$DependencyPackageLocalPath = "$installFiles\InstallDependencyAgent-Windows.exe";

	Import-DscResource -ModuleName 'xComputerManagement';
    Import-DscResource -Module 'PackageManagement' -ModuleVersion 1.1.7.0;
    Import-DscResource -Name 'xRemoteFile';
    Import-DscResource -Name 'cAdministrativeTemplateSetting';
    Import-DscResource -ModuleName 'PowerShellModule';
    Import-DscResource -Name 'xPendingReboot';

	xRemoteFile OIPackage
	{
		Uri = "https://go.microsoft.com/fwlink/?LinkId=828603"
		DestinationPath = $OIPackageLocalPath
		MatchSource = $true
	}

	$installMonitoringAgentSetScript = @"
	`$oArgs= @('/C:"setup.exe /qn ADD_OPINSIGHTS_WORKSPACE=1 OPINSIGHTS_WORKSPACE_ID=$OpsInsightsWsId OPINSIGHTS_WORKSPACE_KEY=$OpsInsightsWsKey AcceptEndUserLicenseAgreement=1"')
	Start-Process '$OIPackageLocalPath' -ArgumentList `$oArgs -NoNewWindow -Wait
"@

	Script InstallMonitoringAgent
	{
		DependsOn = '[xRemoteFile]OIPackage'
		GetScript = {  }
		SetScript = $installMonitoringAgentSetScript
		TestScript = 
		{
			if (gcim Win32_Product -Filter 'Name="Microsoft Monitoring Agent"')
			{
				return $true
			}
			else
			{
				return $false
			}
		}
	}

	Service OIService
	{
			Name = "HealthService"
			State = "Running"
			DependsOn = "[Script]InstallMonitoringAgent"
	}

	PSModuleResource PSWindowsUpdate
    {
		Ensure = "Present"
		Module_Name = 'PSWindowsUpdate'
        InstallScope = "allusers"
        MinimumVersion = '2.0.0.0'
		MaximumVersion = '2.0.0.0'
    }

	File AVScript	# Creates Definition Update powershell script ; Determines and stores the MpCmdRun.exe path in "Defender.path" which it then will read in all subsequent runs.
	{
		DestinationPath = 'C:\Windows\System32\oobe\DefUpd.ps1'
		Ensure = "Present"
		Contents = @"
`$tempDir = `$env:TEMP
`$log = Get-ChildItem `$tempDir -File MpCmdRun.log
if (([math]::Round((`$log.Length/1KB),0)) -ge 512)
{
Remove-Item "`$tempDir\MpCmdRun.log" -Force
}
`$getPath = "`$env:WINDIR\System32\oobe\Defender.path"
if (Test-Path `$getPath)
{
`$mpCmdRun = Get-Content `$getPath
}
else
{
`$pf = `$env:PROGRAMFILES
`$server = "Microsoft Windows Server 2016"
`$desktop = "Microsoft Windows 10"
`$caption = (Get-WmiObject Win32_OperatingSystem).Caption
if ((`$caption -like "`$server*") -or (`$caption -like "`$desktop*"))
{
	`$mpCmdRun = "`$pf\Windows Defender\MpCmdRun.exe"
}
else
{
	`$mpCmdRun = "`$pf\Microsoft Security Client\MpCmdRun.exe"
}
`$val = '"'+`$mpCmdRun+'"'
Add-Content `$getPath -Value `$val -Force
}
`$mpArgs=@('-SignatureUpdate','-MMPC')
`$proc = Start-Process `$mpCmdRun -ArgumentList `$mpArgs -Wait -PassThru
return `$proc.ExitCode
"@
	}

	xScheduledTask AVDefinitionUpdateTask		# The scheduled task that runs the created Definition Update script.
	{
		Ensure = "Present"
		DependsOn = '[File]AVScript'
		TaskName = 'AV Definition Update'
		ScheduleType = 'Daily'
		ActionExecutable = 'powershell.exe'
		ActionArguments = '-ExecutionPolicy Bypass -NonInteractive -WindowStyle Hidden -Command ".\DefUpd.ps1"'
		ActionWorkingPath = 'C:\Windows\System32\oobe'
		DaysInterval = 1
		StartTime = '0:00:00'
		RepeatInterval = '03:00:00'
		RepetitionDuration = '23:59:59'
		RunOnlyIfNetworkAvailable = $true
	}

	cAdministrativeTemplateSetting DisableSrvMgrLogon
	{
		PolicyType = 'Machine'
        Ensure = 'Present'
        Type = 'Dword'
        KeyValueName = 'Software\Policies\Microsoft\Windows\Server\ServerManager\DoNotOpenAtLogon'
        Data = '1'
	}

	xRemoteFile DependencyPackage {
			Uri = "https://aka.ms/dependencyagentwindows"
			DestinationPath = $DependencyPackageLocalPath
	DependsOn = "[Service]OIService"
	}
  
	Script InstallServiceMapDependencyAgent
	{
		DependsOn = "[xRemoteFile]DependencyPackage"
		GetScript = 
		{
				return ""
		}
		SetScript =
		{
			& "c:\Install Files\InstallDependencyAgent-Windows.exe" /S
		}
		TestScript =
		{
			$service = Get-WmiObject -Class Win32_Service -Filter  "Name LIKE 'MicrosoftDependencyAgent'"
			If ($service -ne $null) { return $true } Else { return $false }
		}
	}

	xPendingReboot MMAgentDependencyReboot
	{
			Name = 'After software install'
			SkipComponentBasedServicing = $True
			SkipWindowsUpdate = $False
			SkipPendingFileRename = $True
			SkipPendingComputerRename = $True
			SkipCcmClientSDK = $True
			DependsOn = "[Script]InstallServiceMapDependencyAgent"
	}
}