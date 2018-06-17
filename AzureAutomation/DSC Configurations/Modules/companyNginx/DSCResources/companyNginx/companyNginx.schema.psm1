Configuration companyNginx
{
	Import-DSCResource -Module nx

    nxPackage InstallNginx
    {
		Name           = "Nginx"
		Ensure         = "Present"
		PackageManager = "Apt"
		DependsOn      = ""
	}

    nxScript UpgradeNginx
    {
		SetScript  = @"
#!/bin/bash         
apt update
apt -f install
echo "N" | apt upgrade nginx -y -qq
service nginx restart
"@
		TestScript = @"
#!/bin/bash
if nginx -v | grep -q 'version 1.6'; then
    exit 1
else
    exit 0
fi   

"@
		GetScript  = ""
		DependsOn  = "[nxPackage]InstallNginx"
	}

    nxService NginxService
    {
		Name       = "Nginx"
		Controller = "systemd"
		Enabled    = $true
		State      = "Running"
		DependsOn  = "[nxScript]UpgradeNginx"
	}
}
