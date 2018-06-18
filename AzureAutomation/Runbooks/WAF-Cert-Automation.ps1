<#
.SYNOPSIS
Barracuda WAF Cert Automation

.DESCRIPTION
Pulls certs from the Azure Key Vault to a Hybrid Worker.
Imports cert into Hybrid Worker and Exports a signed cert, key, and intermediary cert.
Uses a RESTful API client to communicate with the WAF.
Validates cert serial numbers between the Key Vault and the WAF to ensure only modified certs get updated.
Uploads cert to the WAF upon successful validation.
Binds specific certs to specific URLs based on the sniConfig input object.

.PARAMETER CertNames
Certname from the vault 
Example: [{"CertName":"SomeCert"},{"CertName":"SomeOtherCert"}]

.PARAMETER VaultName
Azure Key Vault Name

.PARAMETER ResourceGroupName
Azure Key Vault Resource Group Name

.PARAMETER WafIp
IP address only. Do not include the port or the protocol.

.PARAMETER Port
Integer:
HTTP: 8000
HTTPS: 8443

.PARAMETER CertSuffix
This defaults to the date, but you can override this with whatever suffix you want.
An example for overriding this would be if you needed to run this script multiple times in the same day.
#>

param
(
	[Parameter (Mandatory= $true)]
	[string] $certNames,
	[Parameter (Mandatory=$true)]
	[string] $VaultName,
	[Parameter (Mandatory=$true)]
	[string] $ResourceGroupName,
	[Parameter (Mandatory= $true)]
	[ValidateNotNullOrEmpty()] 
	[string] $wafIp,
	[Parameter (Mandatory= $false)] 
	[int] $port=8000,
	[Parameter (Mandatory= $false)]
	[string] $Protocol = "https",
    [Parameter (Mandatory=$false)]
    [string] $CertSuffix
)

$tempDirectory = 'C:\temp'
# Set assembly variables 
$restSharpDllPath = "$tempDirectory\RestSharp.dll"
# Load RestSharp
if (!(Test-Path $restSharpDllPath))
{
  Invoke-WebRequest -Uri "https://raldevops.blob.core.windows.net/publicarmresources/RestSharp/RestSharp.dll" -OutFile $restSharpDllPath
}
Add-Type -Path $restSharpDllPath

# Set base variables
if(!(test-path $tempDirectory))
{
  mkdir -p $tempDirectory
}

$baseUrl = "$($protocol)://$($wafIp):$($port)"

if(!$certSuffix)
{
    $certSuffix = get-date -UFormat "%Y%m%d"
}


$sniCertificates = New-Object System.Collections.ArrayList
$sniDomains = New-Object System.Collections.ArrayList
$postRequest = New-Object RestSharp.RestRequest([RestSharp.Method]::POST);
$getRequest = New-Object RestSharp.RestRequest([RestSharp.Method]::GET);
$putRequest = New-Object RestSharp.RestRequest([RestSharp.Method]::PUT);



$tenantId = Get-AutomationVariable -Name 'TenantId'
$creds = Get-AutomationPSCredential -Name 'CertBotCreds'
$subscriptionId = Get-AutomationVariable -Name 'SubscriptionId'
Write-Output "Authenticating using CertBotCreds account: tenant: $tenantId creds: $($creds.username) subscriptionId: $subscriptionId" -Verbose
Add-AzureRmAccount -Credential $creds -ServicePrincipal -TenantId $tenantId -SubscriptionId $subscriptionId


function DownloadCertToHybridWorker($certName)
{

	# Try to retrieve the key vault.
	$keyVault = Get-AzureRMKeyVault -VaultName $VaultName -ResourceGroupName $ResourceGroupName 
	if ($keyVault -eq $null)
	{
		throw "Could not retrieve key vault $VaultName. Check that a key vault with this name exists in the resource group $ResourceGroupName."
	}

	$pfxSecret = Get-AzureKeyVaultSecret -VaultName $VaultName -Name $certName  
	if ($pfxSecret -eq $null)
	{
		throw "Could not retrieve cert $certName. Check that a cert with this name exists in this key vault."
	}

	#Set the password used for this certificate
	$Private:OFS=""
	$PasswordLength = 63
	$PwCharacters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ23456789'

	$RandomNums = 1..$PasswordLength | ForEach-Object { Get-Random -Maximum $PwCharacters.Length }
	$pw = [String]$PwCharacters[$RandomNums]
	$secPw = ConvertTo-SecureString -String $pw -AsPlainText -Force

	write-output "building pfx..."
	$pfxUnprotectedBytes = [Convert]::FromBase64String($pfxSecret.SecretValueText)
	$pfx = New-Object Security.Cryptography.X509Certificates.X509Certificate2
	$pfx.Import($pfxUnprotectedBytes, $null, [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
	$pfxProtectedBytes = $pfx.Export([Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12, $secPw)

	$certPrivateFileName = $certName + ".pfx"
	$certPublicFileName = $certName + ".pem"
	$certIntermetiateFileName = $certName + "-intermediate.pem"
	$serverKeyFileName = $certName + "-server-key.pem"
	$pfxPath = "c:\temp\$certPrivateFileName"
	$pemPath = "c:\temp\$certPublicFileName"
	$keyPath = "c:\temp\$serverKeyFileName"
	$intermediatePath = "c:\temp\$certIntermetiateFileName"
	[IO.File]::WriteAllBytes($pfxPath, $pfxProtectedBytes)

	Import-PfxCertificate -FilePath $pfxPath Cert:\LocalMachine\My -Password $secPw -Exportable -outvariable certInfo
	$thumbprint = $certInfo.Thumbprint
	Get-ChildItem -Path cert:\localMachine\my\$thumbprint | Export-PfxCertificate -FilePath $pfxPath -Password $secPw -ChainOption BuildChain

	$opensslInstallPath = 'c:\temp\opensslInstall\'
	$opensslPath = "$opensslInstallPath\openssl.exe"

	if(!(test-path $opensslPath))
	{
		mkdir -p $opensslInstallPath
		$url = "https://raldevops.blob.core.windows.net/publicarmresources/OpenSSL/openssl-1.0.2n-i386-win32.zip"
		$compressedFile = "$opensslInstallPath\openssl.zip"
		Invoke-WebRequest -Uri $url -OutFile $compressedFile

		Add-Type -assembly "system.io.compression.filesystem"
		[io.compression.zipfile]::ExtractToDirectory($compressedFile, $opensslInstallPath)
	}

	$argsKey = "pkcs12 -in $pfxPath -out $keyPath -nocerts -nodes -password pass:$pw"
	$argsCerts = "pkcs12 -in $pfxPath -out $pemPath -nokeys -clcerts -nodes -passin pass:$pw -passout pass:"
	$argsCaCerts = "pkcs12 -in $pfxPath -out $intermediatePath -cacerts -nodes -password pass:$pw"

	write-output "extracting key..."
	start-process $openSslPath -argumentList $argsKey -NoNewWindow -Wait
	if (test-path $keyPath)
	{
		write-output "key extracted to $keyPath"   
	}
	else
	{
		write-output "key extraction process failed"
		exit 1
	}

	start-sleep -s 10
	write-output "extracting client cert..."
	start-process $openSslPath -argumentList $argsCerts -NoNewWindow -Wait
	if (test-path $pemPath)
	{
		write-output "cert extracted to $pemPath"   
	}
	else
	{
		write-output "cert extraction process failed"
		exit 1
	}

	start-sleep -s 10
	write-output "extracting ca cert..."
	start-process $openSslPath -argumentList $argsCaCerts -NoNewWindow -Wait

	$icert = get-content $intermediatePath -tail 30
	set-content -Path $intermediatePath -value $icert
	if (test-path $intermediatePath)
	{
		write-output "intermediate cert extracted to $intermediatePath"   
	}
	else
	{
		write-output "intermediate cert extraction process failed"
		exit 1
	}

	write-output "removing $pfxPath"
	remove-item $pfxPath -force
	write-output "pfx file removed"	
}

#Begin WAF API communications
class WafApiClient
{
	[String] $baseUrl;
	[String] $vaultName;
	[Object] $postRequest;
	[Object] $getRequest;
	[Object] $putRequest;
	[String] $certSuffix;
	[String] $token;

	WafApiClient($postRequest, $getRequest, $putRequest, $baseUrl, $certSuffix)
	{
		$this.postRequest = $postRequest
		$this.getRequest = $getRequest
		$this.putRequest = $putRequest
		$this.baseUrl = $baseUrl
		$this.certSuffix = $certSuffix
		$this.token = $this.GetBearerToken()
	}

	UploadCert($certName)
	{
		$this.postRequest.AddHeader("authorization", "Basic $($this.token)");
		$this.postRequest.AddHeader("accept", "application/json");
		$basePemPath = "c:\\temp\\"
		$certEnc = $basePemPath+$certName+".pem"
		$keyEnc = $basePemPath+$certName+"-server-key.pem"
		$iCertEnc = $basePemPath+$certName+"-intermediate.pem"
		$this.postRequest.AddParameter("name", "$($certName)-$($this.certSuffix)");
		$this.postRequest.AddParameter("type", "pem");
		$this.postRequest.AddParameter("key_type", "rsa");
		$this.postRequest.AddFile("signed_certificate", "$certEnc", "application/octet-stream");
		$this.postRequest.AddFile("intermediary_certificate", "$iCertEnc", "application/octet-stream");
		$this.postRequest.AddParameter("assign_associated_key", "no");
		$this.postRequest.AddFile("key", "$keyEnc", "application/octet-stream");
		$this.postRequest.AddParameter("allow_private_key_export", "no");

		$clientUploadCert = New-Object RestSharp.RestClient("$($this.baseUrl)/restapi/v3/certificates?upload=signed");
		$response = $clientUploadCert.Execute($this.postRequest);
        if($response.ResponseStatus -eq "Error")
		{
			throw("Error in WafCert::UploadCert. $($response.ErrorException) ")
		} 
		else 
		{
            $this.ValidateCertUpload($response, $basePemPath)
		}
		
	}

	[object] BindCert($sniDomains, $sniCertificates)
	{
		$this.putRequest.AddHeader("authorization", "Basic $($this.token)");
		$this.putRequest.AddHeader("accept", "application/json");
		$body = @{
			"ciphers" = "Custom"; 
			"enable-sni" = "yes"; 
			"certificate" = $sniCertificates[0];
			"status" = "On";
			"hsts-max-age" = 365;
			"enable-strict-sni-check" = "Yes";
			"sni-certificate" = $sniCertificates;
			"ecdsa-certificate" = "";
			"domain" = $sniDomains;
			"override-ciphers-ssl3" = "";
			"override-ciphers-tls-1" = "";
			"override-ciphers-tls-1-1" = "";
			"enable-ssl-3" = "No";
			"enable-tls-1-1" = "Yes";
			"enable-hsts" = "Yes";
			"enable-tls-1-2" = "Yes";
			"include-hsts-sub-domains" = "Yes";
			"sni-ecdsa-certificate" = "";
			"selected-ciphers" = "ECDHE-ECDSA-AES256-GCM-SHA384,ECDHE-RSA-AES256-GCM-SHA384,ECDHE-ECDSA-AES128-GCM-SHA256,ECDHE-RSA-AES128-GCM-SHA256,ECDHE-ECDSA-AES256-SHA384,ECDHE-RSA-AES256-SHA384,ECDHE-ECDSA-AES128-SHA256,ECDHE-RSA-AES128-SHA256,AES256-GCM-SHA384,AES128-GCM-SHA256,AES256-SHA256,AES128-SHA256,ECDHE-ECDSA-AES256-SHA,ECDHE-RSA-AES256-SHA,ECDHE-ECDSA-DES-CBC3-SHA,ECDHE-RSA-DES-CBC3-SHA,ECDHE-ECDSA-AES128-SHA,ECDHE-RSA-AES128-SHA,AES256-SHA,DHE-RSA-AES256-GCM-SHA384,DHE-RSA-AES256-SHA256,DHE-RSA-AES256-SHA,DHE-RSA-CAMELLIA256-SHA,DHE-RSA-AES128-GCM-SHA256,DHE-RSA-AES128-SHA256,DHE-RSA-AES128-SHA,DHE-RSA-CAMELLIA128-SHA,EDH-RSA-DES-CBC3-SHA,CAMELLIA256-SHA,DES-CBC3-SHA,AES128-SHA,CAMELLIA128-SHA";
			"enable-tls-1" = "No";
			"enable-pfs" = "Yes";
		}
		$jsonBody = $body | convertto-json
		$this.putRequest.AddParameter("application/json; charset=utf8;", $jsonBody, "RequestBody");
		$this.putRequest.RequestFormat = "Json";
		$client = New-Object RestSharp.RestClient("$($this.baseUrl)/restapi/v3/services/HTTPS/ssl-security");
        $response = $client.Execute($this.putRequest);
		if($response.ResponseStatus -eq "Error")
		{
			throw("Error in WafCert::BindCert. `n$($response.ErrorException) ")
		} 
		else 
		{
			return $response	
		}
    }

	hidden [String] GetBearerToken()
	{
		$creds = Get-AutomationPSCredential -Name 'WafAutomationCreds'
		$username = $creds.Username
		$passwordSec = $creds.Password
		$loginClient = New-Object RestSharp.RestClient("$($this.baseUrl)/restapi/v3/login");
		$passwordTxt = [System.Runtime.InteropServices.marshal]::PtrToStringAuto([System.Runtime.InteropServices.marshal]::SecureStringToBSTR($passwordSec))        
		$jsonBody = @{"username"=$username;"password"=$passwordTxt} | ConvertTo-Json
		$this.postRequest.AddParameter("application/json; charset=utf8;", $jsonBody, "RequestBody");
		$this.postRequest.RequestFormat = "Json";
		$response = $loginClient.Execute($this.postRequest);
		$tokenResponse = $response.Content | ConvertFrom-Json;
		$Base64Token = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("$($tokenResponse.token):$($passwordTxt)"));
		return $Base64Token
	}

  hidden [Void] ValidateCertUpload($status, $base)
	{
		if ($status.StatusCode -eq "created")
		{
			write-output "Deleting locally stored pem files..."
			$pemFiles = "$base\*.pem"
			rm -recurse -force $pemFiles
			$pemFilesExistAfterDelete = Get-ChildItem $pemFiles
			if (!($pemFilesExistAfterDelete))
			{
				write-output "Successful deletion of local pem files on hybrid worker"
			}
			else
			{
				write-output "***NOTICE: LOCAL PEM FILES FAILED TO DELETE. PLEASE CONNECT TO THE HYBRID WORKER VM WHICH THIS JOB RAN FROM TO REMOVE THEM***"
				write-output "***VALIDATE THAT THE WAF HAS THE CORRECT CERTS CONNECTED TO THE CORRECT SERVICES AND URLS***"
				throw "DELETION OF PEM FILES WERE UNSUCCESSFUL"
			}
		}
		else
		{
			write-output "Cert upload to WAF failed. Pem files are kept on the hybrid worker for troubleshooting purposes. Upon a successful run on this job, the pem files will be deleted automatically. Additionally, if you pull the certs down from the key vault through the runbook, the current pem files on the hybrid worker will be overwritten."
			throw "Upload validation failed. Status message: $($status.StatusCode)"
		}
	}
}

class KeyVaultCert
{
	[string] $serialNumber;
	[string[]] $dnsNameList;
    
	KeyVaultCert($vaultName, $certName)
	{
		$cert = Get-AzureKeyVaultCertificate -VaultName $vaultName -Name $certName
		$this.serialNumber = $cert.Certificate.SerialNumber.ToLower()
        $domainList = $cert.Certificate.DnsNameList | foreach { "$($_.Punycode)" }
		$this.dnsNameList = $domainList.Trim().Split(' ')
	}
}

class WafCert
{
	[String] $SerialNumber;
    [String] $OriginalCertName;
    
	WafCert($postRequest, $getRequest, $putRequest, $certName, $baseUrl, $certSuffix)
	{
		[WafApiClient] $wafApiClient = [WafApiClient]::new($postRequest, $getRequest, $putRequest, $baseUrl, $certSuffix);
		$wafApiClient.getRequest.AddHeader("authorization", "Basic $($wafApiClient.token)");
		$wafApiClient.getRequest.AddHeader("accept", "application/json");
		$wafCerts = $this.GetWafCertsForService($baseUrl, "HTTPS", $getRequest);
		$sniCert = $this.GetSniCert($wafCerts, $baseUrl, $getRequest, $certName);
        $this.SerialNumber = $this.GetSerialNumber($sniCert);
        $this.OriginalCertName = $this.GetOriginalCertName($sniCert);
	}

	hidden [object] GetWafCertsForService($baseUrl, $service, $getRequest)
	{
		#Get all the Certs on the WAF for the HTTPS service
		$client = New-Object RestSharp.RestClient("$($baseUrl)/restapi/v3/services/$($service)/ssl-security");
		$response = $client.Execute($getRequest);
		if($response.ResponseStatus -eq "Error")
		{
			throw("Error in WafCert::GetWafCertsForService. `n$($response.ErrorException) ")
		} 
		else 
		{
			return $response	
		}
	}

	hidden [object] GetSniCert($httpsServiceCerts, $baseUrl, $getRequest, $certName)
	{        
		#Get the currently bound cert on the WAF that we want to update
		$certNameWithSuffix = $this.GetSniCertNameWithSuffix($httpsServiceCerts, $certName)
		$certRequest = New-Object RestSharp.RestClient("$($baseUrl)/restapi/v3/certificates/$($certNameWithSuffix)");
		$response = $certRequest.Execute($getRequest);
		if($response.ResponseStatus -eq "Error")
		{
			throw("Error in WafCert::GetSniCert. `n$($response.ErrorException) ")
		} 
		else 
		{
			return $response	
		}

	}

	hidden [String] GetSniCertNameWithSuffix($certListOnWaf,$certName)
	{
		$allCertsContents = $($certListOnWaf.Content | ConvertFrom-Json)
		$currentActiveCerts = $($allCertsContents.data.HTTPS.'SSL Security'.'sni-certificate' | Select-Object -Unique)
		if (!$currentActiveCerts)
		{
			throw "no sni certs found on WAF"
		}

		foreach($cert in $currentActiveCerts)
		{
			if($cert -like "$($certName)*")
			{
				return $cert
			}
		}
		throw "no cert match found on waf"
	}

	hidden [String] GetSerialNumber($cert)
	{
		$obj = $cert.Content | ConvertFrom-Json
		$sn = $obj.details -split "Serial Number:"
		#remove " : " and whitespace from serial on WAF for equal comparison to key vault
		$WafCertSerialFormatted = $sn[1].Substring(1,54).toLower() -replace ':',''
		#return with whitespace removed
		return $WafCertSerialFormatted.Trim()
	}
    
    hidden [String] GetOriginalCertName($cert)
	{
		$sniCert = $cert.Content | ConvertFrom-Json                    
		return $sniCert.name        
	}
}

#Deserialize certs
$certNamesList = $certNames | ConvertFrom-Json
[WafApiClient] $WafApiClient = [WafApiClient]::new($postRequest, $getRequest, $putRequest, $baseUrl, $certSuffix)
#Process each cert name in list
$rebindCerts = $false
foreach($cert in $certNamesList)
{
	$certName = $cert.CertName
	write-output "****Start Loop for $certName"
	write-output "Creating kvCert Object"
	[KeyVaultCert] $kvCert = [KeyVaultCert]::new($vaultName, $certName)
	write-output "Creating WafCert Object"
	[WafCert] $wafCert = [WafCert]::new($postRequest, $getRequest, $putRequest, $certName, $baseUrl, $certSuffix)
	if($kvCert.SerialNumber -eq $wafCert.SerialNumber)
	{
		write-output "Key Vault Cert and WAF Cert serials match for $certName"
		#Creating list in case we need to bind certs based on potential new certs as we continue to iterate through this loop
		write-output "Building domain and cert name list:"
		foreach($domain in $kvCert.dnsNameList)
		{
			write-output "Adding: $($domain) to $($wafCert.OriginalCertName)"
			$sniDomains.Add($domain)
			$sniCertificates.Add("$($wafCert.OriginalCertName)")   
		}
	}
	else    
	{
		#New Cert Found - setting flag to rebind all certs
		$rebindCerts = $true
		write-output "Key Vault Cert and WAF Cert serials do not match for $certName. $($kvCert.SerialNumber) -eq $($wafCert.SerialNumber). Downloading new cert from Key Vault..."
		DownloadCertToHybridWorker -certName $certName
		start-sleep -s 30
		write-output "Uploading cert to WAF"
		$WafApiClient.UploadCert($certName)
		write-output "Binding cert to domains"
		foreach($domain in $kvCert.dnsNameList)
		{
			write-output "Adding: $($domain) to $($certName)-$($certSuffix)"
			$sniDomains.Add($domain)
			$sniCertificates.Add("$($certName)-$($certSuffix)")   
		}
	}	
}

if($rebindCerts)
{
  write-output "Binding Certs"
	$WafApiClient.BindCert($sniDomains, $sniCertificates)	
}