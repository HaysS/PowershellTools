
## FUNCTIONS

#Get Login Token (required)
function New-ICToken ([PSCredential]$Credential, [String]$HuntServer = "https://localhost:443" ) {
	Write-Verbose "Requesting new Token from $HuntServer using account $($Credential.username)"
	Write-Verbose "Credentials and Hunt Server Address are stored in global variables for use in all IC cmdlets"
	if (-NOT ([System.Net.ServicePointManager]::ServerCertificateValidationCallback)) {
		#Accept Unsigned CERTS
		[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
	}
	if (-NOT $Credential) {
		# Default Credentials
		$username = 'infocyte'
		$password = 'pulse' | ConvertTo-SecureString -asPlainText -Force
		$Credential = New-Object System.Management.Automation.PSCredential($username,$password)
	}

	$Global:HuntServerAddress = $HuntServer

	$data = @{
		username = $Credential.GetNetworkCredential().username
		password = $Credential.GetNetworkCredential().password
	}
	$i = $data | ConvertTo-JSON
	try {
		$response = Invoke-RestMethod "$HuntServerAddress/api/users/login" -Method POST -Body $i -ContentType 'application/json'
	} catch {
		Write-Warning "Error: $_"
		return "ERROR: $($_.Exception.Message)"
	}
	if ($response -match "Error") {
		Write-Warning "Error: Unauthorized"
		return "ERROR: $($_.Exception.Message)"
	} else {
		# Set Token to global variable
		$Global:ICToken = $response.id
		Write-Verbose 'New token saved to global variable: $Global:ICToken'
		$response
	}
}


# Get Full FileReports on all Suspicious and Malicious objects by scanId
function Get-ICFileReports ($scanId) {
	$skip = 0
	Write-Verbose "Exporting FileReports from $HuntServerAddress"
	Write-Progress -Activity "Exporting FileReports from Hunt Server" -status "Requesting FileReports from $scanId [$skip]"

	$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$headers.Add("Authorization", $Global:ICToken)
	try {
		$scan = Invoke-RestMethod ("$HuntServerAddress/api/scans/$scanId") -Headers $headers -Method GET -ContentType 'application/json'
	} catch {
		Write-Warning "Error: $_"
		return "ERROR: $($_.Exception.Message)"
	}

	$skip = 0
	$headers.Add("filter", '{"where":{"scanId":"'+$scanId+'"},"limit":1000,"skip":'+$skip+'}')
	try {
		$objects = Invoke-RestMethod ("$HuntServerAddress/api/ScanReportFiles") -Headers $headers -Method GET -ContentType 'application/json'
	} catch {}
	$more = $true
	While ($more) {
		$skip += 1000
		Write-Progress -Activity "Exporting FileReports from Hunt Server" -status "Requesting FileReports from $scanId [$skip]"
		$headers.remove('filter') | Out-Null
		$headers.Add("filter", '{"where":{"scanId":"'+$scanId+'"},"limit":1000,"skip":'+$skip+'}')
		try {
			$moreobjects = Invoke-RestMethod ("$HuntServerAddress/api/ScanReportFiles") -Headers $headers -Method GET -ContentType 'application/json'
		} catch {
			Write-Warning "Error: $_"
		}
		if ($moreobjects.count -gt 0) {
			$objects += $moreobjects
		} else {
			$more = $false
		}
	}

	$objects | % {
		$_ | Add-Member -Type NoteProperty -Name 'scancompletedon' -Value $scan.scancompletedon
		$_ | Add-Member -Type NoteProperty -Name 'TargetGroup' -Value $scan.TargetGroup

		# Add Signature
		$signatureId = $_.signatureId
		try {
			$sig = Invoke-RestMethod ("$HuntServerAddress/api/Signatures/$signatureId") -Headers $headers -Method GET -ContentType 'application/json'
			$_ | Add-Member -Type NoteProperty -Name 'signature' -Value $sig
		} catch {}

		# Add FileRep
		$fileRepId = $_.fileRepId
		try {
			$filerep = Invoke-RestMethod ("$HuntServerAddress/api/FileReps/$fileRepId") -Headers $headers -Method GET -ContentType 'application/json'
			$_ | Add-Member -Type NoteProperty -Name 'fileReps' -Value $filerep
		} catch {}
	}
	$objects
}


# Get objects by scanId
function Get-ICProcesses ($scanId){
	$skip = 0
	Write-Verbose "Exporting Processes from $scanId [$skip]"
	Write-Progress -Activity "Exporting Process Instances from Hunt Server" -status "Requesting Processes from $scanId [$skip]"

	$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$headers.Add("Authorization", $Global:ICToken)
	$headers.Add("filter", '{"where":{"scanId":"'+$scanId+'"},"limit":1000,"skip":'+$skip+'}')
	try {
		$objects = Invoke-RestMethod ("$HuntServerAddress/api/IntegrationProcesses") -Headers $headers -Method GET -ContentType 'application/json'
	} catch {
		Write-Warning "Error: $_"
		return "ERROR: $($_.Exception.Message)"
	}
	Write-Output $objects
	$more = $true
	While ($more) {
		$skip += 1000
		Write-Progress -Activity "Exporting Process Instances from Hunt Server" -status "Requesting Processes from $scanId [$skip]"
		$headers.remove('filter') | Out-Null
		$headers.Add("filter", '{"where":{"scanId":"'+$scanId+'"},"limit":1000,"skip":'+$skip+'}')
		try {
			$moreobjects = Invoke-RestMethod ("$HuntServerAddress/api/IntegrationProcesses") -Headers $headers -Method GET -ContentType 'application/json'
		} catch {
			Write-Warning "Error: $_"
		}
		if ($moreobjects.count -gt 0) {
			# $objects += $moreobjects
			Write-Output $moreobjects
		} else {
			$more = $false
		}
	}
}

function Get-ICModules ($scanId){
	$skip = 0
	Write-Verbose "Exporting Modules from $scanId [$skip]"
	Write-Progress -Activity "Exporting Module Instances from Hunt Server" -status "Requesting Modules from $scanId [$skip]"

	$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$headers.Add("Authorization", $Global:ICToken)
	$headers.Add("filter", '{"where":{"scanId":"'+$scanId+'"},"limit":1000,"skip":'+$skip+'}')
	try {
		$objects = Invoke-RestMethod ("$HuntServerAddress/api/IntegrationModules") -Headers $headers -Method GET -ContentType 'application/json'
	} catch {
		Write-Warning "Error: $_"
		return "ERROR: $($_.Exception.Message)"
	}
	Write-Output $objects
	$more = $true
	While ($more) {
		$skip += 1000
		Write-Progress -Activity "Exporting Module Instances from Hunt Server" -status "Requesting Modules from $scanId [$skip]"
		$headers.remove('filter') | Out-Null
		$headers.Add("filter", '{"where":{"scanId":"'+$scanId+'"},"limit":1000,"skip":'+$skip+'}')
		try {
			$moreobjects = Invoke-RestMethod ("$HuntServerAddress/api/IntegrationModules") -Headers $headers -Method GET -ContentType 'application/json'
		} catch {
			Write-Warning "Error: $_"
		}
		if ($moreobjects.count -gt 0) {
			Write-Output $moreobjects
			#$objects += $moreobjects
		} else {
			$more = $false
		}
	}
}

function Get-ICDrivers ($scanId){
	$skip = 0
	Write-Verbose "Exporting Drivers from $scanId [$skip]"
	Write-Progress -Activity "Exporting Driver Instances from Hunt Server" -status "Requesting Drivers from $scanId [$skip]"

	$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$headers.Add("Authorization", $Global:ICToken)
	$headers.Add("filter", '{"where":{"scanId":"'+$scanId+'"},"limit":1000,"skip":'+$skip+'}')
	try {
		$objects = Invoke-RestMethod ("$HuntServerAddress/api/IntegrationDrivers") -Headers $headers -Method GET -ContentType 'application/json'
	} catch {
		Write-Warning "Error: $_"
		return "ERROR: $($_.Exception.Message)"
	}
	Write-Output $objects
	$more = $true
	While ($more) {
		$skip += 1000
		Write-Progress -Activity "Exporting Driver Instances from Hunt Server" -status "Requesting Drivers from $scanId [$skip]"
		$headers.remove('filter') | Out-Null
		$headers.Add("filter", '{"where":{"scanId":"'+$scanId+'"},"limit":1000,"skip":'+$skip+'}')
		try {
			$moreobjects = Invoke-RestMethod ("$HuntServerAddress/api/IntegrationDrivers") -Headers $headers -Method GET -ContentType 'application/json'
		} catch {
			Write-Warning "Error: $_"
		}
		if ($moreobjects.count -gt 0) {
			#$objects += $moreobjects
			write-output $moreobjects
		} else {
			$more = $false
		}
	}
}

function Get-ICAutostarts ($scanId){
	$skip = 0
	Write-Verbose "Exporting Autostarts from $scanId [$skip]"
	Write-Progress -Activity "Exporting Autostart Instances from Hunt Server" -status "Requesting Autostarts from $scanId [$skip]"

	$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$headers.Add("Authorization", $Global:ICToken)
	$headers.Add("filter", '{"where":{"scanId":"'+$scanId+'"},"limit":1000,"skip":'+$skip+'}')
	try {
		$objects = Invoke-RestMethod ("$HuntServerAddress/api/IntegrationAutostarts") -Headers $headers -Method GET -ContentType 'application/json'
	} catch {
		Write-Warning "Error: $_"
		return "ERROR: $($_.Exception.Message)"
	}
	Write-Output $objects
	$more = $true
	While ($more) {
		$skip += 1000
		Write-Progress -Activity "Exporting Autostart Instances from Hunt Server" -status "Requesting Autostarts from $scanId [$skip]"
		$headers.remove('filter') | Out-Null
		$headers.Add("filter", '{"where":{"scanId":"'+$scanId+'"},"limit":1000,"skip":'+$skip+'}')
		try {
			$moreobjects = Invoke-RestMethod ("$HuntServerAddress/api/IntegrationAutostarts") -Headers $headers -Method GET -ContentType 'application/json'
		} catch {
			Write-Warning "Error: $_"
		}
		if ($moreobjects.count -gt 0) {
			# $objects += $moreobjects
			Write-Output $moreobjects
		} else {
			$more = $false
		}
	}
}

function Get-ICMemscans ($scanId){
	$skip = 0
	Write-Verbose "Exporting Memscans from $scanId [$skip]"
	Write-Progress -Activity "Exporting Memscan Instances from Hunt Server" -status "Requesting Memscans from $scanId [$skip]"

	$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$headers.Add("Authorization", $Global:ICToken)
	$headers.Add("filter", '{"where":{"scanId":"'+$scanId+'"},"limit":1000,"skip":'+$skip+'}')
	try {
		$objects = Invoke-RestMethod "$HuntServerAddress/api/IntegrationMemscans" -Headers $headers -Method GET -ContentType 'application/json'
	} catch {
		Write-Warning "Error: $_"
		return "ERROR: $($_.Exception.Message)"
	}
	Write-Output $objects
	$more = $true
	While ($more) {
		$skip += 1000
		Write-Progress -Activity "Exporting Memscan Instances from Hunt Server" -status "Requesting Memscans from $scanId [$skip]"
		$headers.remove('filter') | Out-Null
		$headers.Add("filter", '{"where":{"scanId":"'+$scanId+'"},"limit":1000,"skip":'+$skip+'}')
		try {
			$moreobjects = Invoke-RestMethod ("$HuntServerAddress/api/IntegrationMemscans") -Headers $headers -Method GET -ContentType 'application/json'
		} catch {
			Write-Warning "Error: $_"
		}
		if ($moreobjects.count -gt 0) {
			#$objects += $moreobjects
			Write-Output $moreobjects
		} else {
			$more = $false
		}
	}
}

function Get-ICConnections ([String]$scanId, [Switch]$All) {
	$skip = 0
	Write-Verbose "Exporting Connections from $scanId [$skip]"
	Write-Progress -Activity "Exporting Connection Instances from Hunt Server" -status "Requesting Connections from $scanId [$skip]"

	$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$headers.Add("Authorization", $Global:ICToken)
	$headers.Add("filter", '{"where":{"and":[{"scanId":"'+$scanId+'"},{"or":[{"state":"SYN-SENT"},{"state":"ESTABLISHED"}]}]},"limit":1000,"skip":'+$skip+'}')
	try {
		$objects = (Invoke-RestMethod ("$HuntServerAddress/api/IntegrationConnections") -Headers $headers -Method GET -ContentType 'application/json') | where { $_.localaddr -ne $_.remoteaddr }
	} catch {
		Write-Warning "Error: $_"
		return "ERROR: $($_.Exception.Message)"
	}
	Write-Output $objects
	$more = $true
	While ($more) {
		$skip += 1000
		Write-Progress -Activity "Exporting Connection Instances from Hunt Server" -status "Requesting Connections from $scanId [$skip]"
		$headers.remove('filter') | Out-Null
		$headers.Add("filter", '{"where":{"and":[{"scanId":"'+$scanId+'"},{"or":[{"state":"SYN-SENT"},{"state":"ESTABLISHED"}]}]},"limit":1000,"skip":'+$skip+'}')
		try {
			$moreobjects = Invoke-RestMethod ("$HuntServerAddress/api/IntegrationConnections") -Headers $headers -Method GET -ContentType 'application/json'
		} catch {
			Write-Warning "Error: $_"
		}
		if ($moreobjects.count -gt 0) {
			# $objects += $moreobjects
			Write-Output $moreobjects
		} else {
			$more = $false
		}
	}
}

function Get-ICAccounts ($scanId) {
	$skip = 0
	Write-Verbose "Exporting Accounts from $scanId [$skip]"
	Write-Progress -Activity "Exporting Account Instances from Hunt Server" -status "Requesting Accounts from $scanId [$skip]"

	$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$headers.Add("Authorization", $Global:ICToken)
	$headers.Add("filter", '{"where":{"scanId":"'+$scanId+'"},"limit":1000,"skip":'+$skip+'}')
	try {
		$objects = Invoke-RestMethod "$HuntServerAddress/api/IntegrationAccounts" -Headers $headers -Method GET -ContentType 'application/json'
	} catch {
		Write-Warning "Error: $_"
		return "ERROR: $($_.Exception.Message)"
	}
	write-output $objects
	$more = $true
	While ($more) {
		$skip += 1000
		Write-Progress -Activity "Exporting Account Instances from Hunt Server" -status "Requesting Accounts from $scanId [$skip]"
		$headers.remove('filter') | Out-Null
		$headers.Add("filter", '{"where":{"scanId":"'+$scanId+'"},"limit":1000,"skip":'+$skip+'}')
		try {
			$moreobjects = Invoke-RestMethod ("$HuntServerAddress/api/IntegrationAccounts") -Headers $headers -Method GET -ContentType 'application/json'
		} catch {
			Write-Warning "Error: $_"
		}
		if ($moreobjects.count -gt 0) {
			Write-Output $moreobjects
			#$objects += $moreobjects
		} else {
			$more = $false
		}
	}
}

function Get-ICHosts ($scanId) {
	$skip = 0
	Write-Verbose "Exporting Hosts from $scanId [$skip]"
	Write-Progress -Activity "Exporting Host Instances from Hunt Server" -status "Requesting Hosts from $scanId [$skip]"

	$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$headers.Add("Authorization", $Global:ICToken)
	$headers.Add("filter", '{"where":{"scanId":"'+$scanId+'"},"limit":1000,"skip":'+$skip+'}')
	try {
		$objects = Invoke-RestMethod ("$HuntServerAddress/api/IntegrationHosts") -Headers $headers -Method GET -ContentType 'application/json'
	} catch {
		Write-Warning "Error: $_"
		return "ERROR: $($_.Exception.Message)"
	}
	Write-Output $objects
	$more = $true
	While ($more) {
		$skip += 1000
		Write-Progress -Activity "Exporting Host Instances from Hunt Server" -status "Requesting Hosts from $scanId [$skip]"
		$headers.remove('filter') | Out-Null
		$headers.Add("filter", '{"where":{"scanId":"'+$scanId+'"},"limit":1000,"skip":'+$skip+'}')
		try {
			$moreobjects = Invoke-RestMethod ("$HuntServerAddress/api/IntegrationHosts") -Headers $headers -Method GET -ContentType 'application/json'
		} catch {
			Write-Warning "Error: $_"
		}
		if ($moreobjects.count -gt 0) {
			# $objects += $moreobjects
			Write-Output $moreobjects
		} else {
			$more = $false
		}
	}
}


# Get Full FileReport on an object by sha1
function Get-ICFileReport ($sha1){
	Write-Verbose "Requesting FileReport on file with SHA1: $sha1"
	$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$headers.Add("Authorization", $Global:ICToken)
	try {
		$objects = Invoke-RestMethod "$HuntServerAddress/api/FileReps/$sha1" -Headers $headers -Method GET -ContentType 'application/json'
	} catch {
		Write-Warning "Error: $_"
		return "ERROR: $($_.Exception.Message)"
	}

	$objects | % {
		$_ | Add-Member -Type NoteProperty -Name 'avpositives' -Value $_.avResults.positives
		$_ | Add-Member -Type NoteProperty -Name 'avtotal' -Value $_.avResults.total
	}
	$objects
}


# Status and Progress APIs
function Get-ICJobs {
	Write-Verbose "Getting Active Jobs from Infocyte HUNT: $HuntServerAddress"
	$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$headers.Add("Authorization", $Global:ICToken)
	$Skip = 0
	$headers.Add("filter", '{"where":{"or":[]},"order":["createdOn"],"limit":1000,"skip":'+$skip+'}')
	try {
		$Objects = Invoke-RestMethod ("$HuntServerAddress/api/jobs") -Headers $headers -Method GET -ContentType 'application/json'
	} catch {
		Write-Warning "Error: $_"
		return "ERROR: $($_.Exception.Message)"
	}
	if ($Objects) {
		Write-Output $Objects
	} else {
		return $null
	}

	$more = $true
	While ($more) {
		$skip += 1000
		$headers.remove('filter') | Out-Null
		$headers.Add("filter", '{"where":{"or":[]},"order":["createdOn"],"limit":1000,"skip":'+$skip+'}')
		try {
			$moreobjects = Invoke-RestMethod ("$HuntServerAddress/api/jobs") -Headers $headers -Method GET -ContentType 'application/json'
		} catch {
			Write-Warning "Error: $_"
			return "ERROR: $($_.Exception.Message)"
		}
		if ($moreobjects.count -gt 0) {
			Write-Output $moreobjects
		} else {
			$more = $false
		}
	}
}

function Get-ICActiveJobs {
	Write-Verbose "Getting Active Jobs from Infocyte HUNT: $HuntServerAddress"
	$Jobs = Get-ICJobs
	if ($Jobs) {
		$Jobs | where { $_.status -ne "Complete" }
	}
}

function Get-ICUserTasks {
	Write-Verbose "Getting Active Tasks from Infocyte HUNT: $HuntServerAddress"
	$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$headers.Add("Authorization", $Global:ICToken)
	$Skip = 0
	$headers.Add("filter", '{"where":{"or":[]},"order":["createdOn"],"limit":1000,"skip":'+$skip+'}')
	try {
		$objects = Invoke-RestMethod ("$HuntServerAddress/api/usertasks") -Headers $headers -Method GET -ContentType 'application/json'
	} catch {
		Write-Warning "Error: $_"
		return "ERROR: $($_.Exception.Message)"
	}
	Write-Output $objects

	$more = $true
	While ($more) {
		$skip += 1000
		$headers.remove('filter') | Out-Null
		$headers.Add("filter", '{"where":{"or":[]},"order":["createdOn"],"limit":1000,"skip":'+$skip+'}')
		try {
			$moreobjects = Invoke-RestMethod ("$HuntServerAddress/api/usertasks") -Headers $headers -Method GET -ContentType 'application/json'
		} catch {
			Write-Warning "Error: $_"
			return "ERROR: $($_.Exception.Message)"
		}
		if ($moreobjects.count -gt 0) {
			Write-Output $moreobjects
		} else {
			$more = $false
		}
	}
}

function Get-ICActiveTasks {
	Write-Verbose "Getting Active Tasks from Infocyte HUNT: $HuntServerAddress"
	$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$headers.Add("Authorization", $Global:ICToken)
	try {
		$objects += Invoke-RestMethod ("$HuntServerAddress/api/usertasks/active") -Headers $headers -Method GET -ContentType 'application/json'
	} catch {
		Write-Warning "Error: $_"
		return "ERROR: $($_.Exception.Message)"
	}
	if ($objects) {
		$objects | where { $_.status -eq "Active" }
	} else {
		return
	}

}

function Get-ICLastscanId {
	Write-Verbose "Getting last scanId from Infocyte HUNT: $HuntServerAddress"
	$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$headers.Add("Authorization", $Global:ICToken)
	try {
		$Scans = Invoke-RestMethod ("$HuntServerAddress/api/Scans") -Headers $headers -Method GET -ContentType 'application/json'
	} catch {
		Write-Warning "Error: $_"
		return "ERROR: $($_.Exception.Message)"
	}
	if ($Scans) {
		($Scans | sort-object completedOn -descending)[0].id
	} else {
		return $null
	}
}


# Setup APIs
function New-ICTargetGroup ([String]$Name) {
	Write-Verbose "Creating new target list: $Name"
	$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$headers.Add("Authorization", $Global:ICToken)
	$body = '{"name":"'+$Name+'"}'
	try {
		$objects += Invoke-RestMethod ("$HuntServerAddress/api/targets") -Headers $headers -Body $body -Method POST -ContentType 'application/json'
	} catch {
		Write-Warning "Error: $_"
		return "ERROR: $($_.Exception.Message)"
	}
	$objects
}

function New-ICCredential ([String]$Name, [PSCredential]$Cred) {
	Write-Verbose "Creating new Credential ($name) for username $($Cred.Username)"
	$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$headers.Add("Authorization", $Global:ICToken)
	$user = $Cred.Username | ConvertTo-JSON
	$pass = $Cred.GetNetworkCredential().Password
	$body = '{"type":"login","name":"'+$Name+'","username":'+$user+',"password":"'+$pass+'"}'
	try {
		$objects += Invoke-RestMethod ("$HuntServerAddress/api/credentials") -Headers $headers -Body $body -Method POST -ContentType 'application/json'
	} catch {
		Write-Warning "Error: $_"
		return "ERROR: $($_.Exception.Message)"
	}
	$objects
}

function Get-ICCredentials {
	Write-Verbose "Getting Credential Objects from Infocyte HUNT: $HuntServerAddress"
	$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$headers.Add("Authorization", $Global:ICToken)
	try {
		$objects += Invoke-RestMethod ("$HuntServerAddress/api/credentials") -Headers $headers -Method GET -ContentType 'application/json'
	} catch {
		Write-Warning "Error: $_"
		return "ERROR: $($_.Exception.Message)"
	}
	$objects
}

function New-ICQuery ([String]$TargetGroupId, [String]$credentialId = $null, [String]$sshCredentialId = $null, [String]$query) {
	Write-Verbose "Creating new Query in TargetGroup $TargetGroupId ($query) using username $($Cred.Username)"
	$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$headers.Add("Authorization", $Global:ICToken)
	$body = '{"type":"custom","value":"'+$query+'","targetId":"'+$TargetGroupId+'","credentialId":"'+$CredentialId+'","sshCredentialId":null}'
	try {
		$objects += Invoke-RestMethod ("$HuntServerAddress/api/queries") -Headers $headers -Body $body -Method POST -ContentType 'application/json'
	} catch {
		Write-Warning "Error: $_"
		return "ERROR: $($_.Exception.Message)"
	}
	$objects
}

function Get-ICQuery ([String]$TargetGroupId) {
	Write-Verbose "Creating new Credential ($name) for username $($Cred.Username)"
	$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$headers.Add("Authorization", $Global:ICToken)
	$headers.Add("filter", '{"where":{"and":[{"targetId":"'+$TargetGroupId+'"}]},"include":["credential","sshCredential"]}')
	try {
		$objects += Invoke-RestMethod ("$HuntServerAddress/api/queries") -Headers $headers -Method GET -ContentType 'application/json'
	} catch {
		Write-Warning "Error: $_"
		return "ERROR: $($_.Exception.Message)"
	}
	$objects
}


# Scan Metadata
function Get-ICTargetGroup {
	Write-Verbose "Requesting TargetGroups from $HuntServerAddress"
	$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$headers.Add("Authorization", $Global:ICToken)
	$headers.Add("filter", '{"order":["name","id"]}')
	try {
		$objects += Invoke-RestMethod ("$HuntServerAddress/api/targets") -Headers $headers -Method GET -ContentType 'application/json'
	} catch {
		Write-Warning "Error: $_"
		return "ERROR: $($_.Exception.Message)"
	}
	$objects
}

function Get-ICScans {
	$skip = 0
	Write-Verbose "Exporting Scans from $HuntServerAddress"
	Write-Progress -Activity "Exporting Scans from Hunt Server" -status "Requesting Scans from $scanId [$skip]"

	$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$headers.Add("Authorization", $Global:ICToken)
	$headers.Add("filter", '{"limit":1000,"skip":'+$skip+'}')
	try {
		$objects = Invoke-RestMethod "$HuntServerAddress/api/IntegrationScans" -Headers $headers -Method GET -ContentType 'application/json'
	} catch {
		Write-Warning "Error: $_"
		return "ERROR: $($_.Exception.Message)"
	}
	Write-Output $objects
	$more = $true
	While ($more) {
		$skip += 1000
		Write-Progress -Activity "Exporting Scans from Hunt Server" -status "Requesting Scans from $scanId [$skip]"
		$headers.remove('filter') | Out-Null
		$headers.Add("filter", '{"limit":1000,"skip":'+$skip+'}')
		try {
			$moreobjects = Invoke-RestMethod ("$HuntServerAddress/api/IntegrationScans") -Headers $headers -Method GET -ContentType 'application/json'
		} catch {
			Write-Warning "Error: $_"
		}
		if ($moreobjects.count -gt 0) {
			Write-Output $moreobjects
			# $objects += $moreobjects
		} else {
			$more = $false
		}
	}
}

function Get-ICAddresses ($TargetGroupId) {
	$skip = 0
	Write-Verbose "Getting all addresses from TargetGroup $TargetGroupId"
	Write-Progress -Activity "Exporting from $HuntServerAddress" -status "Getting Addresses from $TargetGroupId [$skip]"
	$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$headers.Add("Authorization", $Global:ICToken)
	$headers.Add("filter", '{"where":{"and":[{"targetId":"'+$targetId+'"}]},"limit":1000,"skip":'+$skip+'}')
	try {
		$objects = Invoke-RestMethod ("$HuntServerAddress/api/Addresses") -Headers $headers -Method GET -ContentType 'application/json'
	} catch {
		Write-Warning "Error: $_"
		return "ERROR: $($_.Exception.Message)"
	}
	$more = $true
	While ($more) {
		$skip += 1000
		Write-Progress -Activity "Exporting from $HuntServerAddress" -status "Getting Addresses from $TargetGroupId [$skip]"
		$headers.remove('filter') | Out-Null
		$headers.Add("filter", '{"where":{"and":[{"targetId":"'+$targetId+'"}]},"limit":1000,"skip":'+$skip+'}')
		try {
			$moreobjects = Invoke-RestMethod ("$HuntServerAddress/api/Addresses") -Headers $headers -Method GET -ContentType 'application/json'
		} catch {
			Write-Warning "Error: $_"
		}
		if ($moreobjects.count -gt 0) {
			$objects += $moreobjects
		} else {
			$more = $false
		}
	}
	$objects
}

function Remove-ICAddresses ($TargetGroupId) {
	Write-Verbose "Clearing all resolved hosts from TargetGroup $TargetGroupId"
	$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$headers.Add("Authorization", $Global:ICToken)
	$data = 'where=%7B%22and%22:%5B%7B%22targetId%22:%22'+$TargetGroupId+'%22%7D%5D%7D'
	try {
		$objects += Invoke-RestMethod ("$HuntServerAddress/api/Addresses?$data") -Headers $headers -Method DELETE -ContentType 'application/json'
	} catch {
		Write-Warning "Error: $_"
		return "ERROR: $($_.Exception.Message)"
	}
	$objects
}


# Scan APIs
function Invoke-ICEnumeration ($TargetGroupId, $QueryId) {
	Write-Verbose "Starting Enumeration of $TargetGroupId with Query $QueryId"
	$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$headers.Add("Authorization", $Global:ICToken)
	$body = '{"queries":["'+$QueryId+'"]}'
	try {
		$objects += Invoke-RestMethod ("$HuntServerAddress/api/targets/$TargetGroupId/Enumerate") -Headers $headers -Body $body -Method POST -ContentType 'application/json'
	} catch {
		Write-Warning "Error: $_"
		return "ERROR: $($_.Exception.Message)"
	}
	$objects
}

function Invoke-ICScan ($TargetGroupId) {
	Write-Verbose "Starting Scan of TargetGroup $TargetGroupId"
	$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
	$headers.Add("Authorization", $Global:ICToken)
	$body = '{"options":{"EnableProcess":true,"EnableModule":true,"EnableDriver":true,"EnableMemory":true,"EnableAccount":true,"EnableAutostart":true,"EnableHook":true,"EnableNetwork":true,"EnableLog":true,"EnableDelete":true}}'
	try {
		$objects += Invoke-RestMethod ("$HuntServerAddress/api/targets/$TargetGroupId/scan") -Headers $headers -Body $body -Method POST -ContentType 'application/json'
	} catch {
		Write-Warning "Error: $_"
		return "ERROR: $($_.Exception.Message)"
	}
	$objects
}
