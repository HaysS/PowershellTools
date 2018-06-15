# example script to upload a survey file to HUNT (2.10+)
# Script to upload manual .bz2 file to hunt server.
Param(
	[Parameter(Mandatory = $false,
			ParameterSetName="Path",
			ValueFromPipeline=$true,
			ValueFromPipelineByPropertyName)]
	[String[]]
	$Path, # <folder containing the survey results (.bz2) files to upload>

	[Parameter(Mandatory = $false,
					ParameterSetName="Directory")]
	[ValidateScript({
      $_ | Test-Path -type Container
  })]
  [System.IO.FileInfo]
  $Directory,

	[String]
	$HuntServer = "https://localhost:443",

	[String]
	$TargetGroup = "OfflineScans",

	[PSCredential]
	[System.Management.Automation.Credential()]
	$Credential = [System.Management.Automation.PSCredential]::Empty
)

BEGIN{
	# INITIALIZE
	Write-Host "PSVersion Check: $($PSVersionTable.PSVersion.tostring())"

 if (-NOT ($Directory -or $Path)) {
	 throw "Path or Directory options not specified."
 }

	# Hardcoded Credentials (unsafe in production but convenient for testing)
	# Infocyte Credentials
	# If a user did not add their credentials, use the default ones.
	if ($Credential -eq [System.Management.Automation.PSCredential]::Empty) {
		$username = 'infocyte'
		$password = 'hunt' | ConvertTo-SecureString -asPlainText -Force
		$Script:Credential = New-Object System.Management.Automation.PSCredential($username,$password)
	}

	# VARIABLES
	$survey = "HostSurvey.json.bz2"
	$surveyext = "*.json.bz2"
	$api = "$HuntServer/api"


	# FUNCTIONS
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
			Write-Warning $_
			return "ERROR: $($_.Exception.Message)"
		}
		if ($response -match "Error") {
			Write-Warning "Error: Unauthorized"
			return "ERROR: $($_.Exception.Message)"
		} else {
			# Set Token to global variable
			$Global:ICToken = $response.id
			Write-Verbose "New token saved to global variable: $ICToken"
			$response
		}
	}

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

	function Get-ICTargetGroup {
		Write-Verbose "Requesting TargetGroups from $HuntServerAddress"
		$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
		$headers.Add("Authorization", $Global:ICToken)
		$headers.Add("filter", '{"order":["name","id"]}')
		try {
			$objects += Invoke-RestMethod ("$HuntServerAddress/api/targets") -Headers $headers -Method GET -ContentType 'application/json'
		} catch {
			Write-Warning $_
			return "ERROR: $($_.Exception.Message)"
		}
		$objects
	}

	function New-ICScanId ([String]$ScanName, [String]$targetId) {
		Write-Verbose "Creating new scanId: $ScanId"
		$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
		$headers.Add("Authorization", $Global:ICToken)
		$body = @{ name=$scanName; targetId=$targetId } | ConvertTo-Json
		try {
			$response = Invoke-RestMethod ("$HuntServerAddress/api/scans") -Headers $headers -Body $body -Method POST -ContentType "application/json"
		} catch {
			#Write-Warning $_
			return "ERROR: $($_.Exception.Message)"
		}
		return $response.id #ScanId
	}

	function Get-ICActiveTasks ($Active=$False){
		Write-Verbose "Getting Active Tasks from Infocyte HUNT: $HuntServerAddress"
		$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
		$headers.Add("Authorization", $Global:ICToken)
		try {
			$objects += Invoke-RestMethod ("$HuntServerAddress/api/usertasks/active") -Headers $headers -Method GET -ContentType 'application/json'
		} catch {
			#Write-Warning "Error: $_"
			return "ERROR: $($_.Exception.Message)"
		}
		if ($Active -and $objects) {
			$activeObjects = $objects | where { $_.status -eq "Active" }
			return $activeObjects
		} else {
			return $objects
		}

	}

	function Submit-ICSurvey ([String]$File, [String]$ScanId){
		Write-Verbose "Uploading Surveys"
		$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
		$headers.Add("Authorization", $Global:ICToken)
		$headers.Add("scanId", $ScanId)
		try {
			$objects = Invoke-RestMethod "$HuntServerAddress/api/survey" -Headers $headers -Method POST -InFile $File -ContentType "application/octet-stream"
		} catch {
			#Write-Warning "Error: $_"
			return "ERROR: $($_.Exception.Message)"
		}
		$objects
	}



	# MAIN
	Write-Host "Acquiring token..."
	$Token = New-ICToken $Credential $HuntServer
	if ($Token -like "ERROR*") {
		Write-Warning "Could not login to $HuntServer with $($Credential.username)"
		Write-Warning $Token
		return
	}
	Write-Host "Checking for '$TargetGroup' target group..."
	$TargetGroups = Get-ICTargetGroup
	if ($TargetGroups.name -contains $TargetGroup) {
		Write-Host "$TargetGroup Exists"
		$TargetGroupObj = $targetGroups | where { $_.name -eq $TargetGroup}
	} else {
			Write-Host "$TargetGroup does not exist. Creating new Target Group '$TargetGroup'"
			$TargetGroupObj = New-ICTargetGroup $TargetGroup
	}

	if($ScanName -eq $null) {
		$ScanName = (get-date).toString("yyyy-MM-dd HH:mm")
	}

	if ($ScanId -eq $null) {
		Write-Host "Creating scan $ScanName in $TargetGroup [$($TargetGroupObj.id)]..."
		$ScanId = New-ICScanId $ScanName ($TargetGroupObj.id)
		Write-Host "New ScanId is $ScanId"
	}

}

PROCESS{
	switch ($PSCmdlet.ParameterSetName) {
		"Path" {
			foreach ($file in $Path) {
					if ((Test-Path $file -type Leaf) -and ($file -like "*.json.bz2")) {
						Write-Host "Uploading survey [$file]..."
						Submit-ICSurvey $file $ScanId
					} else {
						Write-Host "$file does not exist or is not a .json.bz2 file"
					}
			}
		}
		"Directory" {
			Write-Host "Recursing through Directory $Directory "
			Get-ChildItem $Directory -recurse -filter $surveyext | foreach {
				Write-Host "Uploading $($_.FullName)"
				Submit-ICSurvey $($_.FullName) $ScanId
			}
		}
	}
}

END{
	# TODO: detect when scan is no longer processing submissions, then mark as completed
	Get-ICActiveTasks $True
	#Write-Host "Closing scan..."
	#Invoke-RestMethod -Headers @{ Authorization = $token } -Uri "$api/scans/$scanId/complete" -Method Post
}
