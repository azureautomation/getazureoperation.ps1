<#
.SYNOPSIS
    Queries subscription operations using List Subscription Operations REST API.
    
    The -restarts parameter will show restart operations and also query restart events from the VM's System event log via remote PowerShell.

.DESCRIPTION
    Queries subscription operations using List Subscription Operations REST API.
    
    The -restarts parameter will show restart operations and also query restart events from the VM's System event log via remote PowerShell.

.LINK
	Reason codes - http://msdn.microsoft.com/en-us/library/aa376885.aspx

.PARAMETER days
    Optional. Query will cover from current time back the number of days specified. Default is 7 days if no value is specified.	

.PARAMETER servicename
    Required. Name of cloud service (hosted service) where the VM is running.	

.PARAMETER name
    Required. Name of the VM to query for restart events (System log Event ID 1074).

.PARAMETER username
    Required. Username of an administrative account within the guest OS of the VM. This is not the Azure subscription administrator.

.PARAMETER password
    Required. Password of an administrative account within the guest OS of the VM. This is not the Azure subscription administrator.

.PARAMETER subscriptionid
    Required. Subscription ID (GUID) for Azure subscription where the VM is running.

.PARAMETER restarts
    Optional. Queries for restart and shutdown operation for the specified VM and also makes a remote PowerShell connection to the VM to query the restart events.

.EXAMPLE
	Get-AzureOperation.ps1 -restarts -days 14 -servicename myservice -name myvm -username craig -password mypassword -subscriptionid 12345678-bbbb-dddd-aaaa-123456789012

.NOTES
    Name: Get-AzureOperation.ps1
    Author: Craig Landis
    Created: 7/30/2014
    Version: 1.0 // Craig Landis -- 7/30/2014
    Format-XML function by Keith Hill - http://rkeithhill.wordpress.com/2006/08/10/cmdlet-style-xml-pretty-print-format-xml/
#>

Param (	
    [int]$days = 7,
    [string]$servicename,
	[string]$name,
	[string]$username,
	[string]$password,
    [string]$subscriptionid = (Get-AzureSubscription -Current).SubscriptionId,
    [switch]$restarts = $false,
    [switch]$text = $false,
    [switch]$csv = $true
)

Function Format-Xml {
    param([string[]]$Path)
        
    begin {
        function PrettyPrintXmlString([string]$xml) {
            $tr = new-object System.IO.StringReader($xml)
            $settings = new-object System.Xml.XmlReaderSettings
            $settings.CloseInput = $true
            $settings.IgnoreWhitespace = $true
            $reader = [System.Xml.XmlReader]::Create($tr, $settings)
            
            $sw = new-object System.IO.StringWriter
            $settings = new-object System.Xml.XmlWriterSettings
            $settings.CloseOutput = $true
            $settings.Indent = $true
            $writer = [System.Xml.XmlWriter]::Create($sw, $settings)
            
            while (!$reader.EOF) {
                $writer.WriteNode($reader, $false)
            }
            $writer.Flush()
            
            $result = $sw.ToString()
            $reader.Close()
            $writer.Close()
            $result
        }
        
        function PrettyPrintXmlFile($path) {
            $rpath = resolve-path $path
            $contents = gc $rpath
            $contents = [string]::join([environment]::newline, $contents)
            PrettyPrintXmlString $contents
        }
    
        function Usage() {
            ""
            "USAGE"
            "    Format-Xml -Path <pathToXmlFile>"
            ""
            "SYNOPSIS"
            "    Formats the XML into a nicely indented form (ie pretty printed)."
            "    Outputs one <string> object for each XML file."
            ""
            "PARAMETERS"
            "    -Path <string[]>"
            "        Specifies path to one or more XML files to format with indentation."
            "        Pipeline input is bound to this parameter."
            ""
            "EXAMPLES"
            "    Format-Xml -Path foo.xml"
            "    Format-Xml foo.xml"
            "    gci *.xml | Format-Xml"  
            "    [xml]`"<doc>…</doc>`" | Format-Xml"
            ""
        }

        if (($args[0] -eq "-?") -or ($args[0] -eq "-help")) {
          Usage
        }
    }
    
    process {
        if ($_) {
          if ($_ -is [xml]) {
            PrettyPrintXmlString $_.get_OuterXml()
          }
          elseif ($_ -is [IO.FileInfo]) {
            PrettyPrintXmlFile $_.FullName
          }
          elseif ($_ -is [string]) {
            if (test-path -type Leaf $_) {
                PrettyPrintXmlFile $_
            }
            else {
                PrettyPrintXmlString $_
            }
          }
          else {
            throw "Pipeline input type must be one of: [xml], [string] or [IO.FileInfo]"
          }
        }
    }
      
    end {
        if ($Path) {
          foreach ($aPath in $Path) {
            PrettyPrintXmlFile $aPath
          }
        }
    }
}

$startTime = ((Get-Date).AddDays(-$days)).ToUniversalTime()
$endTime = (Get-Date).ToUniversalTime()

"`nSubscriptionId: $SubscriptionId"

"`nStart: $startTime"
"End:   $endTime`n"


$version = '2014-05-01'
$headers = @{'x-ms-version'=$version}
$hostedServiceName = $servicename
$deploymentName = $servicename
$roleInstanceName = $name
$endpoint = 'https://management.core.windows.net'
$certificateThumbprint = (Get-AzureSubscription -Current).Certificate.Thumbprint
$uri = ($endpoint + '/' + $subscriptionId + '/operations?StartTime=' + (Get-Date $startTime -f yyyy-MM-ddTHH:mm:ssZ) + '&EndTime=' + (Get-Date $endTime -f yyyy-MM-ddTHH:mm:ssZ))
$operations = Invoke-RestMethod -Uri $uri -CertificateThumbprint $certificateThumbprint -Headers $headers

If ($restarts)
{

    $operations = $operations.SubscriptionOperationCollection.SubscriptionOperations.SubscriptionOperation

    $arrObjects = @()

    $operations | foreach {

        $Output = New-Object System.Object
        $Output | Add-Member -type NoteProperty -name Time -value $_.OperationStartedTime -Force
        $Output | Add-Member -type NoteProperty -name Completed -value $_.OperationCompletedTime -Force
        $Output | Add-Member -type NoteProperty -name Type -value $_.OperationKind -Force
        $Output | Add-Member -type NoteProperty -name OperationId -value $_.OperationId -Force
        $Output | Add-Member -type NoteProperty -name Name -value ($_.OperationParameters.OperationParameter | Where-Object {$_.Name -eq 'roleInstanceName'}).Value -Force
        $Output | Add-Member -type NoteProperty -name User -value $_.OperationCaller.UserEmailAddress -Force

        $arrObjects += $Output
    }

    $secstr = New-Object -TypeName System.Security.SecureString
    $password.ToCharArray() | ForEach-Object {$secstr.AppendChar($_)}
    $cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $username, $secstr

    $vm = Get-AzureVM -ServiceName $servicename -Name $name

    If ($vm.InstanceStatus -eq 'ReadyRole')
    {
        $port = ($vm.VM.ConfigurationSets.Inputendpoints | Where { $_.LocalPort -eq 5986 }).Port
        $vip = ($vm.VM.ConfigurationSets.Inputendpoints | Where { $_.LocalPort -eq 5986 }).Vip
        $uri = ('https://' + $vip + ':' + $port)

        $PSSession = (New-PSSession -ConnectionUri $uri -Credential $cred -SessionOption (New-PSSessionOption -SkipCACheck -SkipCNCheck -NoMachineProfile))

        $events = Invoke-Command -Session $PSSession -ScriptBlock { param ($st,$et)                                                                       
                                                                           $results = Get-WinEvent -LogName System | ? {($_.TimeCreated -ge $st) -and ($_.TimeCreated -le $et) -and (6005,6006,6008,6013,1074,1076,1001,41,22 -contains $_.ID)}
                                                                           $results = Get-WinEvent -LogName System | ? {($_.TimeCreated -ge $st) -and ($_.TimeCreated -le $et) -and (1074 -contains $_.Id)}                                                                   
                                                                           $events = @()
                                                                           $results | foreach {
                                                                                $event = New-Object System.Object                                                                        
                                                                                $event | Add-Member -type NoteProperty -name Time -value (Get-Date $_.TimeCreated.ToUniversalTime() -f yyyy-MM-ddThh:mm:ssZ) -Force
                                                                                $event | Add-Member -type NoteProperty -name Caption -value $OS.Caption -Force
                                                                                $event | Add-Member -type NoteProperty -name Version -value $OS.Version -Force
                                                                                $event | Add-Member -type NoteProperty -name Completed -value $null -Force
                                                                                $event | Add-Member -type NoteProperty -name Type -value $null -Force
                                                                                $event | Add-Member -type NoteProperty -name OperationId -value $null -Force
                                                                                $event | Add-Member -type NoteProperty -name Name -value ($_.MachineName).ToUpper().Split('.')[0] -Force
                                                                                $event | Add-Member -type NoteProperty -name Id -value $_.Id -Force
                                                                                $event | Add-Member -type NoteProperty -name Message -value $_.Message -Force
                                                                                If ($_.Id -eq 1074)
                                                                                {
                                                                                    $event | Add-Member -type NoteProperty -name Process -value $_.Properties[0].Value -Force
                                                                                    $event | Add-Member -type NoteProperty -name 'Reason' -value $_.Properties[2].Value -Force
                                                                                    $event | Add-Member -type NoteProperty -name 'Reason Code' -value $_.Properties[3].Value -Force
                                                                                    $event | Add-Member -type NoteProperty -name Type -value $_.Properties[4].Value -Force
                                                                                    $event | Add-Member -type NoteProperty -name Comment -value $_.Properties[5].Value -Force
                                                                                    $event | Add-Member -type NoteProperty -name User -value $_.Properties[6].Value -Force
                                                                                }
                                                                                $events += $event
                                                                            }
                                                                            $events
                                                                         } -ArgumentList $startTime,$endTime

                                                                         Remove-PSSession $PSSession

    }
    ElseIf ($vm.InstanceStatus)
    {
        Write-Host "`nVM exists but InstanceStatus is not ReadyRole. Please start the VM.`n"
        Exit
    }
    Else
    {
        Write-Host "`nVM does not exist. Verify servicename and name and try again.`n"
        Exit
    }

    $events += $arrObjects | Where-Object {$_.Name -eq $name}

    $events | sort Time | Format-Table Name,Time,User,Type,Process,Reason,'Reason Code' -AutoSize

    If ($text)
    {
        $events | sort Time | Format-Table Name,Time,User,Type,Process,Reason,'Reason Code' -AutoSize | Out-String -Width 4096 | Out-File $env:TEMP\restarts.txt -Force
        Invoke-Item $env:TEMP\restarts.txt
    }

    If ($csv)
    {
        $events | sort Time | select Name,Time,User,Type,Process,Reason,'Reason Code' | Export-Csv $env:TEMP\restarts.csv -NoTypeInformation -Force
        Invoke-Item $env:TEMP\restarts.csv
    }
}
Else
{
    $operations | Format-Xml | Out-File $env:TEMP\Operations.xml -Force

    Invoke-Item $env:TEMP\Operations.xml

}
