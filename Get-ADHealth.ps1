<# 
.SYNOPSIS
	Genera un informe de salud de Active Directory.
.DESCRIPTION
	Genera un informe detallado de la salud de Active Directory.
.PARAMETER Tests
	Comprobaciones que se van a realizar sobre Active Directory.
	Por defecto, el valor es "All".
.PARAMETER DcdiagFail
	Expresión regular que identifica un error generado por el comando DCDIAG.
	Además de este valor, siempre se comprueba el valor "fail ".
	Por defecto, el valor es " no super?".
.PARAMETER DcdiagPassed
	Expresión regular que identifica éxito por el comando DCDIAG.
	Además de este valor, siempre se comprueba el valor "passed ".
	Por defecto, el valor es " super?".
.PARAMETER Filters
	Resultado que se van a mostrar en el informe.
	Por defecto, el valor es "All".
.PARAMETER Timeout
	Tiempo de espera, en segundos, de los comandos ejecutados en remoto.
	Por defecto, el valor es 60.
.PARAMETER DomainControllers
	Listado de los controladores del Active Directory sobre los cuales se van a realizar las comprobaciones.
	Si no está definido, la comprobación se realiza sobre todos los controladores del Active Directory.
	Por defecto, el valor es $Null.
.PARAMETER HtmlFile
	Ruta de acceso al informe generado en formato HTML del estado del Active Directory.
	Si no está definido, no se genera el informe HTML.
.INPUTS
	Ninguna.
.OUTPUTS
	AdhcResult[]. Lista de comprobaciones realizadas y sus resultados.
.COMPONENT
	ActiveDirectory Module
.NOTES
	Versión:    0.9
	Autor:		Ramón Román Castro
	Basado en:	https://gist.github.com/AlexAsplund/28f6c3ef42418902885cde1b83ebc260 (Alex Asplund)
.LINK
	https://github.com/ramonromancastro/Get-ADHealth
#>

Param(
    [Parameter(Mandatory=$false)]
	[ValidateSet(
            "All",
			"CVE-2020-1472",
            "DCDiagDomain",
			"DCDiag",
			"DeletedObjects",
			"DFSREvents",
			"SystemEvents",
			"DuplicateUPN",
			"DuplicateRDN",
			"DuplicatesAMAccountName",
			"DuplicateSPN",
			"DuplicateMail",
			"DuplicateProxyAddress",
			"BloatedTokens",
			"NoClientSite",
			"UnlinkedGPO",
			"OrphanGPO",
			"GPOWithcPassword",
			"OrphanObjects"
        )]
	[String[]]$Tests = "All",
	[Parameter(Mandatory=$false)][String]$DcdiagFail=" no super?",
	[Parameter(Mandatory=$false)][String]$DcdiagPassed=" super?",
	[Parameter(Mandatory=$false)][String]$BloatedTokenGroup=$null,
	[ValidateSet(
            "All",
			"Timeout",
            "Completed",
			"Failed"
        )]
	[String[]]$Filters = "All",
	[Parameter(Mandatory=$false)][Int]$Timeout=60,
	[Parameter(Mandatory=$false)][String[]]$DomainControllers=$Null,
	[Parameter(Mandatory=$false)][String]$HtmlFile=$Null
)

#################################################
# CONTANTS
#################################################

$TestDescription = @{}

$TestDescription['Advertising'] = 'Comprueba si cada DSA se anuncia a sí mismo y si se anuncia a sí mismo con las capacidades de un DSA.'
$TestDescription['CheckSDRefDom'] = 'Esta prueba comprueba que todas las particiones del directorio de la aplicación tengan dominios de referencia del descriptor de seguridad adecuados.'
$TestDescription['CheckSecurityError'] = 'Busca errores de seguridad (o posiblemente relacionados con la seguridad) y realiza el diagnóstico inicial del problema.'
$TestDescription['Connectivity'] = 'Comprueba si los DSA están registrados en DNS, si se puede hacer ping en ellos y si  tienen conectividad de LDAP/RPC.'
$TestDescription['CrossRefValidation'] = 'Esta prueba busca referencias cruzadas que no son válidas de algún modo.'
$TestDescription['CutoffServers'] = 'Comprueba si hay servidores que no recibirán replicaciones porque sus asociados están inactivos.'
$TestDescription['DcPromo'] = 'Comprueba la infraestructura DNS existente para la promoción a controlador de dominio.'
$TestDescription['DNS'] = 'Esta prueba comprueba el estado de la configuración DNS en toda la empresa.'
$TestDescription['FrsEvent'] = 'Esta prueba comprueba si hay errores de operación en el sistema de replicación de archivos (FRS).'
$TestDescription['DFSREvent'] = 'Esta prueba comprueba si hay errores de operación en el DFS.'
$TestDescription['SysVolCheck'] = 'Esta prueba comprueba que SYSVOL está listo.'
$TestDescription['LocatorCheck'] = 'Comprueba que los contenedores de roles globales sean conocidos, puedan localizarse y respondan.'
$TestDescription['Intersite'] = 'Comprueba si hay errores que pueden evitar o interrumpir temporalmente la replicación entre sitios.'
$TestDescription['KccEvent'] = 'Esta prueba comprueba que el comprobador de coherencia de la información se complete sin errores.'
$TestDescription['KnowsOfRoleHolders'] = 'Comprueba si el DSA cree que conoce los contenedores de roles e imprime las funciones en modo detallado.'
$TestDescription['MachineAccount'] = 'Comprueba si la cuenta de equipo tiene la información correcta.'
$TestDescription['NCSecDesc'] = 'Comprueba que los descriptores de seguridad de los encabezados de contexto de nomenclatura tengan los permisos necesarios para la replicación.'
$TestDescription['NetLogons'] = 'Comprueba que los privilegios de inicio de sesión adecuados permiten que continúe la replicación.'
$TestDescription['ObjectsReplicated'] = 'Comprueba que la cuenta de equipo (solo AD) y los objetos DSA se hayan replicado.'
$TestDescription['OutboundSecureChannels'] = 'Comprueba si hay canales seguros desde todos los DC del dominio.'
$TestDescription['RegisterInDNS'] = 'Comprueba si este servidor de directorio puede registrar los registros DNS de ubicación del servidor de directorio.'
$TestDescription['Replications'] = 'Comprueba si la replicación entre servidores de directorio se realiza a tiempo.'
$TestDescription['RidManager'] = 'Comprueba si el maestro RID es accesible y si  contiene la información adecuada.'
$TestDescription['Services'] = 'Comprueba si se están ejecutando los servicios auxiliares adecuados.'
$TestDescription['SystemLog'] = 'Esta prueba comprueba que el sistema se esté ejecutando sin errores.'
$TestDescription['Topology'] = 'Comprueba que la topología generada esté completamente conectada para todos los DSA.'
$TestDescription['VerifyEnterpriseReferences'] = 'Esta prueba comprueba que determinadas referencias del sistema estén intactas en la infraestructura de FRS y replicación en todos los objetos de la empresa en cada DSA.'
$TestDescription['VerifyReferences'] = 'Esta prueba comprueba que determinadas referencias del sistema estén intactas en la infraestructura de FRS y replicación.'
$TestDescription['VerifyReplicas'] = 'Esta prueba comprueba que se hayan creado instancias de todas las particiones del directorio de aplicaciones en todos los servidores de replicación,'

$TestDescription['BloatedTokens'] = ''
$TestDescription['CVE-2020-1472'] = 'Netlogon Elevation of Privilege Vulnerability'
$TestDescription['DFSREvents'] = ''
$TestDescription['DeletedObjects'] = 'Comprueba la existencia de objetos eliminados en el dominio.'
$TestDescription['DuplicateMail'] = 'Comprueba la existencia de objetos con mail duplicado.'
$TestDescription['DuplicateProxyAddress'] = ''
$TestDescription['DuplicateRDN'] = 'Comprueba la existencia de objetos con Relative Distinguished Name (RDN) duplicado.'
$TestDescription['DuplicateSPN'] = 'Comprueba la existencia de objetos con ServicePrincipalName duplicado.'
$TestDescription['DuplicateUPN'] = 'Comprueba la existencia de objetos con UserPrincipalName duplicado.'
$TestDescription['DuplicatesAMAccountName'] = 'Comprueba la existencia de objetos con sAMAccountName duplicado.'
$TestDescription['GPOWithcPassword'] = 'Comprueba la existencia de GPOs que contengan cPassword.'
$TestDescription['NoClientSite'] = 'Comprueba si existen equipos que están iniciando sesión y cuya dirección IP no está asignada a ningún sitio.'
$TestDescription['OrphanObjects'] = ''
$TestDescription['SystemEvents'] = ''
$TestDescription['UnlinkedGPO'] = 'Comprueba si existen GPOs que no se están enlazando actualmente.'
$TestDescription['OrphanGPO'] = 'Comprueba si existen carpetas en SYVOL\Policies que no están definidas como GPOs.'

#################################################
# CLASSES
#################################################

Class AdhcResult {
    [string]$Source
    [string]$TestName
    [string]$State
    $Was
    $ShouldBe
    [string]$Category
    [string]$Description
    $Data
    [string[]]$Tags

}

#################################################
# VARIABLES
#################################################

$Version = 'v0.6'
#$OutputEncoding = [Console]::InputEncoding = [Console]::OutputEncoding = [Text.UTF8Encoding]::UTF8
$StopWatch = [System.Diagnostics.Stopwatch]::StartNew()

#################################################
# INCLUDES
#################################################

Add-Type -AssemblyName System.Web

#################################################
# FUNCIONES
#################################################

Function New-AdhcResult {
    [cmdletbinding()]
    param(
        # Source of the result. The computer that was tested
        [parameter(ValueFromPipelineByPropertyName)]
        [string]$Source = $env:COMPUTERNAME,

        # Name of the test
        [parameter(Mandatory,ValueFromPipelineByPropertyName)]
        [string]$TestName,

		[ValidateSet(
			"Timeout",
            "Completed",
			"Failed"
        )][String]$State = "Completed",

        [parameter(ValueFromPipelineByPropertyName)]
        $Was,

        [parameter(ValueFromPipelineByPropertyName)]
        $ShouldBe,

        # General category of the test. Like "Directory Services" or "DNS"
        [parameter(Mandatory,ValueFromPipelineByPropertyName)]
        [string]$Category,

        # Tags for this test like "Security", "Updates", "Logon"
        [parameter(Mandatory,ValueFromPipelineByPropertyName)]
        [string[]]$Tags,
        
        # Test description
        [parameter(ValueFromPipelineByPropertyName)]
        [string]$Description,

        # Extra data to the test result. Like accountnames or SPN's etc.
        [parameter(ValueFromPipelineByPropertyName)]
        $Data

    )

    Begin {

    }

    Process {
        [AdhcResult]@{
            Source = $Source
            TestName = $TestName
            State = $State
            Was = $Was
            ShouldBe = $ShouldBe
            Category = $Category
            Description = $Description
            Data = $Data
            Tags = $Tags
        }
    }
    End { }
}

Function Test-AdhcDCDiag {
    [cmdletbinding()]
    param(
        # Name of the DC
        [parameter(ValueFromPipeline)]
        [string]$ComputerName,

        # What DCDiag tests would you like to run?
        [ValidateSet(
            "All",
            "Advertising",
            "DNS",
            "NCSecDesc",
            "KccEvent",
            "Services",
            "NetLogons",
            "CrossRefValidation",
            "CutoffServers",
            "CheckSecurityError",
            "Intersite",
            "CheckSDRefDom",
            "Connectivity",
            "SysVolCheck",
            "Replications",
            "ObjectsReplicated",
            "DcPromo",
            "RidManager",
            "Topology",
            "MachineAccount",
            "LocatorCheck",
            "OutboundSecureChannels",
            "RegisterInDNS",
            "VerifyEnterpriseReferences",
            "KnowsOfRoleHolders",
            "VerifyReplicas",
            "VerifyReferences"
        )]
        [string[]]$Tests = "All",

        # Excluded tests
        [ValidateSet(
            "Advertising",
            "DNS",
            "NCSecDesc",
            "KccEvent",
            "Services",
            "NetLogons",
            "CrossRefValidation",
            "CutoffServers",
            "CheckSecurityError",
            "Intersite",
            "CheckSDRefDom",
            "Connectivity",
            "SysVolCheck",
            "Replications",
            "ObjectsReplicated",
            "DcPromo",
            "RidManager",
            "Topology",
            "MachineAccount",
            "LocatorCheck",
            "OutboundSecureChannels",
            "RegisterInDNS",
            "VerifyEnterpriseReferences",
            "KnowsOfRoleHolders",
            "VerifyReplicas",
            "VerifyReferences"
        )]
        [string[]]$ExcludedTests
        
    )
    Begin {

        $DCDiagTests = @{
            Advertising = @{}
            CheckSDRefDom = @{}
            CheckSecurityError = @{
	            ExtraArgs = @(
                    "/replsource:$((Get-ADDomainController -Filter *).HostName | ? {$_ -notmatch $env:computername} | Get-Random)"
                )
            }
            Connectivity = @{}
            CrossRefValidation = @{}
            CutoffServers = @{}
            DcPromo = @{
	            ExtraArgs = @(
                    "/ReplicaDC",
                    "/DnsDomain:$((Get-ADDomain).DNSRoot)",
                    "/ForestRoot:$((Get-ADDomain).Forest)"
                )
            }
            DNS = @{}
            SysVolCheck = @{}
            LocatorCheck = @{}
            Intersite = @{}
            KccEvent = @{}
            KnowsOfRoleHolders = @{}
            MachineAccount = @{}
            NCSecDesc = @{}
            NetLogons = @{}
            ObjectsReplicated = @{}
            OutboundSecureChannels = @{}
            RegisterInDNS = @{
	            ExtraArgs = "/DnsDomain:$((Get-ADDomain).DNSRoot)"
            }
            Replications = @{}
            RidManager = @{}
            Services = @{}
            Topology = @{}
            VerifyEnterpriseReferences = @{}
            VerifyReferences = @{}
            VerifyReplicas = @{}
        }

        $TestsToRun = $DCDiagTests.Keys | Where-Object {$_ -notin $ExcludedTests}

        If($Tests -ne 'All'){
            $TestsToRun = $Tests
        }
        
        if(($Tests | Measure-Object).Count -gt 1 -and $Tests -contains "All"){
            Write-Error "Invalid Tests parameter value: You can't use 'All' with other tests." -ErrorAction Stop
        }

        Write-Verbose "Executing tests: $($DCDiagTests.Keys -join ", ")"
    }
    Process {
        if(![string]::IsNullOrEmpty($ComputerName)) {
             $ServerArg = "/s:$ComputerName"
        }
        else {
            $ComputerName = $env:COMPUTERNAME
            $ServerArg = "/s:$env:COMPUTERNAME"
        }
        
        Write-Verbose "Starting DCDIAG on $ComputerName"



       $TestResults = @()

        $TestsToRun | Foreach {
            Write-Verbose "Starting test $_ on $ComputerName"

            $TestName = $_
            $ExtraArgs = $DCDiagTests[$_].ExtraArgs
			$Output = $Null
			$State = $Null
            
            if($_ -in @("DcPromo", "DNS", "RegisterInDNS")){
                if($env:COMPUTERNAME -ne $ComputerName){

                    Write-Verbose "Test cannot be performed remote, invoking dcdiag"
                    $Job = Invoke-Command -AsJob -ComputerName $ComputerName -ArgumentList @($TestName,$ExtraArgs) -ScriptBlock {
                        $TestName = $args[0]
                        $ExtraArgs = $args[1]
                        dcdiag /test:$TestName $ExtraArgs
                    }
                }
                else {
                    $Job = Start-Job -ScriptBlock { dcdiag /test:$($args[0]) $($args[1]) } -ArgumentList $TestName, $ExtraArgs
                }
            }
            else {
                $Job = Start-Job -ScriptBlock { dcdiag /test:$($args[0]) $($args[1]) $($args[2]) } -ArgumentList $TestName, $ExtraArgs, $ServerArg
            }
			
			Wait-Job -Job $Job -Timeout $Timeout | Out-Null
			$Output = Receive-Job -Job $Job

            $Fails = ($Output | Select-String -AllMatches -Pattern $DcdiagFail,'fail ' | Measure-Object).Count
            $Passes = ($Output | Select-String -AllMatches -Pattern $DcdiagPassed,'passed ' |  Measure-Object).Count
			
			If ($Job.State -eq 'Running') { Stop-Job $Job; $State = "Timeout" }
			ElseIf ($Job.State -eq 'Failed') { $State = "Failed" }
			ElseIf ($Fails -eq 0 -and $Passes -gt 0) { $State = "Completed" }
			Else { $State = "Failed" }
		
            $ResultSplat = @{
                Source = $ComputerName
                TestName = "$_"
                State = $State
                Was = $Fails,$Passes
                ShouldBe = 0,0
				Description = $TestDescription[$_]
                Category = "DCDIAG"
                Data = $Output
                Tags = @('DCDIAG',$_)
            }
			
            $TestResults += New-AdhcResult @ResultSplat
        }
        $TestResults
    }
    End {
    }
}

Function DCDiagDomainTest{
	$TestResults = @()
	If ("DCDiagDomain" -in $Tests -Or $Tests -eq "All"){
		$DCDiagDomainTests = @(
			"CheckSDRefDom",
			"ObjectsReplicated",
			"NCSecDesc",
			"DNS",
			"DCPromo",
			"CrossRefValidation"
		)
		
		$TestResults += Test-AdhcDCDiag -Tests $DCDiagDomainTests -ComputerName (Get-ADDomain | Select-Object -ExpandProperty PDCEmulator)
	}
	$TestResults
}

Function DCDiagTest{
	$TestResults = @()
	If ("DCDiag" -in $Tests -Or $Tests -eq "All"){
		$DCTests = @(
			"Advertising",
			"CheckSecurityError",
			"CutoffServers",
			"Intersite",
			"KccEvent",
			"KnowsOfRoleHolders",
			"LocatorCheck",
			"MachineAccount",
			"NetLogons",
			"RegisterInDNS",
			"Replications",
			"RidManager",
			"Services",
			"SysVolCheck",
			"Topology",
			"VerifyReferences",
			"VerifyReplicas"
		)
		$TestResults += $DomainControllers | Test-AdhcDCDiag -Tests $DCTests -Verbose
	}
	$TestResults
}


#################################################
#
# MAIN CODE
#
#################################################

$TestResults = @()

# Get all DCs

Write-Verbose "Retrieving domain controllers"
If ($DomainControllers -eq $null) { $DomainControllers = (Get-ADDomainController -Filter *).Name | Sort-Object }

#################################################
# Start domain wide dcdiag
#################################################

$TestResults += DCDiagDomainTest

#################################################
# DC specific tests
#################################################

$TestResults += DCDiagTest

#################################################
# Test CVE-2020-1472
#################################################

If ("CVE-2020-1472" -in $Tests -Or $Tests -eq "All"){
	Write-Verbose "Starting test CVE-2020-1472 events on domains controllers"

	$Jobs = Invoke-Command -AsJob -ComputerName $DomainControllers -ScriptBlock {
		Try{
		Get-EventLog -LogName "System" -EntryType Error -After (get-date).AddDays(-1) | Where-Object {($_.Source -eq 'NetLogon' -and ($_.eventid -eq 5827 -or $_.eventid -eq 5828 -or $_.eventid -eq 5829))}
		}
		Catch{
			'Ha ocurrido un error ejecutando el test.'
		}
	}

	Wait-Job -Job $Jobs -Timeout $Timeout | Out-Null
	$Logs = Receive-Job -Job $Jobs
	
	$Jobs.ChildJobs | ForEach-Object{
		$ChildJob = $_
		
		# Data
		$Data = $Logs | Where-Object { $_.PSComputerName -eq $ChildJob.Location }
		$ResultCount = ($Data| Measure-Object).Count
		
		# State
		If ($ChildJob.State -eq 'Running') { Stop-Job $ChildJob; $State = "Timeout" }
		ElseIf ($ChildJob.State -eq 'Failed') { $State = "Failed" }
		ElseIf ($ResultCount -eq 0) { $State = "Completed" }
		Else { $State = "Failed" }

		$ResultSplat = @{
			Source = $_.Location
			TestName = "CVE-2020-1472"
			State = $State
			Was = $ResultCount
			ShouldBe = 0
			Description = $TestDescription['CVE-2020-1472']
			Category = "EventLog"
			Data = $Data | Sort-Object -Property TimeGenerated -Descending
			Tags = @('System','Event','CVE')
		}

		$TestResults += New-AdhcResult @ResultSplat
	}
}

#################################################
# Test DFSR event logs for errors
#################################################

If ("DFSREvents" -in $Tests -Or $Tests -eq "All"){
	Write-Verbose "Starting test DFRS events on domains controllers"

	$Jobs = Invoke-Command -AsJob -ComputerName $DomainControllers -ScriptBlock {
		Try{
			Get-EventLog -LogName "DFS Replication" -EntryType Error -After (get-date).AddDays(-1) | Where-Object {$_.EventId -ne 5014 -and $_.ReplacementStrings[6] -ne 9036}
		}
		Catch{
			'Ha ocurrido un error ejecutando el test.'
		}
	}
	Wait-Job -Job $Jobs -Timeout $Timeout | Out-Null
	$Logs = Receive-Job -Job $Jobs
	
	$Jobs.ChildJobs | ForEach-Object{
		$ChildJob = $_
		
		# Data
		$Data = $Logs | Where-Object { $_.PSComputerName -eq $ChildJob.Location }
		$ResultCount = ($Data| Measure-Object).Count
		
		# State
		If ($ChildJob.State -eq 'Running') { Stop-Job $ChildJob; $State = "Timeout" }
		ElseIf ($ChildJob.State -eq 'Failed') { $State = "Failed" }
		ElseIf ($ResultCount -eq 0) { $State = "Completed" }
		Else { $State = "Failed" }

		$ResultSplat = @{
			Source = $_.Location
			TestName = "DFSREvents"
			State = $State
			Was = $ResultCount
			ShouldBe = 0
			Description = $TestDescription['DFSREvents']
			Category = "EventLog"
			Data = $Data | Sort-Object -Property TimeGenerated -Descending
			Tags = @('System','Event')
		}
		
		$TestResults += New-AdhcResult @ResultSplat
	}
}

#################################################
# Test system event logs for errors
#################################################

If ("SystemEvents" -in $Tests -Or $Tests -eq "All"){
	Write-Verbose "Starting test System events on domains controllers"

	$Jobs = Invoke-Command -AsJob -ComputerName $DomainControllers -ScriptBlock {
		Try{
		$Filter = {
			($_.Source -eq 'NetLogon' -and -not ($_.EventId -eq 5805 -or $_.EventId -eq 5723 -or $_.EventId -eq 5722)) -and
		
			# Filter TGS/TGT events
			($_.Source -ne 'KDC' -and -not ($_.EventId -eq 16 -or $_.EventId -eq 11)) -and
		
			# Filter out DCOM errors
			($_.Source -ne "DCOM" -and $_.EventId -ne 10016)
	
		}
		
		$Errors = Get-EventLog -LogName "System" -EntryType Error -After (Get-Date).AddDays(-1)
		$Errors | Where-Object $Filter
		}
		Catch{
			'Ha ocurrido un error ejecutando el test.'
		}
	}


	$Jobs | Wait-Job -Timeout $Timeout | Out-Null
	$Logs = $Jobs | Receive-Job
	
	$Jobs.ChildJobs | ForEach-Object{
		$ChildJob = $_
		
		# Data
		$Data = $Logs | Where-Object { $_.PSComputerName -eq $ChildJob.Location }
		$ResultCount = ($Data| Measure-Object).Count
		
		# State
		If ($ChildJob.State -eq 'Running') { Stop-Job $ChildJob; $State = "Timeout" }
		ElseIf ($ChildJob.State -eq 'Failed') { $State = "Failed" }
		ElseIf ($ResultCount -eq 0) { $State = "Completed" }
		Else { $State = "Failed" }

		$ResultSplat = @{
			Source = $_.Location
			TestName = "SystemEvent"
			State = $State
			Was = $ResultCount
			ShouldBe = 0
			Description = $TestDescription['SystemEvents']
			Category = "EventLog"
			Data = $Data | Sort-Object -Property TimeGenerated -Descending
			Tags = @('System','Event')
		}
		
		$TestResults += New-AdhcResult @ResultSplat
	}
}

#################################################
# Test for duplicate UPN
#################################################

If ("DuplicateUPN" -in $Tests -Or $Tests -eq "All"){
	Write-Verbose "Starting test duplicate UPN on domain objects"

	# Get all AD-objects containing a UPN
	$ADUserPrincipalNames = (Get-ADObject -LDAPFilter "UserPrincipalName=*" -Properties UserPrincipalName).UserPrincipalName

	# Create the hashtable
	$UPNCount = @{}

	# Loop through all UPN's and +1 on their key in the hashtable
	$ADUserPrincipalNames | foreach {
		$UPNCount["$_"]++
	}

	# Get all UPN's where value -gt 1
	$DuplicateUPNs = $ADUserPrincipalNames | Where-Object {$UPNCount["$_"] -gt 1} | Select-Object -Unique
	$DuplicateCount = ($DuplicateUPNs | Measure-Object).Count
	If ($DuplicateCount -eq 0) { $State = "Completed" }
	Else { $State = "Failed" }

	$ResultSplat = @{
		Source = "Directory"
		TestName = "DuplicateUPN"
		State = $State
		Was = $DuplicateCount
		ShouldBe = 0
		Description = $TestDescription['DuplicateUPN']
		Category = "Duplicate Attributes"
		Data = $DuplicateUPNs
		Tags = @('Attributes','UPN','UserPrincipalName')
	}

	$TestResults += New-AdhcResult @ResultSplat
}

#################################################
# Check for delete objects
#################################################

If ("DeletedObjects" -in $Tests -Or $Tests -eq "All"){
	Write-Verbose "Starting test deleted objects on domain"

	$DeleteObjects = (Get-ADObject -LDAPFilter "(|(cn=*\0ADEL:*)(ou=*\0ADEL:*))").DistinguishedName

	$DeleteObjectsCount = ($DeleteObjects | Measure-Object).Count
	If ($DeleteObjectsCount -eq 0) { $State = "Completed" }
	Else { $State = "Failed" }

	$ResultSplat = @{
		Source = "Directory"
		TestName = "DeletedObjects"
		State = $State
		Was = $DeleteObjectsCount
		ShouldBe = 0
		Description = $TestDescription['DeletedObjects']
		Category = "Deleted Objects"
		Data = $DeleteObjects
		Tags = @('Attributes','DistinguishedNames')
	}

	$TestResults += New-AdhcResult @ResultSplat
}

#################################################
# Check for duplicate RDN
#################################################

If ("DuplicateRDN" -in $Tests -Or $Tests -eq "All"){
	Write-Verbose "Starting test duplicate RDN on domain"
	# https://social.technet.microsoft.com/wiki/contents/articles/15435.active-directory-duplicate-object-name-resolution.aspx

	$DuplicateRDNs = (Get-ADObject -LDAPFilter "(|(cn=*\0ACNF:*)(ou=*\0ACNF:*))").DistinguishedName

	$DuplicateCount = ($DuplicateRDNs | Measure-Object).Count
	If ($DuplicateCount -eq 0) { $State = "Completed" }
	Else { $State = "Failed" }

	$ResultSplat = @{
		Source = "Directory"
		TestName = "DuplicateRDN"
		State = $State
		Was = $DuplicateCount
		ShouldBe = 0
		Description = $TestDescription['DuplicateRDN']
		Category = "Duplicate Attributes"
		Data = $DuplicateRDSs
		Tags = @('Attributes','DistinguishedNames')
	}

	$TestResults += New-AdhcResult @ResultSplat
}

#################################################
# Check for duplicate sAMAccountName
#################################################

If ("DuplicatesAMAccountName" -in $Tests -Or $Tests -eq "All"){
	Write-Verbose "Starting test duplicate sAMAccountName on domain"
	# https://social.technet.microsoft.com/wiki/contents/articles/15435.active-directory-duplicate-object-name-resolution.aspx

	$DuplicatesAMAccountNames = (Get-ADObject -LDAPFilter "(sAMAccountName=$duplicate*)").sAMAccountName

	$DuplicateCount = ($DuplicatesAMAccountNames | Measure-Object).Count
	If ($DuplicateCount -eq 0) { $State = "Completed" }
	Else { $State = "Failed" }

	$ResultSplat = @{
		Source = "Directory"
		TestName = "DuplicatesAMAccountNames"
		State = $State
		Was = $DuplicateCount
		ShouldBe = 0
		Description = $TestDescription['DuplicatesAMAccountName']
		Category = "Duplicate Attributes"
		Data = $DuplicatesAMAccountNames
		Tags = @('Attributes','sAMAccountName')
	}

	$TestResults += New-AdhcResult @ResultSplat
}

#################################################
# Check for duplicate SPN
#################################################

If ("DuplicateSPN" -in $Tests -Or $Tests -eq "All"){
	Write-Verbose "Starting test duplicate SPN on domain objects"

	# Get all objects containting SPN's
	$ServicePrincipalNames = (Get-ADObject -LDAPFilter "ServicePrincipalName=*" -Properties ServicePrincipalName).ServicePrincipalName

	# Create hashtable
	$SPNCount = @{}

	# Loop through all SPN's and increment on it's hashtable key
	$ServicePrincipalNames | Foreach {
		$SPNCount["$_"]++
	}

	# Get all SPN's where value -gt 1
	$DuplicateSPNs = $ServicePrincipalNames | Where-Object {$SPNCount["$_"] -gt 1} | Select-Object -Unique

	$DuplicateCount = ($DuplicateSPNCount | Measure-Object).Count
	If ($DuplicateCount -eq 0) { $State = "Completed" }
	Else { $State = "Failed" }

	$ResultSplat = @{
		Source = "Directory"
		TestName = "DuplicateSPNs"
		State = $State
		Was = $DuplicateCount
		ShouldBe = 0
		Description = $TestDescription['DuplicateSPN']
		Category = "Duplicate Attributes"
		Data = $DuplicateSPNs
		Tags = @('Attributes','SPN','ServicePrincipalNames')
	}

	$TestResults += New-AdhcResult @ResultSplat
}

#################################################
# Check for duplicate mail
#################################################

If ("DuplicateMail" -in $Tests -Or $Tests -eq "All"){
	Write-Verbose "Starting test duplicate mail on domain objects"

	# Get all AD objects containing mail-attribute
	$MailAttributes = (Get-ADObject -LDAPFilter "mail=*" -Properties mail).mail

	# Create hashtable
	$MailCount = @{}

	# Increment key
	$MailAttributes | Foreach {
		$MailCount["$_"]++
	}

	# Get all mail's where value -gt 1
	$DuplicateMail = $MailAttributes | ? {$MailCount["$_"] -gt 1}

	$DuplicateCount = ($DuplicateMail | Measure-Object).Count
	If ($DuplicateCount -eq 0) { $State = "Completed" }
	Else { $State = "Failed" }

	$ResultSplat = @{
		Source = "Directory"
		TestName = "DuplicateMail"
		State = $State
		Was = $DuplicateCount
		ShouldBe = 0
		Description = $TestDescription['DuplicateMail']
		Category = "Duplicate Attributes"
		Data = $DuplicateMail
		Tags = @('Attributes','Mail')
	}

	$TestResults += New-AdhcResult @ResultSplat
}

#################################################
# Check for duplicate ProxyAddresses
#################################################

If ("DuplicateProxyAddress" -in $Tests -Or $Tests -eq "All"){
	Write-Verbose "Starting test duplicate proxy address on domain"
	
	# Get all objects containing ProxyAddresses
	$ProxyAddresses = (Get-ADObject -LDAPFilter "ProxyAddresses=*" -Properties ProxyAddresses).ProxyAddresses

	# Create hashtable
	$ProxyAddressCount = @{}

	# Increment key
	$ProxyAddresses | Foreach {$ProxyAddressCount["$_"]++}

	# Get all ProxyAddresses where value -gt 1
	$DuplicateProxyAddresses = $ProxyAddresses | ? {$ProxyAddressCount["$_"] -gt 1}

	$DuplicateCount = ($DuplicateProxyAddresses | Measure-Object).Count
	If ($DuplicateCount -eq 0) { $State = "Completed" }
	Else { $State = "Failed" }

	$ResultSplat = @{
		Source = "Directory"
		TestName = "DuplicateProxyAddresses"
		State = $State
		Was = $DuplicateCount
		ShouldBe = 0
		Description = $TestDescription['DuplicateProxyAddress']
		Category = "Duplicate Attributes"
		Data = $DuplicateProxyAddresses
		Tags = @('Attributes','ProxyAddresses')
	}

	$TestResults += New-AdhcResult @ResultSplat
}

#################################################
# Check for orphan objects
#################################################

If ("OrphanObjects" -in $Tests -Or $Tests -eq "All"){
	Write-Verbose "Starting test orphan objects on domain"
	# https://techguyvijay.blogspot.com/2012/03/lost-and-found-folder-in-active.html

	$LostAndFoundContainer = (Get-ADDomain).LostAndFoundContainer
	$OrphanObjects = (Get-ADObject -SearchBase (Get-ADDomain).LostAndFoundContainer -Filter {ObjectClass -ne 'lostAndFound'}).DistinguishedName

	$OrphanObjectsCount = ($OrphanObjects | Measure-Object).Count
	If ($OrphanObjectsCount -eq 0) { $State = "Completed" }
	Else { $State = "Failed" }

	$ResultSplat = @{
		Source = "Directory"
		TestName = "OrphanObjects"
		State = $State
		Was = $OrphanObjectsCount
		ShouldBe = 0
		Description = $TestDescription['OrphanObjects']
		Category = "Orphan Objects"
		Data = $OrphanObjects
		Tags = @('Group','LostAndFound','Attributes','DistinguishedName')
	}

	$TestResults += New-AdhcResult @ResultSplat
}

#################################################
# Check for bloated tokens
#################################################

If (("BloatedTokens" -in $Tests -Or $Tests -eq "All") -And $BloatedTokenGroup){
	Write-Verbose "Starting test bloated tokens on domain"

	# WARNING: This will take an extremely long time and will be resource intensive
	# You might want to limit a regular run to admins only and run through on the whole domain once in a while.
	# https://blog.jijitechnologies.com/active-directory-token-bloat

	$UserDNs = (Get-ADGroup -Identity $BloatedTokenGroup -Properties members).Members

	$TokenSizes = @()

	Foreach($UserDN in $UserDNs) {

		# Get all nested groups using LDAP_IN_CHAIN (1.2.840.113556.1.4.1941)
		$Groups = Get-ADGroup -LDAPFilter "(member:1.2.840.113556.1.4.1941:=$UserDN)" -Properties sIDHistory
		
		$Object = [PSCustomObject]@{
			DistinguishedName = $UserDN
			UserTokenSize = 1200
		}

		foreach ($Group in $Groups){
			if ($Group.SIDHistory.Count -ge 1){
				# Groups with sidhistory always counts as +40
				$Object.TokenSize = 40
			}
			switch($Group.GroupScope){
				'Global' {$Object.UserTokenSize+=8}
				'Universal' {$Object.UserTokenSize+=8}
				'DomainLocal' {$Object.UserTokenSize+=40}
			}
		}

		$TokenSizes += $Object

		# Max default token size for 2012R2 is 48000
		$BloatedTokens = $TokenSizes | ? {$_.UserTokenSize -gt 48000}
		$BloatedTokenCount = ($BloatedTokens | Measure-Object).Count
		If ($BloatedTokenCount -eq 0) { $State = "Completed" }
		Else { $State = "Failed" }

		$ResultSplat = @{
			Source = "Directory"
			TestName = "BloatedTokens"
			State = $State
			Was = $BloatedTokenCount
			ShouldBe = 0
			Description = $TestDescription['BloatedTokens']
			Category = "Kerberos"
			Data = $BloatedTokens
			Tags = @('Groups','Tokens','Kerberos')
		}

		$TestResults += New-AdhcResult @ResultSplat
	}
}

#################################################
# Check for no client site
#################################################

If ("NoClientSite" -in $Tests -Or $Tests -eq "All"){
	# https://docs.microsoft.com/en-us/archive/blogs/instan/troubleshooting-account-lockout-the-pss-way
	Write-Verbose "Starting test no client site on domains controllers"

	$Jobs = Invoke-Command -AsJob -ComputerName $DomainControllers -ScriptBlock {
		Try{
		$NetLogonLog = Import-Csv "$env:SystemRoot\Debug\netlogon.log" -Delimiter " " -Header Date,Time,Pid,Domain,Message,ComputerName,IpAddress
		$NoClientSite = $NetlogonLog | Where-Object Message -eq "NO_CLIENT_SITE:" | Select ComputerName,IpAddress
		$NoClientSite
		}
		Catch{
			'Ha ocurrido un error ejecutando el test.'
		}
	}

	Wait-Job -Job $Jobs -Timeout $Timeout | Out-Null
	Receive-Job -Job $Jobs
	
	$Jobs.ChildJobs | ForEach-Object{
		$ChildJob = $_
		
		# Data
		$Data = $ChildJob.Output | Select-Object -ExpandProperty IpAddress | Sort-Object -Unique
		$ResultCount = ($Data | Measure-Object).Count
		
		# State
		If ($ChildJob.State -eq 'Running') { Stop-Job $ChildJob; $State = "Timeout" }
		ElseIf ($ChildJob.State -eq 'Completed') { If ($ResultCount -eq 0) { $State = "Completed" }  Else { $State = "Failed" } }
		ElseIf ($ChildJob.State -eq 'Failed') { $State = "Failed"; $Data = $ChildJob.JobStateInfo.Reason; }
		Else { $State = "Failed"; $Data = $ChildJob.JobStateInfo.Reason; }
		
		$ResultSplat = @{
			Source = $_.Location
			TestName = "NoClientSite"
			State = $State
			Was = $ResultCount
			ShouldBe = 0
			Description = $TestDescription['NoClientSite']
			Category = "NetLogon"
			Data = $Data
			Tags = @('Netlogon','Sites')
		}

		$TestResults += New-AdhcResult @ResultSplat
	}
}

#################################################
# Check for unlinked GPO's
#################################################

If ("UnlinkedGPO" -in $Tests -Or $Tests -eq "All"){
	Write-Verbose "Starting test unlinked GPOs on domain"
	[xml]$GPOXmlReport = Get-GPOReport -All -ReportType Xml
	$UnlinkedGPOs = ($GPOXmlReport.GPOS.GPO | Where-Object {$_.LinksTo -eq $null}).Name

	$UnlinkedGPOCount = ($UnlinkedGPOs | Measure-Object).Count
	If ($UnlinkedGPOCount -eq 0) { $State = "Completed" }
	Else { $State = "Failed" }

	$ResultSplat = @{
		Source = "Directory"
		TestName = "UnlinkedGPO"
		State = $State
		Was = $UnlinkedGPOCount
		ShouldBe = 0
		Description = $TestDescription['UnlinkedGPO']
		Category = "Group Policy"
		Data = $UnlinkedGPOs | Sort-Object
		Tags = @('Group Policy')
	}

	$TestResults += New-AdhcResult @ResultSplat
}

#################################################
# Check for orphan GPO's
#################################################

If ("OrphanGPO" -in $Tests -Or $Tests -eq "All"){
	Write-Verbose "Starting test unused GPOs on domain"
	
	
	$DNSRoot = (Get-ADDomain | Select-Object -ExpandProperty DNSRoot)
	$Path = "\\$($DNSRoot)\SYSVOL\$($DNSRoot)\Policies\"
	$GPOs = Get-ChildItem $Path -Directory | Where-Object { $_.Name -ne "PolicyDefinitions"} | Select-Object -ExpandProperty Name
	
	$OrphanGPOs = @()
	ForEach($GPO in $GPOs){
		Try{
			If ((Get-GPO -Guid $GPO -ErrorAction SilentlyContinue) -eq $null) { $OrphanGPOs += $GPO }
		}
		Catch{}
	}
	
	$OrphanGPOCount = ($OrphanGPOs | Measure-Object).Count
	If ($OrphanGPOCount -eq 0) { $State = "Completed" }
	Else { $State = "Failed" }

	$ResultSplat = @{
		Source = "Directory"
		TestName = "UnusedGPO"
		State = $State
		Was = $UnusedGPOCount
		ShouldBe = 0
		Description = $TestDescription['OrphanGPO']
		Category = "Group Policy"
		Data = $OrphanGPOs | Sort-Object
		Tags = @('Group Policy')
	}

	$TestResults += New-AdhcResult @ResultSplat
}

#################################################
# Check GPO's containing cPassword
#################################################

If ("GPOWithcPassword" -in $Tests -Or $Tests -eq "All"){
	Write-Verbose "Starting test GPO's containing cPassword on domain"

	# $Path = "C:\Windows\SYSVOL\domain\Policies\"
	$DNSRoot = (Get-ADDomain | Select-Object -ExpandProperty DNSRoot)
	$Path = "\\$($DNSRoot)\SYSVOL\$($DNSRoot)\Policies\"

	# Get all GPO XMLs
	$XMLs = Get-ChildItem $Path -recurse -Filter *.xml

	# GPO's containing cpasswords
	$cPasswordGPOs = @()

	# Loop through all XMLs and use regex to parse out cpassword
	# Return GPO display name if it returns
	Foreach($XMLFile in $XMLs){
		$Content = Get-Content -Raw -Path $XMLFile.FullName
		if($Content.Contains("cpassword")){

			[string]$CPassword = [regex]::matches($Content,'(cpassword=).+?(?=\")')
			$CPassword = $CPassword.split('(\")')[1]
			if($CPassword){
				[string]$GPOguid = [regex]::matches($XMLFile.DirectoryName,'(?<=\{).+?(?=\})')
				$GPODetail = Get-GPO -guid $GPOguid
				$cPasswordGPOs += $GPODetail.DisplayName   
			}
		}
	}

	$cPasswordGPOsCount = ($cPasswordGPOs | Measure-Object).Count
	If ($cPasswordGPOsCount -eq 0) { $State = "Completed" }
	Else { $State = "Failed" }
	
	$ResultSplat = @{
		Source = "Directory"
		TestName = "GPOWithcPassword"
		State = $State
		Was = $cPasswordGPOsCount
		ShouldBe = 0
		Description = $TestDescription['GPOWithcPassword']
		Category = "Group Policy"
		Data = $cPasswordGPOs | Sort-Object
		Tags = @('Group Policy','cPassword','Security')
	}

	$TestResults += New-AdhcResult @ResultSplat
}

$FilterResults = @()
$TestResults | ForEach-Object{
	If ($Filters -eq "All" -or $_.Status -in $Filters){
		$FilterResults += $_
	}
}

#################################################
# Create HTML report
#################################################

If ($HtmlFile){
	Write-Verbose "Writing HTML report"
	
	If ((Test-Path $HtmlFile) -like $false){ New-Item $HtmlFile -type file | Out-Null}
	
	$Position = 0

	# HTML header
	
	Clear-Content $HtmlFile 
	Add-Content $HtmlFile "<!DOCTYPE html>"
	Add-Content $HtmlFile "<html lang='es'>"
	Add-Content $HtmlFile "<head>"
	Add-Content $HtmlFile "<title>AD Status Report</title>"
	Add-Content $HtmlFile "<meta charset='utf-8'>"
	Add-Content $HtmlFile "<meta name='viewport' content='width=device-width, initial-scale=1'>"
	Add-Content $HtmlFile "<meta http-equiv='x-ua-compatible' content='ie=edge'>"
	Add-Content $HtmlFile "<meta http-equiv='X-Content-Type-Options' content='nosniff'/>"
	Add-Content $HtmlFile "<meta name='author' content='Ramón Román Castro <ramonromancastro@gmail.com>'/>"
	Add-Content $HtmlFile "<meta name='description' content='Comprobación del estado del Directorio Activo'/>"
	Add-Content $HtmlFile "<link rel='stylesheet' href='https://www.w3schools.com/w3css/4/w3.css'>"
	Add-Content $HtmlFile "<link rel='stylesheet' href='https://fonts.googleapis.com/icon?family=Material+Icons'>"
	Add-Content $HtmlFile "<style>.w3-content{max-width:1440px;}@media screen{.data-hide{overflow:hidden;height:1.5em;}} .microsoft-brand-color{ background-color:#00a1f1;color:white;}</style>"
	Add-Content $HtmlFile "<script type='text/javascript'>function flip_data(tag){ object = document.getElementById(tag); if (object.classList.contains('data-hide')) object.classList.remove('data-hide'); else object.classList.add('data-hide'); }</script>"
	Add-Content $HtmlFile "</head>"
	
	# HTML body
	
	Add-Content $HtmlFile "<body>"
	Add-Content $HtmlFile "<p class='w3-padding' style='margin:0;background-color:#0078d7;color:white;'>Microsoft&trade; Active Directory&trade;</p>"
	Add-Content $HtmlFile "<header class='w3-container w3-center w3-padding-64 w3-jumbo microsoft-brand-color'>"
	Add-Content $HtmlFile "<h1>Comprobaci&oacute;n del estado del Directorio Activo</h1>"
	Add-Content $HtmlFile "</header>"
	Add-Content $HtmlFile "<div class='w3-content'>"
	Add-Content $HtmlFile "<div class='w3-container w3-padding-32'>"
	Add-Content $HtmlFile "<h2>Comprobaciones realizadas: $($Tests -join ', ')</h2>"
	Add-Content $HtmlFile "<h2>Filtros aplicados: $($Filters -join ', ')</h2>"
	Add-Content $HtmlFile "<div class='w3-row-padding w3-stretch'>"
	
	$Summary = @{}

	$Summary['Failed'] = @()
	$Summary['Timeout'] = @()
	$Summary['Completed'] = @()
	
	$FilterResults | ForEach-Object{
		$Summary[$_.State] += $_.TestName;
	}
	
	$Summary['Failed'] | Sort-Object -Unique | ForEach-Object{
		Add-Content $HtmlFile "<div class='w3-col l2 m6 s12 w3-section'><div class='w3-card w3-red w3-padding-large w3-center' style='word-wrap:break-word;'><span class='w3-xlarge'>$($_)</span><br/>Failed</div></div>"
	}
	
	$Summary['Timeout'] | Sort-Object -Unique | ForEach-Object{
		Add-Content $HtmlFile "<div class='w3-col l2 m6 s12 w3-section'><div class='w3-card w3-yellow w3-padding-large w3-center' style='word-wrap:break-word;'><span class='w3-xlarge'>$($_)</span><br/>Timeout</div></div>"
	}
	
	Add-Content $HtmlFile "</div>"

	# HTML table

	Add-content $HtmlFile "<table class='w3-table-all w3-small'>" 
	Add-Content $HtmlFile "<tr>"
	Add-Content $HtmlFile "<th style='width:1%'>#</th>" 
	Add-Content $HtmlFile "<th style='width:9%'>Origen</th>" 
	Add-Content $HtmlFile "<th style='width:1%'>Comprobaci&oacute;n</th>" 
	Add-Content $HtmlFile "<th style='width:1%'>Estado</th>" 
	Add-Content $HtmlFile "<th style='width:10%'>Categor&iacute;a</th>"
	Add-Content $HtmlFile "<th style='width:25%'>Descripci&oacute;n</th>"
	Add-Content $HtmlFile "<th style='width:43%'>Detalles</th>"
	Add-Content $HtmlFile "<th style='width:10%'>Etiquetas</th>"
	Add-Content $HtmlFile "</tr>" 

	$FilterResults | ForEach-Object{
		$Results = $_
		
		If ($Results.State -eq 'Completed') { $StateColor = "w3-text-green" }
		ElseIf ($Results.State -eq 'Timeout') { $StateColor = "w3-text-yellow" }
		Else { $StateColor = "w3-text-red" }
		
		Add-content $HtmlFile "<tr>" 
		If (($Results.Data | Measure-Object).Count -gt 1) {
			Add-Content $HtmlFile "<td><a class='w3-text-blue' style='cursor:pointer;' onclick='flip_data(""data_$($Position)"")'>[+]</a></td>"
		}
		Else{
			Add-Content $HtmlFile "<td></td>" 
		}
		Add-Content $HtmlFile "<td>$([System.Web.HttpUtility]::HtmlEncode($Results.Source))</td>" 
		Add-Content $HtmlFile "<td>$([System.Web.HttpUtility]::HtmlEncode($Results.TestName))</td>" 
		Add-Content $HtmlFile "<td><span class='$($StateColor)'><strong>$([System.Web.HttpUtility]::HtmlEncode($Results.State))</strong></span></td>"
		Add-Content $HtmlFile "<td>$([System.Web.HttpUtility]::HtmlEncode($Results.Category))</td>"
		Add-Content $HtmlFile "<td>$([System.Web.HttpUtility]::HtmlEncode($Results.Description))</td>"
		If ($Results.Data) {
			Add-Content $HtmlFile "<td><div id='data_$($Position)' class='data-hide'>$((([System.Web.HttpUtility]::HtmlEncode($Results.Data -join ""`n"")).Trim(""`n"")).Replace(""`n"",""<br>""))</div></td>"
		}
		Else{
			Add-Content $HtmlFile "<td></td>"
		}
		Add-Content $HtmlFile "<td>$([System.Web.HttpUtility]::HtmlEncode($Results.Tags -join "", ""))</td>"
		Add-content $HtmlFile "</tr>" 
		$Position++
	}
	Add-content $HtmlFile "</table>"
	
	# HTML footer

	$StopWatch.Stop()
	Add-Content $HtmlFile "<p class='w3-tiny'><strong>Fecha de creación:</strong> $(Get-Date) ($($StopWatch.Elapsed.TotalSeconds) segundos)</p>"
	Add-Content $HtmlFile "</div>"
	Add-Content $HtmlFile "</div>"
	Add-Content $HtmlFile "<footer class='w3-container w3-dark-grey w3-padding-32 w3-margin-top w3-small'>"
	Add-Content $HtmlFile "<div class='w3-row-padding'>"
	Add-Content $HtmlFile "<div class='w3-col s12 m6 l6'>"
	Add-Content $HtmlFile "<p>Get-ADHealth $($Version) (basado en <a href='https://gist.github.com/AlexAsplund/28f6c3ef42418902885cde1b83ebc260'>ADHealthCheck-NoReport</a>)<br>"
	Add-Content $HtmlFile "Modificado por <a href='http://www.rrc2software.com'>Ram&oacute;n Rom&aacute;n Castro</a><br>"
	Add-Content $HtmlFile "Desarrollado con <a href='https://www.w3schools.com/w3css/default.asp' target='_blank'>w3.css</a></p>"
	Add-Content $HtmlFile "</div>"
	Add-Content $HtmlFile "<div class='w3-col s12 m6 l6'>"
	Add-Content $HtmlFile "<p><img class='w3-round w3-margin-right' src='https://www.gravatar.com/avatar/6aa0dbab21fb734130b9772c4f380deb?s=48&d=mm&r=g'/><span class='w3-large'>Ram&oacute;n Rom&aacute;n Castro</span></p>"
	Add-Content $HtmlFile "<p class='w3-small'><strong>correo:</strong> ramonromancastro@gmail.com<br><strong>web:</strong> <a href='http://www.rrc2software.com'>www.rrc2software.com</a></p>"
	Add-Content $HtmlFile "</div>"
	Add-Content $HtmlFile "</div>"
	Add-Content $HtmlFile "</footer>"
	Add-Content $HtmlFile "</body>" 
	Add-Content $HtmlFile "</html>"
}

$FilterResults
