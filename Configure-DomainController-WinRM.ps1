#Variables

#replace with your WinRM Cert Name
$TemplateName = 'EagersDomainController'

#replace with desired log path
$LogPath = "c:\scripts\winrmbindscript.log"

#region setup logging 
function Write-Log {
    param(
        [int]$ErrorLevel = 1, # 1 - info, 2 - warning, 3 - error
        [Parameter(position = 1, ValueFromPipeline = $true)][string]$Msg,
        [Parameter(position = 2)][string]$Component, # source of the entry
        [Parameter(position = 3)][string]$LogFile = $LogPath,
        [switch]$break,
        [switch]$tee

    )

    if ( !$Component ) { $Component = $PSCommandPath -replace '^.*\\|\.[^\.]*$' } # script name
    if ( !$LogFile ) { $LogFile = $PSCommandPath -replace '\.ps1$', '.log' } # <ScriptRoot>\<ScriptName>.log
    if ($break) { $Msg = '#############################################################' }
    if ($tee) { Write-Output $msg }
    $TZBias = (Get-WmiObject Win32_TimeZone).bias
    $Time = "$(Get-Date -Format 'HH:mm:ss.fff')$TZBias"
    $Date = Get-Date -Format 'MM-dd-yyyy'
    $Context = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    
    $LogEntry = "<![LOG[$Msg]LOG]!><time=`"$Time`" date=`"$Date`" component=`"$Component`" context=`"$Context`" type=`"$ErrorLevel`" thread=`"$pid`" file=`"`">"

    Add-Content -Path $LogFile -Value $LogEntry
    
} 
#endregion

#region Resolve the cert template name
Function Get-CertInfo {
    Param([Parameter(Mandatory = $true, 
            ValueFromPipeline = $true,
            ValueFromRemainingArguments = $false, 
            Position = 0,
            ParameterSetName = 'Parameter Set 1')]
        $cert)
    process {
        $cert | % {
            $_ | select `
                Friendlyname,
            Thumbprint,
            @{N = "Template"; E = { ($_.Extensions | 
                        ? { $_.oid.Friendlyname -match "Certificate Template Information" }).Format(0) `
                        -replace "(.+)?=(.+)\((.+)?", '$2' }
            },
            @{N = "Subject"; E = { $_.SubjectName.name } }, ValidThrough, NotAfter
        }
    }
}
#endregion

#check if listener already exists
$listener = dir WSMan:\localhost\Listener | where Keys -like *https* 

if ($listener) {
    #Listener already exists, verify it's using the right cert, and the longest possible cert

    #Resolve the HTTPs listener name
    $ListenerName = dir WSMan:\localhost\Listener | where Keys -like *https* | select -expand Name

    #Get the WINRM HTTPS listener certificate thumbprint remove spaces and then forceUpperCase
    $CertThumbprt = ((Get-ChildItem "WSMan:\localhost\Listener\$ListenerName" | where Name -like "CertificateThumbprint" | select -ExpandProperty Value) -replace ' ').ToUpper()

    #Compare that to our longest cert...
        
    #grabs the longest lasting cert availble for SSL 
    $longestCert = dir cert:\localmachine\My | Get-Certinfo |
    where Subject -like *$env:COMPUTERNAME* | where Template -eq $TemplateName | sort NotAfter -Descending | select -ExpandProperty ThumbPrint

    write-log "is the current cert for ssl the longest one available ? $($longestCert -eq $CertThumbprt)" -tee

    #Are we using the longest cert we could?  If so, we've got nothing to do, time to quit
    If ($longestCert -eq $CertThumbprt) {
        #we're done
        Write-log "This machine is using the longest possible cert for SSL, exiting with errorlevel 0..." -tee
        exit 0 
    }

    #Is $CertThumbPrt or $LongestCert actually nonexistant?
    if (($longestCert -eq $null) ) {
        #! Error condition: listener is enabled, but not using a valid cert
        Write-log "!error condtion: This machine doesn't have a valid cert anymore (maybe it changed names or domains?) errorlevel 1 ..." -tee
        exit 1 

        #later : try to renew a cert 
                
    }

    #Do we have a longer cert available and we're not using it?  Lets fix that
    If ($longestCert -ne $CertThumbprt) {
        Set-Location wsman:        
        dir WSMan:\localhost\Listener | ? Name -eq $ListenerName | Remove-Item -Recurse 
        winrm quickconfig -transport:https
    }

}
else {
    #if no listener...
    
    #attempts to find a certificate suitable for Client Authentication for this system, and picks the one with the longest date
    $longestCert = dir cert:\localmachine\My | Get-Certinfo |
    where Subject -like *$env:COMPUTERNAME* | where Template -eq $TemplateName |
    sort NotAfter -Descending 
    #region errorconditions 
    #if longestCert is empty, then we can't setup a listener, lets #exit
    If ($longestCert -eq $null) {
        Write-Log -Msg "!error condition: no valid cert to enable a listener (no cert or name mismatch), #exiting with errorlevel 3" -tee 
        exit 3
    }
    
    #cert has expired
    if ($longestcert.NotAfter -le (Get-Date)) {
        #! error condition: Certificate has expired 
        Write-Log -Msg "!error condition: The only cert available has expired, #exiting with errorlevel 1" -tee 
        
        #Renew cert steps go here
        exit 1 
    }
    #endregion

    #We have a valid cert, enabling winrm over https (tl: can't contain the output of this command below if it errors, sadly)
    Invoke-Expression "winrm quickconfig -transport:https -force" -ErrorVariable winRMerror | Out-Null
    if ($WinrmError) {
        #! error condition: winrm quickconfig failed for some reason
        Write-log "!error condition: winrm quickconfig failed for some reason, #exiting w/ errorlevel 4" -tee
        Write-log "!error text $WinrmError"
        exit 4 
    }

    #We need to create a service record to tell the domain we're listneing on https, let's do that below    
    $fqdn = [System.Net.Dns]::GetHostByName(($env:ComputerName)).HostName.ToLower()
    $SPNoutput = Invoke-Expression "setspn -S HTTPS/$fqdn $($env:COMPUTERNAME)" -ErrorVariable spnerror 
    
    
    #test for https record in output of prev cmd
    if ($out = $SPNoutput | Select-String HTTPS) {
        write-log "success!  SPN seems to have been created, output [$($out.ToString().Trim())]" -tee
        Write-Log "output from SPN command $SPNoutput"
        exit 0
    }
    else {
        write-log "!error condition: failed to create SPN! output [$SPNoutput] error [$SPNerror]" -tee
        write-log "!error condition: exiting with errorlevel 4" -tee
        exit 4
    }


}


# SIG # Begin signature block
# MIIPXAYJKoZIhvcNAQcCoIIPTTCCD0kCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUNl+iwANw8ZsMFRZAAyPYyVOQ
# CSSgggyWMIIGRTCCBC2gAwIBAgITEwAAAALT6MovLT5j/wAAAAAAAjANBgkqhkiG
# 9w0BAQsFADAXMRUwEwYDVQQDEwxFYWdlcnNSb290Q0EwHhcNMTkwOTI1MDExMTQ1
# WhcNMjkwOTI1MDEyMTQ1WjB3MRIwEAYKCZImiZPyLGQBGRYCYXUxEzARBgoJkiaJ
# k/IsZAEZFgNjb20xGDAWBgoJkiaJk/IsZAEZFghhcGVhZ2VyczEYMBYGCgmSJomT
# 8ixkARkWCHJlc291cmNlMRgwFgYDVQQDEw9FYWdlcnNJc3N1aW5nQ0EwggIiMA0G
# CSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDfiDx4l1Edy1kj7yn3tFmo6BLDq5fJ
# eW5/g4uzJnE74FXB0jP3V2d7sThXwy+IgRujne4FtJdNuEExpFgzIuNmgGP1dmnH
# kBKV5UNtRNOLpTjml6HouHnoffPeHAjGjtoGlBJjM1RXLnSCZjS8H9RHChDQ2uoA
# LELN+8t9UVOI4SHzTcLxVd6jZnpSjgazIw9wAhYyjWdVWWlJ6iCwoVUUX2AUHdSk
# AoThxKNJH2AKr4Qrs/M/2zqosMhcVTqHIczMbICOvDAYSWonY8CBLVa22pW7mHyy
# 2YqY0is+ScINXFWXLCBbxzvi1uEz/F4KIapegiMjshzqcXo6qRjWOADrPA1J694R
# zTBzLsk+Ios0y5TG7vT/C/NuR5wALDgsFu3TwhBo8Unsm8sUqThSNJVnt8v/sdwG
# P1DLXOB81IWpYcQouIaoRq0GUAeixNLXTY9gcTUbZCoDmhhoyvkYlg64lvcEWN1p
# G1i/5e6Cq7a47SvAmXCwoTVvz+waJ5E8KxSkvT/HbbybqYVC/9V65MfUs5UaU30Y
# hSF+JwS9ZbixKWdW1dNROaWmrNO+VCy0q1KhAHc++Jcc04ocbVxm9UNXxKUXc4Jz
# yuKULv29XO8BJgz29cN8+wzyIoxNgTD4TbKnCkt0uCvRe0UdA/sFxWduOpmvr6qS
# rjZ7F7n+8rsN3QIDAQABo4IBKDCCASQwEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0O
# BBYEFMnlCaZXgEJxyWXQgeTcLWXVm7cEMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIA
# QwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFOwn
# mhU+XpbiNTaDYdRMbeBl3QIqMEUGA1UdHwQ+MDwwOqA4oDaGNGh0dHA6Ly9lYWdl
# cnNyb290Y2EuYXBlYWdlcnMuY29tLmF1L0VhZ2Vyc1Jvb3RDQS5jcmwwUAYIKwYB
# BQUHAQEERDBCMEAGCCsGAQUFBzAChjRodHRwOi8vZWFnZXJzcm9vdGNhLmFwZWFn
# ZXJzLmNvbS5hdS9FYWdlcnNSb290Q0EuY3J0MA0GCSqGSIb3DQEBCwUAA4ICAQAH
# cAFN1CpX+AHXiUsqQa2sLggU7X9XAqAA/8xjhy1IdD6fIi4UB/2HpLW4Wa1wufuW
# 9ngCd3utHuhtk7g0tzQJiAg2NmQVqJgAo108y5nJXQjyn/fUDQUcMD+GWc4mADfv
# 8bveq1bLAu6pAo/4q1uONs0+sUoyEn5Kahtme2c6smTeGzT4jjQJVNoT3W0/trUq
# o1h34F+PeWLNcRAve/DiyXCHo/BhXV0R/OJ/BpVk7P/ooWoPIknofG8PL5xy8uFT
# 1pO4xcb/A4NfIFP1rm1P+ga+vVMsKrF9nAEdCHyzQFYiYLE3N+6aBnqP5iuxsa5L
# X83qqdADcpXt7KlPuSioG6Tm2Z27dsfcYj0Tn2uKer7vw/RnX2XXqTrR2uuPdap5
# Z2uItT5Vu2Fqs9c7vhCM2qzJ+/OjEBMiYT6sI3Q1AhWOfhfwCeyfgtUOpigKwHEE
# DMBlyNL4wlZFDJdSiVlKZ7E3Opq2+nZVeVLzHDtsnAPa3ULcW/LbjUv8uKwrjus+
# qd233N+ceRHgO37PwNacl1H+q6AA7fVILCN60Lg8se2pB9HchHm3W+h0DGWo3CpT
# b9t1pbnzMxdpjePmhEBqssdust7rIN4GzDNmWi1WUxoxmKjXgPzWXMG0rIiqqYtp
# tHkVxwoEB4y5TJZR3KlH7kfBM/V2GjVPVz+7Kd+KODCCBkkwggQxoAMCAQICE1cA
# AABQabdHMW1Xg40AAAAAAFAwDQYJKoZIhvcNAQELBQAwdzESMBAGCgmSJomT8ixk
# ARkWAmF1MRMwEQYKCZImiZPyLGQBGRYDY29tMRgwFgYKCZImiZPyLGQBGRYIYXBl
# YWdlcnMxGDAWBgoJkiaJk/IsZAEZFghyZXNvdXJjZTEYMBYGA1UEAxMPRWFnZXJz
# SXNzdWluZ0NBMB4XDTE5MTAxMTAwNTI0M1oXDTIxMTAxMDAwNTI0M1owgZkxEjAQ
# BgoJkiaJk/IsZAEZFgJhdTETMBEGCgmSJomT8ixkARkWA2NvbTEYMBYGCgmSJomT
# 8ixkARkWCGFwZWFnZXJzMRgwFgYKCZImiZPyLGQBGRYIcmVzb3VyY2UxDjAMBgNV
# BAsTBUFkbWluMQ4wDAYDVQQLEwVVc2VyczEaMBgGA1UEAxMRUGF0cmljayBPJ0Rv
# bm5lbGwwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCgn1zirPTUQZDY
# OoFnudK/fgyf00nKDs7zM4upLyxzYg0dvxw88k+0qtTXlbYQgw2MLT1Nr7k6r7kX
# 0p1vnVUPoQpP8IxWYZ00HnZQkS3VrcQEHwsiigq1V2EsLv913e67T7MAkiTBP43z
# r34esku02ZgU6xedXulgQC9vNjbBdVELbqEvSkPDeN04gAj602E4m5z9aY9R9irU
# lPDhkSOoW0dj1OyQE50jxx15CqTwXrJltTlN+fF/Cp73zJVN4IydMNnY/41VxXkf
# VHi4sqSvte79NDd07pI+nbPBjY0HJibdwDCiswN2UmIE+qX+nEPN5fb5BEOWJcVT
# 4bSG7tjxAgMBAAGjggGpMIIBpTA9BgkrBgEEAYI3FQcEMDAuBiYrBgEEAYI3FQiD
# 3bBCg4+8T4f9kTKD7405h4i/JBeDx/xWhcSUMgIBZAIBCDATBgNVHSUEDDAKBggr
# BgEFBQcDAzAOBgNVHQ8BAf8EBAMCB4AwGwYJKwYBBAGCNxUKBA4wDDAKBggrBgEF
# BQcDAzA9BgNVHREENjA0oDIGCisGAQQBgjcUAgOgJAwib2Rvbm5lbGxwQHJlc291
# cmNlLmFwZWFnZXJzLmNvbS5hdTAdBgNVHQ4EFgQUcKqsEQBNEOCfsQ0SYne4zLxz
# zpowHwYDVR0jBBgwFoAUyeUJpleAQnHJZdCB5NwtZdWbtwQwSwYDVR0fBEQwQjBA
# oD6gPIY6aHR0cDovL0VhZ2Vyc0lzc3VpbmdDQS5hcGVhZ2Vycy5jb20uYXUvRWFn
# ZXJzSXNzdWluZ0NBLmNybDBWBggrBgEFBQcBAQRKMEgwRgYIKwYBBQUHMAKGOmh0
# dHA6Ly9FYWdlcnNJc3N1aW5nQ0EuYXBlYWdlcnMuY29tLmF1L0VhZ2Vyc0lzc3Vp
# bmdDQS5jcnQwDQYJKoZIhvcNAQELBQADggIBAMlA/YyUyWE/BLooK40Rwn+cSNMa
# fgcWT7fqKXypuh9EY5Fs2zuzXkARNnOqr1fprWEOyD7zN8dmxRVYAwYLowgQbKNN
# GVqDtHkX0NbKVQzm785KfIuzBwniT9fV6SZdq5jVCtBdXTMoRUy+6MeJtMy1eVIx
# OEsu+wmN78ykapWTK69hKWiQ2vA90pki58n5F6/9h9oTtDh438Vhft9iu9Shaohe
# oDHzL06Ad5tKwlkjqgoFJEPYsxnssynYClvfhjmulCeeNs4cKM8uLeqgqkua9XwI
# DzjU8w49a5KBDj5Pxh5as049IRPUYaHR6h08/bKQf16FvXiTdfRUpZ91ap0QcpAC
# aDgdIF/0DTp4VS/louwBG0Xys4ZKJnGyIdTdeUDnkxwatPfj1j/9JFgSXc1DOSIp
# RoyjBHObqxWM3CAg+X8r42bDMEV+hE/xeqg+wjJMBsmLgxQjXl9Ai18xF8dszdZq
# +KnlWnf6JwLHzd7QWlsPVip8qnjyUh3+kV7wpUpq89Zh5jupfNtkRPwJtGI+IPCK
# Nr5eD6xS1y2EMdlckGu8OQPGH04GIDFiJ7FHTdeCb865J9Z+JOMRNkEVuakgz2LH
# K7ivD3nti7caEhS9dDyvnwOUc5deZghs/n3loJhDTZJQ7/SmyIjCbJ8yjmQPMVx6
# ZzN9WTe+wsF6VcI5MYICMDCCAiwCAQEwgY4wdzESMBAGCgmSJomT8ixkARkWAmF1
# MRMwEQYKCZImiZPyLGQBGRYDY29tMRgwFgYKCZImiZPyLGQBGRYIYXBlYWdlcnMx
# GDAWBgoJkiaJk/IsZAEZFghyZXNvdXJjZTEYMBYGA1UEAxMPRWFnZXJzSXNzdWlu
# Z0NBAhNXAAAAUGm3RzFtV4ONAAAAAABQMAkGBSsOAwIaBQCgeDAYBgorBgEEAYI3
# AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisG
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBRjeiNrTQ/k
# KXct3cCvKVfzg2Xd8TANBgkqhkiG9w0BAQEFAASCAQCIwSolpy7fWHpxirr4JL8D
# RAO/m31bMuVNOoNNk9GrDTLeWpjj9nNG7X3bkckKC3NeyKeMhZdMYQzcOS7fBfKW
# 3e+9CMH9A+Ku4pEVjfEMq1QxzhZ34ngDtmrbv3JYqGa85TdIDKnXSy3ahbxbrFWh
# Blo8plOh2LtxBBfUCfdptRQpm0EGCqjuPtsnVvnGkQii8wduZACkwyKOPNlknaO9
# SfpdLe/TDyLy3eIuh38ykggMVUkNJNB0nyRts6AeMocS/wMLZIxVCjuPi8FRmgT9
# fV5dANXp/IaysD8TJpEwkd9FBl2bbqWgwDmZOwcGReUo+znqRWpr/mOkUz+HmlbS
# SIG # End signature block
