# AD User Search and Password Reset by Matthew Podowski
#Requires -Version 5.1
# Requires -Module activedirectory
#Import-Module activedirectory
<# 
This script requires Windows ActiveDirectory tools to be installed. 
In Windows 10 1809 or later you can run the following two commands to install them:
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Servicing" /v RepairContentServerSource /d 2 /t REG_DWORD /f
powershell.exe -NoProfile -Command "Get-WindowsCapability -Online | Where-Object {$_.Name -like 'Rsat.ActiveDirectory*'} | Add-WindowsCapability -Online

#run PS script from a cmd prompt:
powershell -executionpolicy bypass ".\ADPS.ps1

#>

$Log_File = "$PSScriptRoot\ADPS_Log_File.txt"
$Log_errors = $false
$searchResultsSizeLimit = 50

$trimFromCanonicalName = 'contoso.com/'
$emailRoot1 = '@contoso.com'
$emailRoot2 = '@subdomain.contoso.com'



Function searchADUser {
	param (
		[string]$searchThisString
	)

$e = [char]27
#For readability, the line below has been split up using ` 
Get-ADUser -LDAPFilter:"(anr=$searchThisString)" -properties CanonicalName,PasswordExpired,PasswordLastSet,`
lastlogontimestamp,birthDate,employeeNumber,extensionAttribute9,LockedOut,description,title -ResultSetSize:"$searchResultsSizeLimit" `
| sort surName | `
Format-Table @{Label="givenName"; Expression={ 
	if ($_.CanonicalName -split '/' -contains 'Deprovision') { $color = "90" }
	"$e[${color}m$($_.givenName )${e}[0m"
	}}, `
@{Label="surName"; Expression={ 
	if ($_.CanonicalName -split '/' -contains 'Deprovision') { $color = "90" }
	"$e[${color}m$($_.surName )${e}[0m"
	}}, `
@{Label="UserPrincipalName"; Expression={ 
	if ($_.CanonicalName -split '/' -contains 'Deprovision') { $color = "90" }
	"$e[${color}m$($_.UserPrincipalName )${e}[0m"
	}}, `
@{Label="ID number"; Expression={
	if ($_.CanonicalName -split '/' -contains 'Deprovision') { $color = "90" }
	"$e[${color}m$($_.employeeNumber )${e}[0m"
	}}, `
@{Label="birthDate"; Expression={
	if ($_.CanonicalName -split '/' -contains 'Deprovision') { $color = "90" }
	"$e[${color}m$($_.birthDate.Insert(4,'-').Insert(7,'-') )${e}[0m"
	}}, `
@{Label="alternateEmail"; Expression={
	if ($_.CanonicalName -split '/' -contains 'Deprovision') { $color = "90" }
	"$e[${color}m$($_.extensionAttribute9 )${e}[0m"
	}}, `
@{Label="pwState"; Expression={
	$t = "OK"
	if ("True" -eq $_.PasswordExpired) { $color = "90" ; $t = "Expired" }
	if ("True" -eq $_.LockedOut) { $color = "31" ; $t = "Locked" }
	"$e[${color}m$( $t )${e}[0m" 
	}}, `
@{Label="passwordLastSet"; Expression={
	if ("True" -eq $_.PasswordExpired) { $color = "90" }
	"$e[${color}m$(($_.passwordLastSet).ToString("M-dd-yyyy h:mm tt ") )${e}[0m" 
	}}, `
@{Label="container"; Expression={
	if ($_.CanonicalName -split '/' -contains 'Deprovision') { $color = "90" }
	"$e[${color}m$(($_.CanonicalName -replace $trimFromCanonicalName,'' -replace $_.Name,'').TrimEnd('/') )${e}[0m "
	}}, `
@{Label="title/description"; Expression={
	if ($_.CanonicalName -split '/' -contains 'Deprovision') { $color = "90" }
	$t = $_.title + $_.description
	if ( $_.title -And $_.description ) { $t = $_.title + ' / ' + $_.description }
	"$e[${color}m$( $t )${e}[0m"
	}}

}


Function getADUserShort {
		param (
		[string]$getThisID
	)
	Get-ADUser -Identity $getThisID -properties employeeNumber, passwordLastSet | Format-Table givenName, surName, UserPrincipalName, @{Label="ID number"; Expression={$_.employeeNumber}}, @{Label="passwordLastSet"; Expression={($_.passwordLastSet).ToString("M-dd-yyyy h:mm tt ")}}
}



Function ResetPass {
write-host
$resetThisID = (read-host -Prompt  "Enter username or email to reset password for")
$resetThisID = $resetThisID -replace $emailRoot2,'' -replace $emailRoot1,''
write-host -fore magenta $resetThisID

#verify user or exit
	try{
		getADUserShort $resetThisID
	} catch {
		write-host -fore yellow "Not a valid username! Please try again.
		"
		return
	}

$tempString = read-host -Prompt  "Enter a password (e to exit)"

	if ($tempString.length -eq 1 -and $tempString -match "e") {
		write-host "Cancelled.
		"
		return
	}
	while ($tempString.length -lt 8) {
		$tempString = Read-Host "Please enter at least 8 characters"
		if ($tempString -match "e") { return }
	}

$SecPaswd = ConvertTo-SecureString -String $tempString -AsPlainText -Force

	try{
		Set-ADAccountPassword -Identity $resetThisID -NewPassword $SecPaswd -Reset -PassThru -Verbose -ErrorAction Stop -Confirm:$true 
		#-WhatIf:$true
    } catch {
        write-warning $Error[0]
		if ( $Log_errors ) { write-output "$(Get-TimeStamp) Reset failed $resetThisID : $Error[0]" | Out-File $Log_File -Force -Append }
        return
    }

	try{
		Set-ADUser -Identity $resetThisID -ChangePasswordAtLogon $false
    } catch {
        write-warning $Error[0]
		if ( $Log_errors ) { write-output "$(Get-TimeStamp) Warning: $Error[0]" | Out-File $Log_File -Force -Append }
    }

	try{
		Unlock-ADAccount -Identity $resetThisID
    } catch {
        write-warning $Error[0]
		if ( $Log_errors ) { write-output "$(Get-TimeStamp) Warning: $Error[0]" | Out-File $Log_File -Force -Append }
    }

write-output "$(Get-TimeStamp) Reset success: $resetThisID" | Out-File $Log_File -Force -Append
Write-Host -fore cyan $tempString

write-host "
Success. Press any key to clear the screen and continue..."
$x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
clear
getADUserShort $resetThisID
write-host
}


Function UnLock {
write-host
$resetThisID = (read-host -Prompt  "Enter username or email to unlock")
$resetThisID = $resetThisID -replace $emailRoot2,'' -replace $emailRoot1,''
#write-host -fore magenta $resetThisID

#verify user or exit
	try{
		getADUserShort $resetThisID
	} catch {
		write-warning $Error[0]
		write-host "Please try again.
		"
		return
	}

	try{
		Unlock-ADAccount -Identity $resetThisID
    } catch {
		write-warning $Error[0]
        if ( $Log_errors ) { write-output "$(Get-TimeStamp) Unlock failed ( $resetThisID ): $Error[0]"  | Out-File $Log_File -Force -Append }
		write-host
        return
    }

write-output "$(Get-TimeStamp) Unlock success: $resetThisID" | Out-File $Log_File -Force -Append
write-host -fore magenta "$resetThisID unlocked.
"
getADUserShort $resetThisID
write-host
}


Function GetDetails {
write-host "
---Get Details---
Note: only first 3 results will be returned."
$detailSearch = (read-host -Prompt  "Enter user to get details for")

if ($detailSearch.length -lt 2) {
write-host "Please enter at least two characters.
"
return }

write-host -fore magenta $detailSearch
try{
    Get-AdUser -LDAPFilter:"(anr=$detailSearch)" -ResultSetSize:"3" -Properties memberof, description, PasswordExpired, PasswordLastSet, birthDate, employeeNumber, extensionAttribute9, BadLogonCount, badPwdCount, UserPrincipalName, DisplayName, DistinguishedName, Division, DoesNotRequirePreAuth, EmailAddress, Enabled, LastBadPasswordAttempt, LockedOut, logonCount, ObjectClass, Office, OfficePhone, PasswordNeverExpires, sAMAccountName, department, company, manager, title | Format-List
} catch{
    write-host -fore yellow "Not a valid username! Please try again.
	"
    return
}


write-host "End of details."
}


function DisplayLog {
	write-host "
	Last 50 log entries:"
	Get-Content $Log_File | select -Last 50
	write-host
}


function Get-TimeStamp {

    return "[{0:MM/dd/yy} {0:HH:mm:ss}]" -f (Get-Date)

}

function InstallComponents {
write-host "
Installing ActiveDirectory components...
"
#TODO: If Win build lower than 1809/17763 then error out and quit.
# If Win build higher than ...

#TODO: elevation code if script is not already run as admin.
#Start-Process -FilePath "powershell" -Verb runAs

#Get-ItemProperty -Path HKLM:SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Name UseWUServer
Set-ItemProperty -Path HKLM:SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Name UseWUServer -Value 0

Restart-Service -Name wuauserv -Force

Get-WindowsCapability -Online | Where-Object {$_.Name -like 'Rsat.ActiveDirectory*'} | Add-WindowsCapability -Online
write-host "
Install completed.
"
}

function ShortGreeting {
	whoami
	write-host "ADPS v1.3beta
Search by name, login, or ID."
write-host -fore cyan "Enter 'h' to see help.

"
}


##### main loop
$host.UI.RawUI.WindowTitle = "ADPS"
whoami
write-host "
Welcome to AD user search and reset! v1.3
Search by name, login, or ID."
write-host -fore cyan "Enter 'h' to see help.

"

while (($mainInput = Read-Host -Prompt "Enter search term or r/d/h") -ne "e") {
switch ($mainInput) {
   r { ResetPass }
   e {"Exit" ; exit }
   d {"Details" ; GetDetails }
   u {"Unlock" ; UnLock }
   c {"Clear" ; clear ; ShortGreeting }
   l { DisplayLog }
   n { InstallComponents }
   h {"
   Help:
   	<string> - search AD for this string. Accepts two or more characters.
	r - reset password
	u - unlock account
	d - get details for a user
	l - show log entries
	c - clear screen
	h - help
	e - exit

	Search results limited to 50 entries.
	Best if viewed full-screen at 1680 resolution or better.
	Windows RSAT.ActiveDirectory components are required. Run 'n' to install from script.

   "}
   default { write-host
			if ($mainInput.length -lt 2) {
			write-host
			} else { searchADUser $mainInput ; write-host }
		}
	}
}

#TODO:
#Fix the occasional leftover buffer output from Details function. Fixed?
#Color-code main search results: Alternate Row Highlight
#Temp unlock search limit?



#This version:
#Changed order of last column fields, added a separator between them.
#Display short greeting when clearing screen.
#Display user running the script in greeting.
#Display affected user account after resetting or unlocking.
#Small code and text improvements.

