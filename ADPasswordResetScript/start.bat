@ECHO OFF

set debug=0

IF NOT "%1"=="" (
	IF "%1"=="d" (SET debug=1)
	)

set "commandToRun=powershell -ExecutionPolicy Bypass -File %~dp0\ADPS.ps1 "


if %debug% == 0 ( start /MAX %commandToRun% )
if %debug% NEQ 0 ( cmd /c %commandToRun% )

if %debug% NEQ 0 pause

EXIT 0