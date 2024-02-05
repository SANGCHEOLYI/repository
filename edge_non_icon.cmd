+
:: BatchGotAdmin
 :-------------------------------------
 REM  --> Check for permissions
 >nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"

REM --> If error flag set, we do not have admin.
 if '%errorlevel%' NEQ '0' (
     echo Requesting administrative privileges...
     goto UACPrompt
 ) else ( goto gotAdmin )

:UACPrompt
     echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
     echo UAC.ShellExecute "%~s0", "", "", "runas", 1 >> "%temp%\getadmin.vbs"

    "%temp%\getadmin.vbs"
     exit /B

:gotAdmin
     if exist "%temp%\getadmin.vbs" ( del "%temp%\getadmin.vbs" )
     pushd "%CD%"
     CD /D "%~dp0"
 :-------------------------------------
net use \\158.44.13.189 /user:user 852000
::copy MicrosoftEdgePolicyTemplates

copy \\158.44.13.189\data\gpedit_browser\MicrosoftEdgePolicyTemplates\windows\admx\en-US\*.* C:\Windows\PolicyDefinitions\en-US\*.*

copy \\158.44.13.189\data\gpedit_browser\MicrosoftEdgePolicyTemplates\windows\admx\\ko-KR\*.* C:\Windows\PolicyDefinitions\\ko-KR\*.*

copy \\158.44.13.189\data\gpedit_browser\MicrosoftEdgePolicyTemplates\windows\admx\*.* C:\Windows\PolicyDefinitions\*.*

copy \\158.44.13.189\data\gpedit_browser\MicrosoftEdgePolicyTemplates\ie_list.xml C:\Users\ie_list.xml

xcopy \\158.44.13.189\data\gpedit_browser\EMRClient_ActiveX.exe "C:\Windows\System32\EMRClient_ActiveX.*" /y
xcopy \\158.44.13.189\data\gpedit_browser\EMRClient_ActiveX.exe "C:\Windows\SysWOW64\EMRClient_ActiveX.*" /y
xcopy \\158.44.13.189\data\gpedit_browser\EMRClient_ActiveX.exe "C:\Program Files\EMR\EMRClient_ActiveX.*" /y
xcopy \\158.44.13.189\data\gpedit_browser\EMRClient_ActiveX.exe "C:\Program Files (x86)\EMR\EMRClient_ActiveX.*" /y

xcopy \\158.44.13.189\data\gpedit_browser\edgeapp_emr.lnk "%UserProfile%\Desktop\emr(¿§Áö¾Û).*" /y /k

xcopy \\158.44.13.189\data\gpedit_browser\edgeweb_emr.lnk "%UserProfile%\Desktop\emr(¿§Áö).*" /y /k

::ÀÌÀü ¿§ÁöÁ¤Ã¥ »èÁ¦

del C:\driver\MS_EDGE_BHO.bat

REG DELETE HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge /f
REG DELETE HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Edge /f

::gpedit ¼³Á¤

reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" /v "InternetExplorerIntegrationLevel" /t REG_DWORD /d "1" /f
reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" /v "InternetExplorerIntegrationSiteList" /d "C:\Users\ie_list.xml" /f
reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" /v "DefaultPopupsSetting" /t REG_DWORD /d "1" /f

C:\Windows\SysWOW64\EMRClient_ActiveX.exe

::reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" /v "WebAppInstallForceList" /d "[{\"create_desktop_shortcut\":true,\"default_launch_container\":\"window\",\"url\":\"https://hi.bohun.or.kr\",\"fallback_app_name\":\"BOHUN_EMR\"}]" /f

::ÆË¾÷ Â÷´Ü Çã¿ë¸ñ·Ï

reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge\PopupsAllowedForUrls" /v "1" /d "[*.]bohun.or.kr" /f
reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge\PopupsAllowedForUrls" /v "2" /d "[*.]cdc.go.kr" /f
reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge\PopupsAllowedForUrls" /v "3" /d "[*.]kdca.go.kr" /f
reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge\PopupsAllowedForUrls" /v "4" /d "[*.]learning-hub.co.kr" /f
reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge\PopupsAllowedForUrls" /v "5" /d "[*.]studymart.co.kr" /f
reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge\PopupsAllowedForUrls" /v "6" /d "[*.]hunet.co.kr" /f
reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge\PopupsAllowedForUrls" /v "7" /d "[*.]nhis.or.kr" /f
reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge\PopupsAllowedForUrls" /v "8" /d "[*.]kims.co.kr" /f
reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge\PopupsAllowedForUrls" /v "9" /d "[*.]ncc.re.kr" /f

GPUPDATE /FORCE

net use \\158.44.13.189 /delete