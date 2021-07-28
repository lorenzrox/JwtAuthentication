.tools\iisschema.exe /uninstall jwtauthentication_schema.xml /y
.tools\iisschema.exe /install JwtAuthentication\jwtauthentication_schema.xml.
%windir%\System32\inetsrv\appcmd.exe uninstall module JwtAuthenticationModule
%windir%\System32\inetsrv\appcmd.exe install module /name:JwtAuthenticationModule /image:C:\iis\native_modules\JwtAuthentication.dll
pause