# PwnBuilder

**Generador de comandos para 42 herramientas de pentesting y CTF**, de [Un Fantasma en el Sistema](https://www.unfantasmaenelsistema.com).

▶ **Abrir:** https://unfantasmaenelsistema.github.io/PwnBuilder/

Monta el comando de las herramientas de Kali marcando opciones, sin memorizar banderas. Ves el comando montarse en directo y lo copias a tu terminal.

> ⚖️ **Uso responsable.** Son herramientas ofensivas reales. PwnBuilder solo escribe el **texto** del comando: no ejecuta nada ni se conecta a ningún sitio. Úsalas únicamente sobre sistemas y redes propios o con autorización por escrito (pentest, CTF, laboratorio). El acceso no autorizado es delito.

## Herramientas (42)

- **Reconocimiento:** nmap, dig, whois, dnsenum, fierce, theHarvester, netdiscover, enum4linux, CeWL
- **Web:** dirb, Nikto, sqlmap, commix, WPScan, Wfuzz
- **Contraseñas:** Hydra, Medusa, Hashcat, John the Ripper, crunch
- **WiFi:** Airmon-ng, Airodump-ng, Aireplay-ng, Aircrack-ng
- **Sniffing / MITM:** tcpdump, TShark, arpspoof, Ettercap, dsniff
- **Explotación y shells:** Metasploit, msfvenom, SearchSploit, Netcat, socat
- **Reversing y forense:** GDB, radare2, objdump, strings, strace, binwalk, foremost, Volatility

## Qué cambió respecto a la versión anterior

- **Motor declarativo:** cada herramienta se describe por sus campos (`tools.js`) y el comando se arma solo. Añadir o corregir una herramienta es cambiar datos, no reescribir HTML+JS.
- **Comando en directo** y botón de copiar, con los campos obligatorios marcados en el propio comando (`‹…›`) hasta que los rellenas.
- **Buscador** y herramientas **agrupadas por categoría**, con descripción de cada una.
- **Bilingüe (ES/EN)** y **tema claro/oscuro**, con logo y enlaces de la casa.
- Correcciones: nmap ya no genera varios `-p` en conflicto (combina puertos y scripts en uno), sqlmap muestra todas las opciones de volcado, Wfuzz está disponible, y la **PWA** (instalable y con uso sin conexión) lleva iconos reales.

## PWA

Se puede «instalar» desde el navegador y funciona sin conexión: el *service worker* (`sw.js`) cachea el shell de la app. Todo con rutas relativas, así que funciona en cualquier subcarpeta.

## Privacidad

Todo ocurre en tu navegador. No se ejecuta ni se envía nada: solo se construye el texto del comando. Solo el idioma, el tema y la última herramienta se guardan en `localStorage`.

## Estructura

```
index.html   interfaz
app.js        motor (arma el comando), buscador, idioma, tema, PWA
tools.js      las 42 herramientas (campos + lógica); también se carga en Node
styles.css    estilos
manifest.webmanifest, sw.js, icons/   PWA
icono.png     logo de la casa
```

Para probar en local: `python -m http.server` y abre `http://localhost:8000`.

## English

**PwnBuilder** builds the command for 42 Kali pentesting/CTF tools (nmap, hydra, sqlmap, hashcat, aircrack-ng, Metasploit, Volatility…) by ticking options — no need to memorise flags. The command assembles live and you copy it to your terminal; required fields show as `‹…›` placeholders until filled. Data-driven engine (`tools.js`), search, category grouping, per-tool descriptions, installable PWA with offline support. **It only writes command text — it runs nothing and connects nowhere.** For authorised testing, CTFs and labs only. Bilingual (ES/EN), light/dark themes, everything in your browser.

## Licencia / License

[MIT](LICENSE) © Un Fantasma en el Sistema.
