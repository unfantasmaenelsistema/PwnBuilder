/* tools.js — definición de las 42 herramientas de PwnBuilder (Un Fantasma en el Sistema, MIT)
 * Cada herramienta describe sus campos; el comando se arma solo (o con un build propio).
 * Tipos de campo: head | text | num | opt | flag | select
 *   opt/text/num → añade «flag valor» si hay valor (flag '' = posicional); req:1 lo marca obligatorio.
 *   flag → añade «flag» si está marcado.  select → añade el valor elegido.
 *   raw:1 → no entrecomilla (para valores que ya son seguros o llevan su propia sintaxis). */
(function (root) {
  'use strict';
  function L(es, en) { return { es: es, en: en }; }

  var CATS = {
    recon: L('Reconocimiento y enumeración', 'Reconnaissance & enumeration'),
    web: L('Web', 'Web'),
    pass: L('Contraseñas y fuerza bruta', 'Passwords & brute force'),
    wifi: L('WiFi', 'Wi-Fi'),
    mitm: L('Sniffing y MITM', 'Sniffing & MITM'),
    exploit: L('Explotación y shells', 'Exploitation & shells'),
    rev: L('Reversing y forense', 'Reverse engineering & forensics')
  };

  var T = [
    // ───────── Reconocimiento ─────────
    { id: 'nmap', cat: 'recon', bin: 'nmap', name: 'Nmap', d: L('Escáner de puertos, servicios, versiones y vulnerabilidades por NSE.', 'Scanner for ports, services, versions and NSE vulnerability scripts.'),
      fields: [
        { k: 'text', id: 'target', req: 1, ph: '192.168.1.0/24', l: L('IP / rango (obligatorio)', 'IP / range (required)') },
        { k: 'text', id: 'ports', ph: '22,80,443', l: L('Puertos', 'Ports') },
        { k: 'head', l: L('Descubrimiento', 'Discovery') },
        { k: 'flag', id: 'sn', flag: '-sn', l: L('Ping scan, sin puertos (-sn)', 'Ping scan, no ports (-sn)') },
        { k: 'flag', id: 'Pn', flag: '-Pn', l: L('No hacer ping (-Pn)', 'No ping (-Pn)') },
        { k: 'flag', id: 'F', flag: '-F', l: L('Rápido, 100 puertos (-F)', 'Fast, top 100 ports (-F)') },
        { k: 'flag', id: 'pall', flag: '-p-', l: L('Todos los puertos (-p-)', 'All ports (-p-)') },
        { k: 'head', l: L('Escaneo', 'Scan') },
        { k: 'flag', id: 'sS', flag: '-sS', l: L('SYN scan (-sS)', 'SYN scan (-sS)') },
        { k: 'flag', id: 'sU', flag: '-sU', l: L('UDP scan (-sU)', 'UDP scan (-sU)') },
        { k: 'flag', id: 'sV', flag: '-sV', l: L('Versión de servicios (-sV)', 'Service version (-sV)') },
        { k: 'flag', id: 'O', flag: '-O', l: L('Detección de SO (-O)', 'OS detection (-O)') },
        { k: 'flag', id: 'A', flag: '-A', l: L('Agresivo: -sV -O -sC (-A)', 'Aggressive: -sV -O -sC (-A)') },
        { k: 'flag', id: 'sC', flag: '-sC', l: L('Scripts por defecto (-sC)', 'Default scripts (-sC)') },
        { k: 'select', id: 'T', l: L('Velocidad', 'Timing'), opts: [{ v: '', l: L('(por defecto)', '(default)') }, { v: '-T2', l: L('T2 educado', 'T2 polite') }, { v: '-T3', l: L('T3 normal', 'T3 normal') }, { v: '-T4', l: L('T4 rápido', 'T4 fast') }, { v: '-T5', l: L('T5 agresivo', 'T5 insane') }] },
        { k: 'flag', id: 'v', flag: '-v', l: L('Verbose (-v)', 'Verbose (-v)') },
        { k: 'head', l: L('Enumeración por servicio (añade scripts)', 'Service enumeration (adds scripts)') },
        { k: 'flag', id: 'smb', l: L('SMB (445, smb-*)', 'SMB (445, smb-*)') },
        { k: 'flag', id: 'ftp', l: L('FTP anónimo (21)', 'FTP anon (21)') },
        { k: 'flag', id: 'ssh', l: L('SSH (22, ssh-*)', 'SSH (22, ssh-*)') },
        { k: 'flag', id: 'http', l: L('HTTP (80, http-*)', 'HTTP (80, http-*)') },
        { k: 'flag', id: 'mysql', l: L('MySQL (3306)', 'MySQL (3306)') },
        { k: 'flag', id: 'mssql', l: L('MSSQL (1433)', 'MSSQL (1433)') },
        { k: 'head', l: L('Vulnerabilidades (NSE)', 'Vulnerabilities (NSE)') },
        { k: 'flag', id: 'heartbleed', l: L('Heartbleed', 'Heartbleed') },
        { k: 'flag', id: 'eternalblue', l: L('EternalBlue (MS17-010)', 'EternalBlue (MS17-010)') },
        { k: 'flag', id: 'shellshock', l: L('Shellshock', 'Shellshock') },
        { k: 'flag', id: 'vuln', l: L('Categoría vuln (--script vuln)', 'vuln category (--script vuln)') },
        { k: 'text', id: 'script', ph: 'http-enum,vulners', l: L('Scripts NSE adicionales', 'Extra NSE scripts') },
        { k: 'head', l: L('Salida', 'Output') },
        { k: 'text', id: 'out', ph: 'resultado', l: L('Archivo de salida (-oA, sin extensión)', 'Output file (-oA, no extension)') }
      ],
      build: function (v) {
        var p = ['nmap'], inc = false, ports = [], scripts = [];
        ['sn', 'Pn', 'F', 'pall', 'sS', 'sU', 'sV', 'O', 'A', 'sC', 'v'].forEach(function (id) {
          if (v.c(id)) p.push(v.field(id).flag);
        });
        if (v.v('T')) p.push(v.v('T'));
        var svc = { smb: [445, 'smb-*'], ftp: [21, 'ftp-anon'], ssh: [22, 'ssh-*'], http: [80, 'http-*'], mysql: [3306, 'mysql-*'], mssql: [1433, 'ms-sql-*'] };
        Object.keys(svc).forEach(function (id) { if (v.c(id)) { ports.push(svc[id][0]); scripts.push(svc[id][1]); } });
        if (v.c('heartbleed')) scripts.push('ssl-heartbleed');
        if (v.c('eternalblue')) scripts.push('smb-vuln-ms17-010');
        if (v.c('shellshock')) scripts.push('http-shellshock');
        if (v.c('vuln')) scripts.push('vuln');
        if (v.v('script')) scripts.push(v.v('script'));
        if (v.v('ports')) ports.unshift(v.v('ports'));
        if (ports.length) p.push('-p ' + ports.join(','));
        if (scripts.length) p.push('--script ' + scripts.join(','));
        if (v.v('out')) p.push('-oA ' + v.q(v.v('out')));
        var tgt = v.v('target');
        if (!tgt) { inc = true; tgt = '‹IP›'; }
        p.push(v.v('target') ? v.q(tgt) : tgt);
        return { cmd: p.join(' '), incomplete: inc };
      } },
    { id: 'dig', cat: 'recon', bin: 'dig', name: 'dig', d: L('Consultas DNS: registros A, MX, TXT, trazado…', 'DNS lookups: A, MX, TXT records, tracing…'),
      fields: [
        { k: 'opt', id: 'server', flag: '@', ph: '8.8.8.8', l: L('Servidor DNS (@)', 'DNS server (@)'), glue: 1 },
        { k: 'opt', id: 'domain', flag: '', req: 1, ph: 'example.com', l: L('Dominio (obligatorio)', 'Domain (required)') },
        { k: 'select', id: 'type', flag: '', raw: 1, l: L('Tipo de registro', 'Record type'), opts: [{ v: '', l: L('(A por defecto)', '(A by default)') }, { v: 'A', l: L('A', 'A') }, { v: 'AAAA', l: L('AAAA', 'AAAA') }, { v: 'MX', l: L('MX', 'MX') }, { v: 'NS', l: L('NS', 'NS') }, { v: 'TXT', l: L('TXT', 'TXT') }, { v: 'SOA', l: L('SOA', 'SOA') }, { v: 'CNAME', l: L('CNAME', 'CNAME') }, { v: 'ANY', l: L('ANY', 'ANY') }, { v: 'AXFR', l: L('AXFR (transferencia de zona)', 'AXFR (zone transfer)') }] },
        { k: 'flag', id: 'short', flag: '+short', l: L('Respuesta corta (+short)', 'Short answer (+short)') },
        { k: 'flag', id: 'trace', flag: '+trace', l: L('Trazar desde la raíz (+trace)', 'Trace from root (+trace)') }
      ] },
    { id: 'whois', cat: 'recon', bin: 'whois', name: 'whois', d: L('Datos de registro de un dominio o IP.', 'Registration data for a domain or IP.'),
      fields: [{ k: 'flag', id: 'v', flag: '-v', l: L('Verbose (-v)', 'Verbose (-v)') }, { k: 'opt', id: 'domain', flag: '', req: 1, ph: 'example.com', l: L('Dominio o IP (obligatorio)', 'Domain or IP (required)') }] },
    { id: 'dnsenum', cat: 'recon', bin: 'dnsenum', name: 'dnsenum', d: L('Enumeración DNS: subdominios, MX, transferencias de zona.', 'DNS enumeration: subdomains, MX, zone transfers.'),
      fields: [
        { k: 'opt', id: 'domain', flag: '', req: 1, ph: 'example.com', l: L('Dominio (obligatorio)', 'Domain (required)') },
        { k: 'opt', id: 'wordlist', flag: '-f', ph: '/usr/share/wordlists/subdomains.txt', l: L('Diccionario de subdominios (-f)', 'Subdomain wordlist (-f)') },
        { k: 'flag', id: 'enum', flag: '--enum', l: L('Enumeración completa (--enum)', 'Full enumeration (--enum)') },
        { k: 'opt', id: 'out', flag: '-o', ph: 'dnsenum.xml', l: L('Salida XML (-o)', 'XML output (-o)') }
      ] },
    { id: 'fierce', cat: 'recon', bin: 'fierce', name: 'fierce', d: L('Localiza objetivos DNS no contiguos de un dominio.', 'Finds non-contiguous DNS targets of a domain.'),
      fields: [
        { k: 'opt', id: 'domain', flag: '--domain', req: 1, ph: 'example.com', l: L('Dominio (obligatorio)', 'Domain (required)') },
        { k: 'opt', id: 'wordlist', flag: '--subdomain-file', ph: '/usr/share/wordlists/subdomains.txt', l: L('Diccionario de subdominios', 'Subdomain wordlist') }
      ] },
    { id: 'theHarvester', cat: 'recon', bin: 'theHarvester', name: 'theHarvester', d: L('OSINT: correos, subdominios y hosts en fuentes públicas.', 'OSINT: emails, subdomains and hosts from public sources.'),
      fields: [
        { k: 'opt', id: 'domain', flag: '-d', req: 1, ph: 'example.com', l: L('Dominio (obligatorio)', 'Domain (required)') },
        { k: 'num', id: 'limit', flag: '-l', ph: '500', l: L('Límite de resultados (-l)', 'Result limit (-l)') },
        { k: 'opt', id: 'sources', flag: '-b', ph: 'bing,crtsh,duckduckgo', l: L('Fuentes (-b)', 'Sources (-b)') }
      ] },
    { id: 'netdiscover', cat: 'recon', bin: 'netdiscover', name: 'netdiscover', d: L('Descubre hosts activos en la red por ARP.', 'Discovers live hosts on the network via ARP.'),
      fields: [
        { k: 'opt', id: 'iface', flag: '-i', ph: 'eth0', l: L('Interfaz (-i)', 'Interface (-i)') },
        { k: 'opt', id: 'range', flag: '-r', ph: '192.168.1.0/24', l: L('Rango (-r)', 'Range (-r)') },
        { k: 'flag', id: 'p', flag: '-p', l: L('Modo pasivo (-p)', 'Passive mode (-p)') }
      ] },
    { id: 'enum4linux', cat: 'recon', bin: 'enum4linux', name: 'enum4linux', d: L('Enumeración de SMB/Samba en sistemas Windows.', 'SMB/Samba enumeration on Windows systems.'),
      fields: [
        { k: 'flag', id: 'a', flag: '-a', l: L('Todo (-a)', 'Everything (-a)') },
        { k: 'flag', id: 'U', flag: '-U', l: L('Usuarios (-U)', 'Users (-U)') },
        { k: 'flag', id: 'S', flag: '-S', l: L('Recursos compartidos (-S)', 'Shares (-S)') },
        { k: 'flag', id: 'P', flag: '-P', l: L('Política de contraseñas (-P)', 'Password policy (-P)') },
        { k: 'opt', id: 'target', flag: '', req: 1, ph: '192.168.1.10', l: L('IP (obligatorio)', 'IP (required)') }
      ] },
    { id: 'cewl', cat: 'recon', bin: 'cewl', name: 'CeWL', d: L('Crea diccionarios rastreando las palabras de una web.', 'Builds wordlists by crawling a website’s words.'),
      fields: [
        { k: 'num', id: 'depth', flag: '-d', ph: '2', l: L('Profundidad (-d)', 'Depth (-d)') },
        { k: 'num', id: 'min', flag: '-m', ph: '5', l: L('Longitud mínima (-m)', 'Min length (-m)') },
        { k: 'flag', id: 'e', flag: '-e', l: L('Incluir correos (-e)', 'Include emails (-e)') },
        { k: 'opt', id: 'out', flag: '-w', ph: 'palabras.txt', l: L('Guardar en (-w)', 'Save to (-w)') },
        { k: 'opt', id: 'url', flag: '', req: 1, ph: 'https://example.com', l: L('URL (obligatorio)', 'URL (required)') }
      ] },
    // ───────── Web ─────────
    { id: 'dirb', cat: 'web', bin: 'dirb', name: 'dirb', d: L('Fuerza bruta de rutas y directorios web.', 'Brute-forces web paths and directories.'),
      fields: [
        { k: 'opt', id: 'url', flag: '', req: 1, ph: 'http://example.com', l: L('URL (obligatorio)', 'URL (required)') },
        { k: 'opt', id: 'wordlist', flag: '', ph: '/usr/share/wordlists/dirb/common.txt', l: L('Diccionario', 'Wordlist') },
        { k: 'opt', id: 'ext', flag: '-X', ph: '.php,.html', l: L('Extensiones (-X)', 'Extensions (-X)') },
        { k: 'flag', id: 'r', flag: '-r', l: L('No recursivo (-r)', 'Non-recursive (-r)') },
        { k: 'opt', id: 'out', flag: '-o', ph: 'dirb.txt', l: L('Salida (-o)', 'Output (-o)') }
      ],
      build: function (v) {
        var p = ['dirb'], inc = false;
        var url = v.v('url'); if (!url) { inc = true; url = '‹URL›'; }
        p.push(v.v('url') ? v.q(url) : url);
        if (v.v('wordlist')) p.push(v.q(v.v('wordlist')));
        if (v.v('ext')) p.push('-X ' + v.q(v.v('ext')));
        if (v.c('r')) p.push('-r');
        if (v.v('out')) p.push('-o ' + v.q(v.v('out')));
        return { cmd: p.join(' '), incomplete: inc };
      } },
    { id: 'nikto', cat: 'web', bin: 'nikto', name: 'Nikto', d: L('Escáner de vulnerabilidades y configuraciones web.', 'Web server vulnerability and misconfiguration scanner.'),
      fields: [
        { k: 'opt', id: 'host', flag: '-h', req: 1, ph: 'http://example.com', l: L('Host (obligatorio)', 'Host (required)') },
        { k: 'num', id: 'port', flag: '-p', ph: '443', l: L('Puerto (-p)', 'Port (-p)') },
        { k: 'flag', id: 'ssl', flag: '-ssl', l: L('Forzar SSL (-ssl)', 'Force SSL (-ssl)') },
        { k: 'opt', id: 'tuning', flag: '-Tuning', ph: '1,2,3', l: L('Tuning (-Tuning)', 'Tuning (-Tuning)') },
        { k: 'opt', id: 'out', flag: '-o', ph: 'nikto.html', l: L('Salida (-o)', 'Output (-o)') }
      ] },
    { id: 'sqlmap', cat: 'web', bin: 'sqlmap', name: 'sqlmap', d: L('Detecta y explota inyecciones SQL automáticamente.', 'Detects and exploits SQL injection automatically.'),
      fields: [
        { k: 'opt', id: 'url', flag: '-u', req: 1, ph: 'http://example.com/p.php?id=1', l: L('URL con parámetro (obligatorio)', 'URL with parameter (required)') },
        { k: 'opt', id: 'data', flag: '--data', ph: 'id=1&user=x', l: L('Datos POST (--data)', 'POST data (--data)') },
        { k: 'select', id: 'level', flag: '--level', raw: 1, l: L('Nivel', 'Level'), opts: [{ v: '', l: L('(1)', '(1)') }, { v: '1', l: '1' }, { v: '2', l: '2' }, { v: '3', l: '3' }, { v: '4', l: '4' }, { v: '5', l: '5' }] },
        { k: 'select', id: 'risk', flag: '--risk', raw: 1, l: L('Riesgo', 'Risk'), opts: [{ v: '', l: L('(1)', '(1)') }, { v: '1', l: '1' }, { v: '2', l: '2' }, { v: '3', l: '3' }] },
        { k: 'flag', id: 'batch', flag: '--batch', l: L('Sin preguntas (--batch)', 'No prompts (--batch)') },
        { k: 'head', l: L('Enumeración', 'Enumeration') },
        { k: 'flag', id: 'dbs', flag: '--dbs', l: L('Bases de datos (--dbs)', 'Databases (--dbs)') },
        { k: 'flag', id: 'tables', flag: '--tables', l: L('Tablas (--tables)', 'Tables (--tables)') },
        { k: 'flag', id: 'columns', flag: '--columns', l: L('Columnas (--columns)', 'Columns (--columns)') },
        { k: 'opt', id: 'D', flag: '-D', ph: 'usuarios_db', l: L('Base de datos (-D)', 'Database (-D)') },
        { k: 'opt', id: 'Tb', flag: '-T', ph: 'cuentas', l: L('Tabla (-T)', 'Table (-T)') },
        { k: 'opt', id: 'C', flag: '-C', ph: 'password', l: L('Columna (-C)', 'Column (-C)') },
        { k: 'flag', id: 'dump', flag: '--dump', l: L('Volcar lo seleccionado (--dump)', 'Dump the selection (--dump)') },
        { k: 'flag', id: 'dumpall', flag: '--dump-all', l: L('Volcar todo (--dump-all)', 'Dump everything (--dump-all)') }
      ] },
    { id: 'commix', cat: 'web', bin: 'commix', name: 'commix', d: L('Detecta y explota inyección de comandos.', 'Detects and exploits command injection.'),
      fields: [
        { k: 'opt', id: 'url', flag: '-u', req: 1, ph: 'http://example.com/p.php?x=1', l: L('URL (obligatorio)', 'URL (required)') },
        { k: 'opt', id: 'param', flag: '-p', ph: 'x', l: L('Parámetro (-p)', 'Parameter (-p)') },
        { k: 'opt', id: 'data', flag: '--data', ph: 'x=1', l: L('Datos POST (--data)', 'POST data (--data)') },
        { k: 'flag', id: 'shell', flag: '--os-cmd=id', l: L('Ejecutar «id» (--os-cmd=id)', 'Run “id” (--os-cmd=id)') }
      ] },
    { id: 'wpscan', cat: 'web', bin: 'wpscan', name: 'WPScan', d: L('Escáner de seguridad para WordPress.', 'WordPress security scanner.'),
      fields: [
        { k: 'opt', id: 'url', flag: '--url', req: 1, ph: 'https://example.com', l: L('URL (obligatorio)', 'URL (required)') },
        { k: 'select', id: 'enum', flag: '--enumerate', raw: 1, l: L('Enumerar', 'Enumerate'), opts: [{ v: '', l: L('(nada)', '(none)') }, { v: 'vp', l: L('vp: plugins vulnerables', 'vp: vulnerable plugins') }, { v: 'u', l: L('u: usuarios', 'u: users') }, { v: 'ap', l: L('ap: todos los plugins', 'ap: all plugins') }, { v: 'at', l: L('at: todos los temas', 'at: all themes') }] },
        { k: 'opt', id: 'token', flag: '--api-token', ph: 'TOKEN', l: L('Token de la API (--api-token)', 'API token (--api-token)') },
        { k: 'flag', id: 'force', flag: '--force', l: L('Forzar (--force)', 'Force (--force)') }
      ] },
    { id: 'wfuzz', cat: 'web', bin: 'wfuzz', name: 'Wfuzz', d: L('Fuzzing web sustituyendo FUZZ por cada palabra.', 'Web fuzzing, replacing FUZZ with each word.'),
      fields: [
        { k: 'opt', id: 'wordlist', flag: '-z file,', req: 1, glue: 1, ph: '/usr/share/wordlists/dirb/common.txt', l: L('Diccionario (obligatorio)', 'Wordlist (required)') },
        { k: 'opt', id: 'hc', flag: '--hc', ph: '404', l: L('Ocultar códigos (--hc)', 'Hide codes (--hc)') },
        { k: 'opt', id: 'hh', flag: '--hh', ph: '0', l: L('Ocultar por tamaño (--hh)', 'Hide by length (--hh)') },
        { k: 'num', id: 't', flag: '-t', ph: '20', l: L('Hilos (-t)', 'Threads (-t)') },
        { k: 'opt', id: 'url', flag: '', req: 1, ph: 'http://example.com/FUZZ', l: L('URL con FUZZ (obligatorio)', 'URL with FUZZ (required)') }
      ] },
    // ───────── Contraseñas ─────────
    { id: 'hydra', cat: 'pass', bin: 'hydra', name: 'Hydra', d: L('Fuerza bruta de credenciales en servicios de red.', 'Brute-forces credentials on network services.'),
      fields: [
        { k: 'opt', id: 'user', flag: '-l', ph: 'admin', l: L('Usuario (-l)', 'User (-l)') },
        { k: 'opt', id: 'userlist', flag: '-L', ph: 'users.txt', l: L('Lista de usuarios (-L)', 'User list (-L)') },
        { k: 'opt', id: 'pass', flag: '-p', ph: 'password', l: L('Contraseña (-p)', 'Password (-p)') },
        { k: 'opt', id: 'passlist', flag: '-P', ph: '/usr/share/wordlists/rockyou.txt', l: L('Lista de contraseñas (-P)', 'Password list (-P)') },
        { k: 'num', id: 't', flag: '-t', ph: '4', l: L('Tareas en paralelo (-t)', 'Parallel tasks (-t)') },
        { k: 'flag', id: 'V', flag: '-V', l: L('Verbose (-V)', 'Verbose (-V)') },
        { k: 'opt', id: 'target', flag: '', req: 1, ph: '192.168.1.10', l: L('Objetivo (obligatorio)', 'Target (required)') },
        { k: 'opt', id: 'service', flag: '', req: 1, ph: 'ssh', l: L('Servicio (obligatorio)', 'Service (required)') }
      ] },
    { id: 'medusa', cat: 'pass', bin: 'medusa', name: 'Medusa', d: L('Fuerza bruta de credenciales, paralela y modular.', 'Parallel, modular credential brute-forcer.'),
      fields: [
        { k: 'opt', id: 'host', flag: '-h', req: 1, ph: '192.168.1.10', l: L('Host (obligatorio)', 'Host (required)') },
        { k: 'opt', id: 'module', flag: '-M', req: 1, ph: 'ssh', l: L('Módulo (obligatorio)', 'Module (required)') },
        { k: 'opt', id: 'user', flag: '-u', ph: 'admin', l: L('Usuario (-u)', 'User (-u)') },
        { k: 'opt', id: 'userlist', flag: '-U', ph: 'users.txt', l: L('Lista de usuarios (-U)', 'User list (-U)') },
        { k: 'opt', id: 'pass', flag: '-p', ph: 'password', l: L('Contraseña (-p)', 'Password (-p)') },
        { k: 'opt', id: 'passlist', flag: '-P', ph: 'rockyou.txt', l: L('Lista de contraseñas (-P)', 'Password list (-P)') },
        { k: 'num', id: 't', flag: '-t', ph: '4', l: L('Hilos (-t)', 'Threads (-t)') }
      ] },
    { id: 'hashcat', cat: 'pass', bin: 'hashcat', name: 'Hashcat', d: L('Recuperación de contraseñas por GPU a partir de hashes.', 'GPU-based password recovery from hashes.'),
      fields: [
        { k: 'opt', id: 'm', flag: '-m', req: 1, ph: '0', l: L('Tipo de hash (-m, p. ej. 0=MD5, 1000=NTLM)', 'Hash type (-m, e.g. 0=MD5, 1000=NTLM)') },
        { k: 'select', id: 'a', flag: '-a', raw: 1, l: L('Modo de ataque', 'Attack mode'), opts: [{ v: '0', l: L('0 — diccionario', '0 — wordlist') }, { v: '3', l: L('3 — máscara (fuerza bruta)', '3 — mask (brute force)') }, { v: '6', l: L('6 — híbrido dicc.+máscara', '6 — hybrid wordlist+mask') }] },
        { k: 'opt', id: 'hashfile', flag: '', req: 1, ph: 'hashes.txt', l: L('Archivo de hashes (obligatorio)', 'Hash file (required)') },
        { k: 'opt', id: 'dict', flag: '', ph: '/usr/share/wordlists/rockyou.txt', l: L('Diccionario o máscara', 'Wordlist or mask') },
        { k: 'opt', id: 'rules', flag: '-r', ph: '/usr/share/hashcat/rules/best64.rule', l: L('Reglas (-r)', 'Rules (-r)') },
        { k: 'flag', id: 'show', flag: '--show', l: L('Mostrar ya crackeados (--show)', 'Show already cracked (--show)') }
      ],
      build: function (v) {
        var p = ['hashcat'], inc = false;
        var m = v.v('m'); if (!m) { inc = true; m = '‹m›'; }
        p.push('-m ' + m, '-a ' + (v.v('a') || '0'));
        var hf = v.v('hashfile'); if (!hf) { inc = true; hf = '‹hashes›'; }
        p.push(v.v('hashfile') ? v.q(hf) : hf);
        if (v.v('dict')) p.push(v.v('a') === '3' ? v.q(v.v('dict')) : v.q(v.v('dict')));
        if (v.v('rules')) p.push('-r ' + v.q(v.v('rules')));
        if (v.c('show')) p.push('--show');
        return { cmd: p.join(' '), incomplete: inc };
      } },
    { id: 'jtr', cat: 'pass', bin: 'john', name: 'John the Ripper', d: L('Cracker de contraseñas por CPU, muy versátil.', 'Versatile CPU password cracker.'),
      fields: [
        { k: 'opt', id: 'format', flag: '--format=', glue: 1, ph: 'raw-md5', l: L('Formato (--format=)', 'Format (--format=)') },
        { k: 'opt', id: 'wordlist', flag: '--wordlist=', glue: 1, ph: '/usr/share/wordlists/rockyou.txt', l: L('Diccionario (--wordlist=)', 'Wordlist (--wordlist=)') },
        { k: 'flag', id: 'rules', flag: '--rules', l: L('Aplicar reglas (--rules)', 'Apply rules (--rules)') },
        { k: 'flag', id: 'single', flag: '--single', l: L('Modo single (--single)', 'Single mode (--single)') },
        { k: 'flag', id: 'show', flag: '--show', l: L('Mostrar crackeados (--show)', 'Show cracked (--show)') },
        { k: 'opt', id: 'hashfile', flag: '', req: 1, ph: 'hashes.txt', l: L('Archivo de hashes (obligatorio)', 'Hash file (required)') }
      ] },
    { id: 'crunch', cat: 'pass', bin: 'crunch', name: 'crunch', d: L('Genera diccionarios por longitud y conjunto de caracteres.', 'Generates wordlists by length and character set.'),
      fields: [
        { k: 'num', id: 'min', flag: '', req: 1, raw: 1, ph: '8', l: L('Longitud mínima (obligatorio)', 'Min length (required)') },
        { k: 'num', id: 'max', flag: '', req: 1, raw: 1, ph: '8', l: L('Longitud máxima (obligatorio)', 'Max length (required)') },
        { k: 'opt', id: 'chars', flag: '', ph: 'abcde12345!@#', l: L('Conjunto de caracteres', 'Character set') },
        { k: 'opt', id: 'out', flag: '-o', ph: 'wordlist.txt', l: L('Guardar en (-o)', 'Save to (-o)') }
      ] },
    // ───────── WiFi ─────────
    { id: 'airmonng', cat: 'wifi', bin: 'airmon-ng', name: 'Airmon-ng', d: L('Activa el modo monitor en la tarjeta WiFi.', 'Enables monitor mode on the Wi-Fi card.'),
      fields: [
        { k: 'select', id: 'action', flag: '', raw: 1, l: L('Acción', 'Action'), opts: [{ v: 'start', l: L('start — activar', 'start') }, { v: 'stop', l: L('stop — desactivar', 'stop') }, { v: 'check kill', l: L('check kill — matar procesos que molestan', 'check kill') }] },
        { k: 'opt', id: 'iface', flag: '', req: 1, ph: 'wlan0', l: L('Interfaz (obligatorio)', 'Interface (required)') }
      ] },
    { id: 'airodumpng', cat: 'wifi', bin: 'airodump-ng', name: 'Airodump-ng', d: L('Captura tráfico y handshakes WiFi.', 'Captures Wi-Fi traffic and handshakes.'),
      fields: [
        { k: 'num', id: 'channel', flag: '-c', ph: '6', l: L('Canal (-c)', 'Channel (-c)') },
        { k: 'opt', id: 'bssid', flag: '--bssid', ph: 'AA:BB:CC:DD:EE:FF', l: L('BSSID (--bssid)', 'BSSID (--bssid)') },
        { k: 'opt', id: 'out', flag: '-w', ph: 'captura', l: L('Guardar en (-w)', 'Save to (-w)') },
        { k: 'opt', id: 'iface', flag: '', req: 1, ph: 'wlan0mon', l: L('Interfaz monitor (obligatorio)', 'Monitor interface (required)') }
      ] },
    { id: 'aireplayng', cat: 'wifi', bin: 'aireplay-ng', name: 'Aireplay-ng', d: L('Inyección de paquetes WiFi (p. ej. desautenticación).', 'Wi-Fi packet injection (e.g. deauthentication).'),
      fields: [
        { k: 'num', id: 'deauth', flag: '-0', ph: '5', l: L('Deauth, nº de paquetes (-0, 0=infinito)', 'Deauth, packet count (-0, 0=infinite)') },
        { k: 'opt', id: 'bssid', flag: '-a', req: 1, ph: 'AA:BB:CC:DD:EE:FF', l: L('BSSID del AP (-a, obligatorio)', 'AP BSSID (-a, required)') },
        { k: 'opt', id: 'client', flag: '-c', ph: '11:22:33:44:55:66', l: L('MAC del cliente (-c)', 'Client MAC (-c)') },
        { k: 'opt', id: 'iface', flag: '', req: 1, ph: 'wlan0mon', l: L('Interfaz monitor (obligatorio)', 'Monitor interface (required)') }
      ] },
    { id: 'aircrackng', cat: 'wifi', bin: 'aircrack-ng', name: 'Aircrack-ng', d: L('Crackea claves WEP/WPA de una captura.', 'Cracks WEP/WPA keys from a capture.'),
      fields: [
        { k: 'opt', id: 'wordlist', flag: '-w', ph: '/usr/share/wordlists/rockyou.txt', l: L('Diccionario (-w)', 'Wordlist (-w)') },
        { k: 'opt', id: 'bssid', flag: '-b', ph: 'AA:BB:CC:DD:EE:FF', l: L('BSSID (-b)', 'BSSID (-b)') },
        { k: 'opt', id: 'cap', flag: '', req: 1, ph: 'captura-01.cap', l: L('Archivo .cap (obligatorio)', '.cap file (required)') }
      ] },
    // ───────── Sniffing / MITM ─────────
    { id: 'tcpdump', cat: 'mitm', bin: 'tcpdump', name: 'tcpdump', d: L('Captura y analiza tráfico de red en la terminal.', 'Captures and analyses network traffic on the terminal.'),
      fields: [
        { k: 'opt', id: 'iface', flag: '-i', ph: 'eth0', l: L('Interfaz (-i)', 'Interface (-i)') },
        { k: 'num', id: 'count', flag: '-c', ph: '100', l: L('Nº de paquetes (-c)', 'Packet count (-c)') },
        { k: 'flag', id: 'nn', flag: '-nn', l: L('Sin resolver nombres ni puertos (-nn)', 'No name/port resolution (-nn)') },
        { k: 'flag', id: 'v', flag: '-v', l: L('Verbose (-v)', 'Verbose (-v)') },
        { k: 'opt', id: 'out', flag: '-w', ph: 'captura.pcap', l: L('Guardar en (-w)', 'Save to (-w)') },
        { k: 'opt', id: 'filter', flag: '', ph: 'tcp port 80', l: L('Filtro BPF', 'BPF filter') }
      ],
      build: function (v) {
        var p = ['tcpdump'];
        if (v.v('iface')) p.push('-i ' + v.q(v.v('iface')));
        if (v.v('count')) p.push('-c ' + (+v.v('count')));
        if (v.c('nn')) p.push('-nn');
        if (v.c('v')) p.push('-v');
        if (v.v('out')) p.push('-w ' + v.q(v.v('out')));
        if (v.v('filter')) p.push("'" + v.v('filter').replace(/'/g, "'\\''") + "'");
        return { cmd: p.join(' '), incomplete: false };
      } },
    { id: 'tshark', cat: 'mitm', bin: 'tshark', name: 'TShark', d: L('Wireshark en línea de comandos.', 'Wireshark on the command line.'),
      fields: [
        { k: 'opt', id: 'iface', flag: '-i', ph: 'eth0', l: L('Interfaz (-i)', 'Interface (-i)') },
        { k: 'num', id: 'count', flag: '-c', ph: '100', l: L('Nº de paquetes (-c)', 'Packet count (-c)') },
        { k: 'flag', id: 'V', flag: '-V', l: L('Detalle completo (-V)', 'Full detail (-V)') },
        { k: 'opt', id: 'out', flag: '-w', ph: 'captura.pcap', l: L('Guardar en (-w)', 'Save to (-w)') },
        { k: 'opt', id: 'filter', flag: '-f', ph: 'tcp port 80', l: L('Filtro de captura (-f)', 'Capture filter (-f)') }
      ] },
    { id: 'arpspoof', cat: 'mitm', bin: 'arpspoof', name: 'arpspoof', d: L('Envenenamiento ARP para situarte en medio (MITM).', 'ARP poisoning to get in the middle (MITM).'),
      fields: [
        { k: 'opt', id: 'iface', flag: '-i', req: 1, ph: 'eth0', l: L('Interfaz (-i, obligatorio)', 'Interface (-i, required)') },
        { k: 'opt', id: 'target', flag: '-t', req: 1, ph: '192.168.1.10', l: L('Víctima (-t, obligatorio)', 'Victim (-t, required)') },
        { k: 'opt', id: 'gateway', flag: '', req: 1, ph: '192.168.1.1', l: L('Puerta de enlace (obligatorio)', 'Gateway (required)') }
      ] },
    { id: 'ettercap', cat: 'mitm', bin: 'ettercap', name: 'Ettercap', d: L('Suite de ataques MITM.', 'MITM attack suite.'),
      fields: [
        { k: 'opt', id: 'iface', flag: '-i', req: 1, ph: 'eth0', l: L('Interfaz (-i, obligatorio)', 'Interface (-i, required)') },
        { k: 'opt', id: 't1', flag: '', ph: '192.168.1.10', l: L('Objetivo 1', 'Target 1') },
        { k: 'opt', id: 't2', flag: '', ph: '192.168.1.1', l: L('Objetivo 2 (gateway)', 'Target 2 (gateway)') }
      ],
      build: function (v) {
        var p = ['ettercap', '-T', '-q', '-i'], inc = false;
        var ifc = v.v('iface'); if (!ifc) { inc = true; ifc = '‹iface›'; }
        p.push(v.v('iface') ? v.q(ifc) : ifc, '-M', 'arp:remote');
        p.push('/' + (v.v('t1') || '') + '//', '/' + (v.v('t2') || '') + '//');
        return { cmd: p.join(' '), incomplete: inc };
      } },
    { id: 'dsniff', cat: 'mitm', bin: 'dsniff', name: 'dsniff', d: L('Captura credenciales en claro del tráfico de red.', 'Captures plaintext credentials from network traffic.'),
      fields: [{ k: 'opt', id: 'iface', flag: '-i', req: 1, ph: 'eth0', l: L('Interfaz (-i, obligatorio)', 'Interface (-i, required)') }] },
    // ───────── Explotación ─────────
    { id: 'msfconsole', cat: 'exploit', bin: 'msfconsole', name: 'Metasploit', d: L('Arranca Metasploit ejecutando un recurso de comandos.', 'Launches Metasploit running a resource of commands.'),
      fields: [
        { k: 'opt', id: 'module', flag: '', req: 1, ph: 'exploit/windows/smb/ms17_010_eternalblue', l: L('Módulo (obligatorio)', 'Module (required)') },
        { k: 'opt', id: 'rhost', flag: '', req: 1, ph: '192.168.1.10', l: L('RHOSTS (obligatorio)', 'RHOSTS (required)') },
        { k: 'opt', id: 'lhost', flag: '', ph: '192.168.1.5', l: L('LHOST', 'LHOST') },
        { k: 'num', id: 'lport', flag: '', ph: '4444', l: L('LPORT', 'LPORT') }
      ],
      build: function (v) {
        var x = [], inc = false;
        var mod = v.v('module'); if (!mod) { inc = true; mod = '‹módulo›'; }
        x.push('use ' + mod);
        var rh = v.v('rhost'); if (!rh) { inc = true; rh = '‹RHOSTS›'; }
        x.push('set RHOSTS ' + rh);
        if (v.v('lhost')) x.push('set LHOST ' + v.v('lhost'));
        if (v.v('lport')) x.push('set LPORT ' + (+v.v('lport')));
        x.push('run');
        return { cmd: 'msfconsole -q -x ' + v.q(x.join('; ') + ';'), incomplete: inc };
      } },
    { id: 'meterpreter', cat: 'exploit', bin: 'msfvenom', name: 'msfvenom (payload)', d: L('Genera un payload de Meterpreter con msfvenom.', 'Generates a Meterpreter payload with msfvenom.'),
      fields: [
        { k: 'select', id: 'payload', flag: '-p', raw: 1, l: L('Payload', 'Payload'), opts: [{ v: 'windows/x64/meterpreter/reverse_tcp', l: 'windows/x64 reverse_tcp' }, { v: 'linux/x64/meterpreter/reverse_tcp', l: 'linux/x64 reverse_tcp' }, { v: 'php/meterpreter/reverse_tcp', l: 'php reverse_tcp' }, { v: 'android/meterpreter/reverse_tcp', l: 'android reverse_tcp' }] },
        { k: 'opt', id: 'lhost', flag: 'LHOST=', glue: 1, req: 1, ph: '192.168.1.5', l: L('LHOST (obligatorio)', 'LHOST (required)') },
        { k: 'num', id: 'lport', flag: 'LPORT=', glue: 1, ph: '4444', l: L('LPORT', 'LPORT') },
        { k: 'select', id: 'format', flag: '-f', raw: 1, l: L('Formato', 'Format'), opts: [{ v: 'exe', l: 'exe' }, { v: 'elf', l: 'elf' }, { v: 'raw', l: 'raw' }, { v: 'apk', l: 'apk' }] },
        { k: 'opt', id: 'out', flag: '-o', ph: 'shell.exe', l: L('Guardar en (-o)', 'Save to (-o)') }
      ] },
    { id: 'searchsploit', cat: 'exploit', bin: 'searchsploit', name: 'SearchSploit', d: L('Busca exploits en la base de Exploit-DB.', 'Searches exploits in the Exploit-DB database.'),
      fields: [
        { k: 'flag', id: 'w', flag: '-w', l: L('Mostrar URLs (-w)', 'Show URLs (-w)') },
        { k: 'opt', id: 'keyword', flag: '', req: 1, ph: 'apache 2.4', l: L('Búsqueda (obligatorio)', 'Search (required)') }
      ] },
    { id: 'netcat', cat: 'exploit', bin: 'nc', name: 'Netcat', d: L('Navaja suiza de red: escucha, conexiones y shells.', 'Network Swiss army knife: listeners, connections and shells.'),
      fields: [
        { k: 'select', id: 'mode', l: L('Modo', 'Mode'), opts: [{ v: 'listen', l: L('Escuchar (-lvnp)', 'Listen (-lvnp)') }, { v: 'connect', l: L('Conectar', 'Connect') }] },
        { k: 'opt', id: 'host', flag: '', ph: '192.168.1.10', l: L('Host (al conectar)', 'Host (when connecting)') },
        { k: 'num', id: 'port', flag: '', req: 1, ph: '4444', l: L('Puerto (obligatorio)', 'Port (required)') },
        { k: 'flag', id: 'z', flag: '-z', l: L('Escaneo de puertos (-z)', 'Port scan (-z)') },
        { k: 'opt', id: 'exec', flag: '-e', ph: '/bin/bash', l: L('Ejecutar al conectar (-e)', 'Execute on connect (-e)') }
      ],
      build: function (v) {
        var p = ['nc'], inc = false;
        if (v.v('mode') === 'listen') {
          p.push('-lvnp');
          var port = v.v('port'); if (!port) { inc = true; port = '‹puerto›'; } p.push(port);
          if (v.v('exec')) p.push('-e ' + v.q(v.v('exec')));
        } else {
          p.push('-v'); if (v.c('z')) p.push('-z');
          if (v.v('exec')) p.push('-e ' + v.q(v.v('exec')));
          var host = v.v('host'); if (!host) { inc = true; host = '‹host›'; } p.push(v.v('host') ? v.q(host) : host);
          var port2 = v.v('port'); if (!port2) { inc = true; port2 = '‹puerto›'; } p.push(port2);
        }
        return { cmd: p.join(' '), incomplete: inc };
      } },
    { id: 'socat', cat: 'exploit', bin: 'socat', name: 'socat', d: L('Relé de datos; aquí, listener de shell inversa estable.', 'Data relay; here, a stable reverse-shell listener.'),
      fields: [{ k: 'num', id: 'port', flag: '', req: 1, ph: '4444', l: L('Puerto de escucha (obligatorio)', 'Listening port (required)') }],
      build: function (v) {
        var port = v.v('port'), inc = false;
        if (!port) { inc = true; port = '‹puerto›'; }
        return { cmd: 'socat file:`tty`,raw,echo=0 TCP-LISTEN:' + port + ',reuseaddr', incomplete: inc };
      } },
    // ───────── Reversing / forense ─────────
    { id: 'gdb', cat: 'rev', bin: 'gdb', name: 'GDB', d: L('Depurador: puntos de ruptura y ejecución paso a paso.', 'Debugger: breakpoints and step-by-step execution.'),
      fields: [
        { k: 'opt', id: 'file', flag: '', req: 1, ph: './binario', l: L('Ejecutable (obligatorio)', 'Executable (required)') },
        { k: 'opt', id: 'break', flag: '-ex b', ph: 'main', l: L('Punto de ruptura (break)', 'Breakpoint (break)') },
        { k: 'flag', id: 'run', flag: '-ex run', l: L('Ejecutar al abrir (run)', 'Run on open (run)') }
      ],
      build: function (v) {
        var p = ['gdb', '-q'], inc = false;
        var f = v.v('file'); if (!f) { inc = true; f = '‹binario›'; }
        p.push(v.v('file') ? v.q(f) : f);
        if (v.v('break')) p.push('-ex ' + v.q('b ' + v.v('break')));
        if (v.c('run')) p.push('-ex run');
        return { cmd: p.join(' '), incomplete: inc };
      } },
    { id: 'radare2', cat: 'rev', bin: 'r2', name: 'radare2', d: L('Framework de análisis y reversing de binarios.', 'Binary analysis and reversing framework.'),
      fields: [
        { k: 'flag', id: 'A', flag: '-A', l: L('Analizar al abrir (-A)', 'Analyse on open (-A)') },
        { k: 'flag', id: 'd', flag: '-d', l: L('Modo depuración (-d)', 'Debug mode (-d)') },
        { k: 'opt', id: 'cmd', flag: '-c', ph: 'aa;afl', l: L('Comandos r2 (-c)', 'r2 commands (-c)') },
        { k: 'opt', id: 'file', flag: '', req: 1, ph: './binario', l: L('Binario (obligatorio)', 'Binary (required)') }
      ] },
    { id: 'objdump', cat: 'rev', bin: 'objdump', name: 'objdump', d: L('Desensambla y muestra secciones de un binario.', 'Disassembles and shows sections of a binary.'),
      fields: [
        { k: 'flag', id: 'd', flag: '-d', l: L('Desensamblar (-d)', 'Disassemble (-d)') },
        { k: 'flag', id: 'h', flag: '-h', l: L('Cabeceras de sección (-h)', 'Section headers (-h)') },
        { k: 'flag', id: 't', flag: '-t', l: L('Tabla de símbolos (-t)', 'Symbol table (-t)') },
        { k: 'flag', id: 'C', flag: '-C', l: L('Demangle C++ (-C)', 'Demangle C++ (-C)') },
        { k: 'flag', id: 'M', flag: '-M intel', l: L('Sintaxis Intel (-M intel)', 'Intel syntax (-M intel)') },
        { k: 'opt', id: 'file', flag: '', req: 1, ph: './binario', l: L('Binario (obligatorio)', 'Binary (required)') }
      ] },
    { id: 'strings', cat: 'rev', bin: 'strings', name: 'strings', d: L('Extrae cadenas de texto legibles de un archivo.', 'Extracts readable text strings from a file.'),
      fields: [
        { k: 'num', id: 'n', flag: '-n', ph: '8', l: L('Longitud mínima (-n)', 'Min length (-n)') },
        { k: 'flag', id: 'a', flag: '-a', l: L('Todo el archivo (-a)', 'Whole file (-a)') },
        { k: 'opt', id: 'file', flag: '', req: 1, ph: './binario', l: L('Archivo (obligatorio)', 'File (required)') }
      ] },
    { id: 'strace', cat: 'rev', bin: 'strace', name: 'strace', d: L('Traza las llamadas al sistema de un programa.', 'Traces a program’s system calls.'),
      fields: [
        { k: 'opt', id: 'out', flag: '-o', ph: 'trace.log', l: L('Guardar en (-o)', 'Save to (-o)') },
        { k: 'flag', id: 't', flag: '-t', l: L('Marcar hora (-t)', 'Timestamp (-t)') },
        { k: 'opt', id: 'filter', flag: '-e trace=', glue: 1, ph: 'open,read,write', l: L('Filtrar llamadas (-e trace=)', 'Filter calls (-e trace=)') },
        { k: 'opt', id: 'cmd', flag: '', req: 1, ph: './programa', l: L('Programa (obligatorio)', 'Program (required)') }
      ] },
    { id: 'binwalk', cat: 'rev', bin: 'binwalk', name: 'binwalk', d: L('Analiza y extrae contenido embebido en firmware.', 'Analyses and extracts content embedded in firmware.'),
      fields: [
        { k: 'flag', id: 'e', flag: '-e', l: L('Extraer (-e)', 'Extract (-e)') },
        { k: 'flag', id: 'M', flag: '-M', l: L('Extracción recursiva (-M)', 'Recursive extraction (-M)') },
        { k: 'flag', id: 'E', flag: '-E', l: L('Análisis de entropía (-E)', 'Entropy analysis (-E)') },
        { k: 'opt', id: 'file', flag: '', req: 1, ph: 'firmware.bin', l: L('Archivo (obligatorio)', 'File (required)') }
      ] },
    { id: 'foremost', cat: 'rev', bin: 'foremost', name: 'foremost', d: L('Recupera archivos por sus firmas (data carving).', 'Recovers files by their signatures (data carving).'),
      fields: [
        { k: 'opt', id: 'input', flag: '-i', req: 1, ph: 'imagen.dd', l: L('Imagen de entrada (-i, obligatorio)', 'Input image (-i, required)') },
        { k: 'opt', id: 'out', flag: '-o', req: 1, ph: 'salida/', l: L('Carpeta de salida (-o, obligatorio)', 'Output folder (-o, required)') },
        { k: 'opt', id: 'types', flag: '-t', ph: 'jpg,pdf,zip', l: L('Tipos (-t)', 'Types (-t)') }
      ] },
    { id: 'volatility', cat: 'rev', bin: 'volatility', name: 'Volatility', d: L('Análisis forense de volcados de memoria RAM.', 'Forensic analysis of RAM memory dumps.'),
      fields: [
        { k: 'opt', id: 'dump', flag: '-f', req: 1, ph: 'memoria.raw', l: L('Volcado de memoria (-f, obligatorio)', 'Memory dump (-f, required)') },
        { k: 'opt', id: 'profile', flag: '--profile=', glue: 1, ph: 'Win7SP1x64', l: L('Perfil (--profile=)', 'Profile (--profile=)') },
        { k: 'select', id: 'plugin', flag: '', raw: 1, l: L('Plugin', 'Plugin'), opts: [{ v: 'imageinfo', l: L('imageinfo — detectar perfil', 'imageinfo — detect profile') }, { v: 'pslist', l: 'pslist' }, { v: 'pstree', l: 'pstree' }, { v: 'netscan', l: 'netscan' }, { v: 'hashdump', l: 'hashdump' }, { v: 'filescan', l: 'filescan' }, { v: 'cmdline', l: 'cmdline' }] }
      ] }
  ];

  var api = { CATS: CATS, TOOLS: T };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.PWN_TOOLS = api;
})(typeof window !== 'undefined' ? window : this);
