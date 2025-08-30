// tools/nmap.js
const nmapModule = {
    html: `
        <h2>Nmap - Generador de Comandos por Secciones</h2>
        <p>Selecciona opciones por categoría para construir tu comando.</p>

        <label for="ipTarget">IP / Rango (obligatorio):</label>
        <input type="text" id="ipTarget" placeholder="192.168.1.1 o 192.168.1.0/24">

        <label for="ports">Puertos:</label>
        <input type="text" id="ports" placeholder="80,443,22-100">

        <!-- 1️⃣ Networking / Descubrimiento -->
        <h3>1️⃣ Networking / Descubrimiento</h3>
        <label><input type="checkbox" id="pingScan"> Ping Scan (-sn)</label><br>
        <label><input type="checkbox" id="skipPing"> Skip Ping (-Pn)</label><br>
        <label><input type="checkbox" id="fastScan"> Escaneo rápido (-F)</label><br>
        <label><input type="checkbox" id="allPorts"> Todos los puertos (-p-)</label><br>

        <!-- 2️⃣ Escaneos comunes -->
        <h3>2️⃣ Escaneos comunes</h3>
        <label><input type="checkbox" id="synScan"> SYN Scan (-sS)</label><br>
        <label><input type="checkbox" id="udpScan"> UDP Scan (-sU)</label><br>
        <label><input type="checkbox" id="versionDetection"> Detección de versión (-sV)</label><br>
        <label><input type="checkbox" id="osDetection"> Detección de SO (-O)</label><br>
        <label><input type="checkbox" id="aggressiveScan"> Escaneo agresivo (-A)</label><br>
        <label><input type="checkbox" id="defaultScripts"> Scripts por defecto (-sC)</label><br>
        <label><input type="checkbox" id="verboseOutput"> Verbose (-v)</label><br>

        <!-- 3️⃣ Enumeración por servicio -->
        <h3>3️⃣ Enumeración por servicio</h3>
        <label><input type="checkbox" id="smbEnum"> SMB Enum (-p 445 --script smb-*)</label><br>
        <label><input type="checkbox" id="ftpAnon"> FTP Anon (-p 21 --script ftp-anon)</label><br>
        <label><input type="checkbox" id="sshEnum"> SSH Enum (-p 22 --script ssh-*)</label><br>
        <label><input type="checkbox" id="httpEnum"> HTTP Enum (-p 80 --script http-*)</label><br>
        <label><input type="checkbox" id="mysqlEnum"> MySQL Enum (-p 3306 --script mysql-*)</label><br>
        <label><input type="checkbox" id="mssqlEnum"> MSSQL Enum (-p 1433 --script ms-sql-*)</label><br>

        <!-- 4️⃣ Vulnerabilidades -->
        <h3>4️⃣ Evaluación de vulnerabilidades</h3>
        <label><input type="checkbox" id="heartbleed"> Heartbleed (--script ssl-heartbleed)</label><br>
        <label><input type="checkbox" id="eternalblue"> EternalBlue (--script smb-vuln-ms17-010)</label><br>
        <label><input type="checkbox" id="log4j"> Log4j (--script log4shell.nse)</label><br>
        <label><input type="checkbox" id="shellshock"> Shellshock (--script http-shellshock)</label><br>

        <!-- 5️⃣ Salida -->
        <h3>5️⃣ Salida y formatos</h3>
        <label><input type="checkbox" id="outNormal"> Salida normal (-oN)</label><br>
        <label><input type="checkbox" id="outXML"> Salida XML (-oX)</label><br>
        <label><input type="checkbox" id="outGrep"> Salida Grepable (-oG)</label><br>
        <label><input type="checkbox" id="outAll"> Salida en todos los formatos (-oA)</label><br>

        <label for="outputFile">Archivo de salida (sin extensión para -oA):</label>
        <input type="text" id="outputFile" placeholder="resultados">

        <label for="script">Scripts NSE adicionales:</label>
        <input type="text" id="script" placeholder="http-enum,vulners">

        <button onclick="nmapModule.generateCommand()">Generar Comando</button>

        <div class="command-box">
            <h4>Comando generado:</h4>
            <p id="outputCommand">nmap</p>
        </div>
    `,
    generateCommand: () => {
        const getVal = id => document.getElementById(id)?.value.trim();
        const getChk = id => document.getElementById(id)?.checked;

        const ipTarget = getVal('ipTarget');
        if (!ipTarget) {
            alert("La dirección IP o rango es obligatoria.");
            return;
        }

        let cmd = "nmap";

        // Networking
        if (getChk('pingScan')) cmd += " -sn";
        if (getChk('skipPing')) cmd += " -Pn";
        if (getChk('fastScan')) cmd += " -F";
        if (getChk('allPorts')) cmd += " -p-";

        // Escaneos comunes
        if (getChk('synScan')) cmd += " -sS";
        if (getChk('udpScan')) cmd += " -sU";
        if (getChk('versionDetection')) cmd += " -sV";
        if (getChk('osDetection')) cmd += " -O";
        if (getChk('aggressiveScan')) cmd += " -A";
        if (getChk('defaultScripts')) cmd += " -sC";
        if (getChk('verboseOutput')) cmd += " -v";

        // Enumeración
        if (getChk('smbEnum')) cmd += " -p 445 --script smb-*";
        if (getChk('ftpAnon')) cmd += " -p 21 --script ftp-anon";
        if (getChk('sshEnum')) cmd += " -p 22 --script ssh-*";
        if (getChk('httpEnum')) cmd += " -p 80 --script http-*";
        if (getChk('mysqlEnum')) cmd += " -p 3306 --script mysql-*";
        if (getChk('mssqlEnum')) cmd += " -p 1433 --script ms-sql-*";

        // Vulnerabilidades
        if (getChk('heartbleed')) cmd += " --script ssl-heartbleed";
        if (getChk('eternalblue')) cmd += " --script smb-vuln-ms17-010";
        if (getChk('log4j')) cmd += " --script log4shell.nse";
        if (getChk('shellshock')) cmd += " --script http-shellshock";

        // Salida
        const outputFile = getVal('outputFile');
        if (getChk('outNormal') && outputFile) cmd += ` -oN ${outputFile}.txt`;
        if (getChk('outXML') && outputFile) cmd += ` -oX ${outputFile}.xml`;
        if (getChk('outGrep') && outputFile) cmd += ` -oG ${outputFile}.grep`;
        if (getChk('outAll') && outputFile) cmd += ` -oA ${outputFile}`;

        // Scripts adicionales
        const scriptExtra = getVal('script');
        if (scriptExtra) cmd += ` --script ${scriptExtra}`;

        // Puertos manuales
        const ports = getVal('ports');
        if (ports) cmd += ` -p ${ports}`;

        cmd += ` ${ipTarget}`;

        document.getElementById('outputCommand').textContent = cmd;
    }
};

toolForms.nmap = nmapModule;
