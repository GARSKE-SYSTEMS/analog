let logText;
let logType;

const searchListModal = bootstrap.Modal.getOrCreateInstance(document.getElementById('searchListModal'));

const logTableHeader = document.getElementById('log-header');
const logTableBody = document.getElementById('log-events');
const logStats = document.getElementById('log-stats');
const servicesTableHeader = document.getElementById('services-header');
const servicesTableBody = document.getElementById('services-events');

var logHeader = [];
var logEntries = [];
var servicesEntries = [];
var cardHints = []; // To be used by the log parser to provide hints for notable statistics

function submitLog() {
    const logTypeInput = document.getElementById('log-type');
    logType = logTypeInput.value;

    logEntries = [];
    servicesEntries = [];
    logHeader = [];
    cardHints = [];

    const logInput = document.getElementById('log-input');
    logText = logInput.value.trim();

    const logFileInput = document.getElementById('log-file');
    if (logFileInput.files.length > 0) {
        const file = logFileInput.files[0];
        const reader = new FileReader();
        reader.onload = function(event) {
            logText = event.target.result.trim();
            processLog();
        };
        reader.readAsText(file);
        return;
    } else if(logText.length === 0) {
        alert('Please provide a log file or paste log text.');
    }
    processLog();
}

function processLog() {
    switch(logType) {
        case 'auth.log':
            processAuthLog();
            break;
        case 'syslog':
            processSyslog();
            break;
        case 'apache_access':
            processApacheAccessLog();
            break;
        default:
            alert('Unsupported log type.');
    }
}



function processAuthLog() {
    // Sample Line: 2025-06-20T12:59:25.000001+02:00 XXXXXXXXX sshd[XXXXX]: Accepted publickey for XXXXXXXX from XXX.XXX.XXX.XXX port XXXX ssh2: RSA SHA256:XXXXXXXXXXXXXXXXXXXXXXXXXX
    const logLines = logText.split('\n');
    
    logHeader = ['Timestamp', 'Hostname', 'Service', 'Message'];
    
    logLines.forEach(line => {
        const parts = line.split(' ');
        if (parts.length < 3) return; // Skip malformed lines

        timestamp = parts[0];
        hostname = parts[1];
        service = parts[2];
        message = parts.slice(3).join(' ');

        service = service.replace(/\[\d*\]/g, ''); // Remove brackets if present
        service = service.replace(/:/g, ''); // Remove colon if present

        logEntries.push({
            timestamp: timestamp,
            hostname: hostname,
            service: service,
            message: message
        });
    });

    // Create notable statistics
    cardHints.push({ //Unique Services
        title: 'Unique Services',
        value: [...new Set(logEntries.map(entry => entry.service))].length,
    });

    // Failed SSH Login Attempts
    const failedSSHLogins = logEntries.filter(entry => entry.service.toLowerCase() === 'sshd' && (entry.message.toLowerCase().includes('failed') || entry.message.toLowerCase().includes('invalid')));
    cardHints.push({
        title: 'Failed SSH Login Attempts',
        value: failedSSHLogins.length,
    });

    // Successful SSH Login Attempts
    const successfulSSHLogins = logEntries.filter(entry => entry.service.toLowerCase() === 'sshd' && entry.message.toLowerCase().includes('accepted'));
    cardHints.push({
        title: 'Successful SSH Login Attempts',
        value: successfulSSHLogins.length,
    });

    // CRON Job User Session Events
    const cronAuthEvents = logEntries.filter(entry => entry.service.toLowerCase() === 'cron' && entry.message.toLowerCase().includes('session'));
    cardHints.push({
        title: 'CRON Job User Session Events',
        value: cronAuthEvents.length,
    });
    

    scanSeverity();
}

function scanSeverity(){
    // Scan the log entries for severity levels
    const severityLevels = ['low', 'medium', 'high', 'critical'];

    logHeader.push('Severity');

    logEntries.forEach(entry => {

        if(!entry.service) {
            switch(logType) {
                case "apache_access":
                    entry.service = 'Apache2'; // Default service for apache access logs
                    break;
                default:
                    entry.service = 'unknown'; // Default service if not provided
                    break;
            }
        }

        if(!entry.message) {
            switch(logType) {
                case "apache_access":
                    entry.message = `HTTP ${entry.status} response from ${entry.ip} for ${entry.method} ${entry.path}`;
                    if (!entry.method) {
                        entry.method = 'GET'; // Default method if not provided
                    }
                    if (!entry.path) {
                        entry.path = '/'; // Default path if not provided
                    }
                    break;
                default:
                    entry.message = "No message provided";
            }
        }


        entry.severity = severityLevels[0]; // Default to lowest severity
        if (entry.message.toLowerCase().includes("critical")) {
            entry.severity = 'critical';
        }
        if (entry.message.toLowerCase().includes('error') || entry.message.toLowerCase().includes('fail')) {
            if( entry.severity === 'low') {
                entry.severity = 'high';
            }
        }

        switch(logType) {
            case "auth.log":
                // Special cases for auth.log
                if (entry.message.toLowerCase().includes('root')) {
                    key = severityLevels.lastIndexOf(entry.severity);
                    entry.severity = severityLevels[key + 1] || entry.severity;
                }
                break;
            case "syslog":
                // Common syslog severity keywords
                const msg = entry.message.toLowerCase();
                if (msg.includes('emerg') || msg.includes('panic') || msg.includes('alert') || msg.includes('crit')) {
                    entry.severity = 'critical';
                } else if (msg.includes('warn') || msg.includes('warning')) {
                    entry.severity = 'medium';
                } else if (msg.includes('notice')) {
                    entry.severity = 'low';
                } else if (msg.includes('info')) {
                    entry.severity = 'low';
                }
                break;
            case "apache_access":
                // Use HTTP status for severity
                if (entry.status >= 500) {
                    entry.severity = 'critical';
                } else if (entry.status >= 400) {
                    entry.severity = 'high';
                } else if (entry.method && entry.method.toUpperCase() === 'POST') {
                    entry.severity = 'medium';
                } else {
                    entry.severity = 'low';
                }
                break;
        }


        // Special cases for specific services
        if (entry.service.toLowerCase() == "systemd-logind") {
            // Special case for systemd-logind service
            
            // New Login Session
            if (entry.message.toLowerCase().includes("New session")) {
                entry.severity = 'high';
            }
        }
        if(entry.service.toLowerCase() == "sshd") {
            // Special case for sshd service
            if (entry.message.toLowerCase().includes("failed password")) {
                entry.severity = 'medium';
            }
            if (entry.message.toLowerCase().includes("accepted publickey")) {
                entry.severity = 'high';
            }
        }
    });

    scanServices();
}

function scanServices() {
    // Scan the log entries for services and their event counts
    const serviceCounts = {};
    const lowServiceCounts = {};
    const mediumServiceCounts = {};
    const highServiceCounts = {};
    const criticalServiceCounts = {};

    logEntries.forEach(entry => {
        const service = entry.service.toLowerCase();
        if (!serviceCounts[service]) {
            serviceCounts[service] = 0;
            lowServiceCounts[service] = 0;
            mediumServiceCounts[service] = 0;
            highServiceCounts[service] = 0;
            criticalServiceCounts[service] = 0;
        }
        serviceCounts[service]++;
        if (entry.severity === 'low') {
            lowServiceCounts[service]++;
        } else if (entry.severity === 'medium') {
            mediumServiceCounts[service]++;
        } else if (entry.severity === 'high') {
            highServiceCounts[service]++;
        } else if (entry.severity === 'critical') {
            criticalServiceCounts[service]++;
        }
    });
    console.log('Service Counts:', serviceCounts);
    console.log('Critical Service Counts:', criticalServiceCounts);
    servicesEntries = Object.keys(serviceCounts).map(service => ({
        service: service,
        loggedLowEvents: lowServiceCounts[service],
        loggedMediumEvents: mediumServiceCounts[service],
        loggedHighEvents: highServiceCounts[service],
        loggedCriticalEvents: criticalServiceCounts[service]
    }));
    console.log('Services Entries:', servicesEntries);
    output();
}

function output() {
    logTableHeader.innerHTML = '';
    logHeader.forEach(header => {
        const th = document.createElement('th');
        th.innerText = header;
        logTableHeader.appendChild(th);
    });

    logTableBody.innerHTML = '';
    logEntries.forEach(entry => {
        const tr = document.createElement('tr');
        for (const key of logHeader) {
            const td = document.createElement('td');
            td.innerText = entry[key.toLowerCase()];
            tr.appendChild(td);
        }
        logTableBody.appendChild(tr);
    });

    servicesTableHeader.innerHTML = '';
    servicesTableHeader.innerHTML = `
        <th>Service</th>
        <th>Low Severity</th>
        <th>Medium Severity</th>
        <th>High Severity</th>
        <th>Critical Severity</th>
    `;

    servicesTableBody.innerHTML = '';
    servicesEntries.forEach(entry => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td onclick="showSearchResults({ service: '${entry.service}'})">${entry.service}</td>
            <td onclick="showSearchResults({ service: '${entry.service}', severity: 'low' })">${entry.loggedLowEvents}</td>
            <td onclick="showSearchResults({ service: '${entry.service}', severity: 'medium' })">${entry.loggedMediumEvents}</td>
            <td onclick="showSearchResults({ service: '${entry.service}', severity: 'high' })">${entry.loggedHighEvents}</td>
            <td onclick="showSearchResults({ service: '${entry.service}', severity: 'critical' })">${entry.loggedCriticalEvents}</td>
        `;
        servicesTableBody.appendChild(tr);
    });

    const totalRow = document.createElement('tr');
    totalRow.classList.add('table-secondary');
    totalRow.innerHTML = `
        <td><b>Total</b></td>
        <td onclick="showSearchResults({ severity: 'low' })"><b>${servicesEntries.reduce((sum, entry) => sum + entry.loggedLowEvents, 0)}</b></td>
        <td onclick="showSearchResults({ severity: 'medium' })"><b>${servicesEntries.reduce((sum, entry) => sum + entry.loggedMediumEvents, 0)}</b></td>
        <td onclick="showSearchResults({ severity: 'high' })"><b>${servicesEntries.reduce((sum, entry) => sum + entry.loggedHighEvents, 0)}</b></td>
        <td onclick="showSearchResults({ severity: 'critical' })"><b>${servicesEntries.reduce((sum, entry) => sum + entry.loggedCriticalEvents, 0)}</b></td>
    `;
    servicesTableBody.appendChild(totalRow);

    

    // Card Hints
    logStats.innerHTML = '';
    cardHints.forEach(hint => {
        const card = document.createElement('div');
        card.classList.add('col');
        card.innerHTML = `
            <div class="card card-body h-100">
                <h5 class="card-title">${hint.value}</h5>
                <p class="card-text">${hint.title}</p>
            </div>
        `;
        logStats.appendChild(card);
    });
}

function showSearchResults(query_obj) {

    // Build query arrays
    const queryKeys   = Object.keys(query_obj);
    const queryValues = queryKeys.map(k => query_obj[k].toLowerCase());

    // Copy header
    const searchResultsHeader = document.getElementById('search-header');
    searchResultsHeader.innerHTML = logTableHeader.innerHTML;

    // Clear previous results
    const searchResultsBody = document.getElementById('search-results');
    searchResultsBody.innerHTML = '';

    // Map header text to column indices
    const headerCells   = logTableHeader.querySelectorAll('th');
    const headers       = Array.from(headerCells).map(th => th.innerText.toLowerCase());
    const columnIndices = queryKeys.map(k => headers.indexOf(k));

    if (columnIndices.includes(-1)) {
        console.warn(`Missing columns for keys: ${queryKeys}`);
    }

    // Iterate original rows and copy matching ones
    const originalRows = logTableBody.querySelectorAll('tr');
    originalRows.forEach(row => {
        const cells = row.querySelectorAll('td');
        const matches = columnIndices.every((col, i) => {
            const text = cells[col]?.innerText.toLowerCase() || '';
            return text.includes(queryValues[i]);
        });
        if (matches) {
            searchResultsBody.appendChild(row.cloneNode(true));
        }
    });

    searchListModal.show();
}

function inputSearchBar() {
    const searchInput = document.getElementById('search-input');
    const searchQuery = searchInput.value.toLowerCase().trim();    

    queryObj = {};

    // Parse search query to queryObj (searchparm1=value1&searchparm2=value2)
    searchQuery.split('&').forEach(param => {
        if(param.includes('=')) {        
            const [key, value] = param.split('=');
            if (key && value) {
                queryObj[key.trim()] = value.trim();
            }
        }else {
            queryObj['message'] = param.trim(); // If no key is provided, assume it's a message search
        }
    });

    showSearchResults(queryObj);
    
}

function processSyslog() {
    // Sample Line: Jun 20 12:34:56 hostname service[pid]: message
    const logLines = logText.split('\n');
    logHeader = ['Timestamp', 'Hostname', 'Service', 'Message'];

    logLines.forEach(line => {
        const parts = line.split(' ');
        if (parts.length < 2) return; // Skip malformed lines

        const timestamp = parts[0];
        const hostname = parts[1];
        let service = parts[2].replace(/\[\d*\]/g, '').replace(/:/g, '');
        const message = parts.slice(3).join(' ');

        logEntries.push({ timestamp, hostname, service, message });
    });

    // Create notable statistics
    cardHints.push({
        title: 'Unique Services',
        value: [...new Set(logEntries.map(entry => entry.service))].length,
    });
    const errorEvents = logEntries.filter(entry => entry.message.toLowerCase().includes('error'));
    cardHints.push({ title: 'Error Events', value: errorEvents.length });
    const warningEvents = logEntries.filter(entry => entry.message.toLowerCase().includes('warn'));
    cardHints.push({ title: 'Warning Events', value: warningEvents.length });
    const infoEvents = logEntries.filter(entry => entry.message.toLowerCase().includes('info'));
    cardHints.push({ title: 'Info Events', value: infoEvents.length });

    scanSeverity();
}

function processApacheAccessLog() {
    const logLines = logText.split('\n');
    logEntries = [];

    logLines.forEach(line => {
        const tokens = line.match(/"[^"]*"|\[[^\]]*\]|\S+/g) || [];
        let entry = {};
        let quotedCount = 0;
        let remaining = [];
        tokens.forEach(token => {
            if (token.startsWith('[') && token.endsWith(']')) {
                entry.timestamp = token.slice(1, -1);
            } else if (token.startsWith('"') && token.endsWith('"')) {
                const content = token.slice(1, -1);
                if (quotedCount === 0) {
                    // request field
                    const [method, path, protocol] = content.split(' ');
                    entry.method = method;
                    entry.path = path;
                    entry.protocol = protocol;
                } else if (quotedCount === 1) {
                    entry.referrer = content !== '-' ? content : undefined;
                } else if (quotedCount === 2) {
                    entry.agent = content !== '-' ? content : undefined;
                }
                quotedCount++;
            } else if (/^\d{3}$/.test(token)) {
                entry.status = parseInt(token);
            } else if (/^\d+$/.test(token) || token === '-') {
                entry.bytes = token !== '-' ? token : undefined;
            } else {
                remaining.push(token);
            }
        });
        // assign IP and user from remaining tokens
        const ipRegex = /^(?:\d{1,3}\.){3}\d{1,3}$|^(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/;
        remaining.forEach(val => {
            if (!entry.ip && ipRegex.test(val)) {
                entry.ip = val;
            } else if (!entry.user) {
                entry.user = val !== '-' ? val : undefined;
            }
        });
        logEntries.push(entry);
    });

    // Build dynamic header
    const allKeys = new Set(logEntries.flatMap(e => Object.keys(e)));
    const order = ['ip','user','timestamp','method','path','protocol','status','bytes','referrer','agent'];
    logHeader = order.filter(k => allKeys.has(k)).map(k => ({
        ip:'IP', user:'User', timestamp:'Timestamp', method:'Method', path:'Path', protocol:'Protocol', status:'Status', bytes:'Bytes', referrer:'Referrer', agent:'Agent'
    }[k]));
    logHeader.push('Service'); // Add service column

    // Notable statistics
    cardHints.push({ title: 'Total Requests', value: logEntries.length });
    const clientErrors = logEntries.filter(e => e.status >= 400 && e.status < 500).length;
    const serverErrors = logEntries.filter(e => e.status >= 500).length;
    const uniqueIPs = new Set(logEntries.map(e => e.ip)).size;
    const pathsCount = {};
    logEntries.forEach(e => { if(e.path) pathsCount[e.path] = (pathsCount[e.path] || 0) + 1; });
    const topPaths = Object.entries(pathsCount).sort((a,b)=>b[1]-a[1]).slice(0,3).map(p=>p[0]).join(', ');
    cardHints.push({ title: 'Client Errors (4xx)', value: clientErrors });
    cardHints.push({ title: 'Server Errors (5xx)', value: serverErrors });
    cardHints.push({ title: 'Unique IPs', value: uniqueIPs });
    cardHints.push({ title: 'Top Paths', value: topPaths });

    scanSeverity();
}