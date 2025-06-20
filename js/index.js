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
    const logInput = document.getElementById('log-input');
    logText = logInput.value.trim();

    const logTypeInput = document.getElementById('log-type');
    logType = logTypeInput.value;

    logEntries = [];
    servicesEntries = [];
    logHeader = [];
    cardHints = [];
    
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
        entry.severity = severityLevels[0]; // Default to lowest severity
        severityLevels.forEach(level => {
            if (entry.message.toLowerCase().includes(level)) {
                entry.severity = level;
            }

            if (entry.message.toLowerCase().includes('error') || entry.message.toLowerCase().includes('fail')) {
                if( entry.severity === 'low') {
                    entry.severity = 'medium';
                }
            }

            if (entry.message.toLowerCase().includes('root')) {
                if (entry.severity === 'low') {
                    entry.severity = 'medium';
                }
            }

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
    });

    scanServices();
}

function scanServices() {
    // Scan the log entries for services and their event counts
    const serviceCounts = {};
    const mediumServiceCounts = {};
    const highServiceCounts = {};
    const criticalServiceCounts = {};

    logEntries.forEach(entry => {
        const service = entry.service.toLowerCase();
        if (!serviceCounts[service]) {
            serviceCounts[service] = 0;
            mediumServiceCounts[service] = 0;
            highServiceCounts[service] = 0;
            criticalServiceCounts[service] = 0;
        }
        serviceCounts[service]++;
        if (entry.severity === 'medium') {
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
        loggedEvents: serviceCounts[service],
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
        <th>Logged Events</th>
        <th>Medium Severity</th>
        <th>High Severity</th>
        <th>Critical Severity</th>
    `;

    servicesTableBody.innerHTML = '';
    servicesEntries.forEach(entry => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td onclick="showSearchResults({ service: '${entry.service}'})">${entry.service}</td>
            <td onclick="showSearchResults({ service: '${entry.service}'})">${entry.loggedEvents}</td>
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
        <td><b>${logEntries.length}</b></td>
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

    // query_obj: Key value pair of search key (e.g. service, severity) and value (e.g. sshd, high)
    const queryKeys = Object.keys(query_obj);
    const queryValues = queryKeys.map(key => query_obj[key].toLowerCase());

    // Filter log entries based on the query
    const filteredEntries = logEntries.filter(entry => {
        return queryKeys.every((key, index) => {
            return entry[key].toLowerCase().includes(queryValues[index]);
        });
    });

    const searchResultsHeader = document.getElementById('search-header');
    searchResultsHeader.innerHTML = logTableHeader.innerHTML; // Copy the log table header

    // Update the search results table
    const searchResultsBody = document.getElementById('search-results');
    searchResultsBody.innerHTML = logTableBody.innerHTML; // Copy Log Data

    // Remove non matching rows only by using the table header and row data
    // Build an array of header names (lowercased) to find the right column index
    const headerCells = searchResultsHeader.querySelectorAll('th');
    const headers = Array.from(headerCells).map(th => th.innerText.toLowerCase());
    const columnIndices = queryKeys.map(key => headers.indexOf(key));

    if (columnIndices.includes(-1)) {
        console.warn(`Header for query keys "${queryKeys}" not found.`);
    } else {
        // Filter rows based on the cell in the matched column
        const rows = searchResultsBody.querySelectorAll('tr');
        rows.forEach(row => {
            const cells = row.querySelectorAll('td');
            const isVisible = columnIndices.every((colIndex, i) => {
                const cell = cells[colIndex];
                return cell && cell.innerText.toLowerCase().includes(queryValues[i]);
            });
            if (!isVisible) {
                row.remove();
            }
        });
    }

    searchListModal.show();
}