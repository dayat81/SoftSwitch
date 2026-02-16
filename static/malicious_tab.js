// Malicious Traffic Tab Functions
let maliciousIPs = new Set();

function detectMaliciousPatterns(flow) {
    // Check for known malicious patterns
    const maliciousPatterns = [
        /(%27)|(\')|(\-\-)|(%23)|(#)/i,  // SQL Injection
        /((%3C)|<)[^\n]+((%3E)|>)/i,      // XSS
        /\.\.[\\/]/i,                      // Path Traversal
        /\;.*cat.*\/etc\/passwd/i,         // Command Injection
        /php:\/\/filter/i,                 // LFI
        /<!ENTITY.*SYSTEM/i,               // XXE
        /admin.*pass.*test[0-9]+/i,        // Brute force
    ];
    return false;
}

function fetchMaliciousStats() {
    fetch('/api/stats')
        .then(res => res.json())
        .then(data => renderMaliciousTable(data))
        .catch(e => console.error("Fetch error:", e));
}

function renderMaliciousTable(data) {
    const body = document.getElementById('malicious-stats-body');
    if (!body) return;
    
    body.innerHTML = '';
    let maliciousCount = 0;
    
    fetch('/api/blacklist')
        .then(res => res.json())
        .then(blacklistData => {
            const customServices = blacklistData.custom_services || {};
            
            data.forEach(service => {
                if (service.details) {
                    service.details.forEach(flow => {
                        const srcService = customServices[flow.src] || '';
                        const dstService = customServices[flow.dst] || '';
                        const isMalicious = srcService.includes('Malicious') || 
                                          dstService.includes('Malicious') ||
                                          srcService.includes('🚨') ||
                                          dstService.includes('🚨');
                        
                        if (isMalicious) {
                            maliciousCount++;
                            const tr = document.createElement('tr');
                            tr.style.background = 'rgba(239, 68, 68, 0.1)';
                            tr.style.borderLeft = '3px solid #ef4444';
                            tr.innerHTML = `
                                <td><span class="badge badge-block">🚨 MALICIOUS</span></td>
                                <td>
                                    <div class="mono">${flow.src}</div>
                                    <div class="host">${srcService || service.service}</div>
                                </td>
                                <td class="mono">${flow.dst}</td>
                                <td>${flow.proto}</td>
                                <td style="text-align: right; color: #ef4444; font-weight: 600;">${flow.pps || 0}</td>
                                <td style="text-align: right; color: #ef4444; font-weight: 600;">${flow.bps || 0}</td>
                                <td style="text-align: right; font-weight: 800;">${flow.pkts ? flow.pkts.toLocaleString() : 0}</td>
                                <td style="text-align: right; color: #60a5fa;">${formatBytes(flow.bytes)}</td>
                                <td style="text-align: center;">
                                    <button onclick="quickAction('block', '${flow.src}')" 
                                            class="btn-block" style="padding: 5px 12px; font-size: 0.7rem;">
                                        BLOCK
                                    </button>
                                </td>
                            `;
                            body.appendChild(tr);
                        }
                    });
                }
            });
            
            const countBadge = document.getElementById('malicious-count');
            if (countBadge) {
                countBadge.innerText = `${maliciousCount} Threats`;
                countBadge.style.display = maliciousCount > 0 ? 'inline-block' : 'none';
            }
            
            if (maliciousCount === 0) {
                body.innerHTML = `
                    <tr>
                        <td colspan="9" style="text-align: center; padding: 40px; color: #94a3b8;">
                            <div style="font-size: 3rem; margin-bottom: 10px;">✅</div>
                            <div>No malicious traffic detected</div>
                            <div style="font-size: 0.8rem; margin-top: 10px;">Monitor is actively watching for threats...</div>
                        </td>
                    </tr>
                `;
            }
        });
}

function switchDashboardTab(tab) {
    document.getElementById('main-dashboard').style.display = 'none';
    document.getElementById('malicious-dashboard').style.display = 'none';
    
    document.getElementById('tab-main').classList.remove('active');
    document.getElementById('tab-malicious').classList.remove('active');
    
    if (tab === 'main') {
        document.getElementById('main-dashboard').style.display = 'block';
        document.getElementById('tab-main').classList.add('active');
        fetchStats();
    } else if (tab === 'malicious') {
        document.getElementById('malicious-dashboard').style.display = 'block';
        document.getElementById('tab-malicious').classList.add('active');
        fetchMaliciousStats();
    }
}
