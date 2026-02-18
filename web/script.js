const BASE_URL = ''; // Relative path

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    fetchStatus();
    setInterval(fetchStatus, 1000); // Poll every 1s for accurate countdowns
});

async function fetchStatus() {
    try {
        const res = await fetch(`${BASE_URL}/status`);
        const data = await res.json();
        renderNATTable(data.hosts);
        if (data.history) renderHistoryTable(data.history);
        if (data.network_config) renderNetworkConfig(data);

    } catch (e) {
        console.error("Connection Error:", e);
    }
}

function renderNetworkConfig(data) {
    // Populate Zone Config Tiles if not already done (or simple overwrite)
    const container = document.getElementById('zone-config');
    // Using static definition for clarity based on requirements, but could be dynamic
    if (container.innerHTML.trim() === '') {
        const zones = [
            { name: 'HIGH', host: 'h1, h2', interval: '40s', color: '#ef4444', class: 'badge-high' },
            { name: 'MEDIUM', host: 'h3, h4', interval: '20s', color: '#fbbf24', class: 'badge-med' },
            { name: 'LOW', host: 'h5, h6', interval: '10s', color: '#22c55e', class: 'badge-low' },
        ];

        container.innerHTML = zones.map(z => `
            <div style="background:#1e293b; padding:10px; border-radius:6px; border:1px solid ${z.color}40; flex:1;">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:5px;">
                    <span class="badge ${z.class}">${z.name}</span>
                    <span style="font-size:0.8em; color:#94a3b8;">${z.interval}</span>
                </div>
                <div class="mono" style="font-size:0.9em;">${z.host}</div>
            </div>
        `).join('');
    }
}

function renderNATTable(hosts) {
    const tbody = document.getElementById('nat-rows');
    tbody.innerHTML = '';

    // Sort hosts h1, h2...
    const sortedKeys = Object.keys(hosts).sort((a, b) => {
        return a.localeCompare(b, undefined, { numeric: true, sensitivity: 'base' });
    });

    sortedKeys.forEach(h => {
        const host = hosts[h];
        if (host.private_ip && host.ip) {
            const row = document.createElement('tr');

            // Risk Styling
            let riskClass = 'badge-low';
            if (host.risk === 'high') riskClass = 'badge-high';
            else if (host.risk === 'medium') riskClass = 'badge-med';

            // Status Logic
            const isRebinding = host.next_hop_in <= 3; // Rebinding in last 3 seconds
            let statusHtml = `<span class="badge badge-low" style="background:rgba(16, 185, 129, 0.1); color:#10b981;">● ACTIVE</span>`;
            if (isRebinding) {
                statusHtml = `<span class="badge badge-med" style="animation:pulse 1s infinite;">↻ REBINDING</span>`;
            }

            row.innerHTML = `
                <td style="font-weight:600; color:var(--text-main);">${h.toUpperCase()}</td>
                <td><span class="badge ${riskClass}">${host.risk.toUpperCase()}</span></td>
                <td style="color:var(--text-muted);">${host.private_ip}</td>
                <td style="color:var(--primary); font-weight:600;">${host.ip}</td>
                <td>${statusHtml}</td>
            `;
            tbody.appendChild(row);
        }
    });
}

function renderHistoryTable(history) {
    const tbody = document.getElementById('history-rows');
    // history is array from old to new. We want newest top.
    const reversed = [...history].reverse();
    tbody.innerHTML = '';

    reversed.forEach(evt => {
        const row = document.createElement('tr');

        let riskClass = 'badge-low';
        let riskLabel = evt.risk || evt.zone || 'LOW';
        if (riskLabel === 'high') riskClass = 'badge-high';
        if (riskLabel === 'medium') riskClass = 'badge-med';

        row.innerHTML = `
            <td style="color:var(--text-muted); font-size:0.85em;">${evt.time_str}</td>
            <td style="font-weight:600;">${evt.host.toUpperCase()}</td>
            <td><span class="badge ${riskClass}">${evt.type === 'transfer_hop' ? 'FORCED' : 'SCHEDULED'}</span></td>
            <td>
                <span style="color:var(--danger); text-decoration:line-through;">${evt.old_ip}</span> 
                <span style="color:var(--text-muted); margin:0 5px;">➜</span> 
                <span style="color:var(--primary); font-weight:600;">${evt.new_ip}</span>
            </td>
        `;
        tbody.appendChild(row);
    });
}

async function triggerShuffle(policy) {
    try {
        const btn = document.querySelector('.btn-danger');
        const originalText = btn.innerHTML;
        btn.innerHTML = 'Executing...';
        btn.disabled = true;

        await fetch(`${BASE_URL}/shuffle`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ hosts: ['h1', 'h2'], policy: policy })
        });

        setTimeout(() => {
            fetchStatus();
            btn.innerHTML = originalText;
            btn.disabled = false;
        }, 800);

    } catch (e) {
        alert("Shuffle Failed: " + e);
        document.querySelector('.btn-danger').disabled = false;
    }
}

async function clearHistory() {
    try {
        await fetch(`${BASE_URL}/clear_history`, { method: 'POST' });
        fetchStatus();
    } catch (e) {
        console.error(e);
    }
}

// End of standard logic

// End of standard logic

async function sendSecureData() {
    const src = document.getElementById('secure-src').value;
    const dst = document.getElementById('secure-dst').value;
    const payload = document.getElementById('secure-payload').value;

    const resultPanel = document.getElementById('secure-result-panel');
    const termBody = document.getElementById('live-terminal');

    // UI Visualization Elements
    const vizSrc = document.getElementById('viz-src-name');
    const vizDst = document.getElementById('viz-dst-name');
    const c1 = document.getElementById('conn-1');
    const c2 = document.getElementById('conn-2');

    // Reset UI
    resultPanel.style.display = 'block';

    // Reset Terminal
    termBody.innerHTML = `
        <div class="cmd-line">
            <span class="cmd-prompt">➜</span>
            <span>Initializing Secure Channel...</span>
        </div>
    `;

    vizSrc.innerText = src.toUpperCase();
    vizDst.innerText = dst.toUpperCase();
    c1.className = 'connector';
    c2.className = 'connector';

    try {
        const res = await fetch(`${BASE_URL}/sim/secure_transfer`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ src, dst, payload })
        });

        const data = await res.json();

        // Handle BLOCK case
        if (data.status === 'blocked') {
            await typeToTerminal(`echo "⛔ SECURITY BLOCKED: ${data.reason}"`, termBody, 'error');
            if (data.trace) renderTrace(data.trace, termBody, c1, c2);
            return;
        }

        if (data.status === 'error') {
            await typeToTerminal(`echo "System Error: ${data.msg}"`, termBody, 'error');
            return;
        }

        // Handle SUCCESS case
        renderTrace(data.trace, termBody, c1, c2);

    } catch (e) {
        await typeToTerminal(`echo "Connection Failed: ${e}"`, termBody, 'error');
    }
}

async function renderTrace(trace, container, c1, c2) {
    for (const step of trace) {
        // Visual Triggers
        if (step.step === 'TLS') c1.classList.add('active');
        if (step.step === 'DELIVERY') c2.classList.add('active');

        // Terminal Output
        if (step.cmd) {
            await typeToTerminal(step.cmd, container, 'cmd');
        }

        let color = '#94a3b8';
        let icon = 'ℹ️';
        if (step.status === 'success') { color = '#4ade80'; icon = '✅'; }
        if (step.status === 'error') { color = '#ef4444'; icon = '❌'; }
        if (step.status === 'warning') { color = '#fbbf24'; icon = '⚠️'; }

        // System Log Output (non-typing, instant block)
        const line = document.createElement('div');
        line.style.marginBottom = '2px';
        line.innerHTML = `<span style="color:${color}">${icon} [${step.step}] ${step.msg}</span>`;
        container.appendChild(line);
        container.scrollTop = container.scrollHeight;

        await new Promise(r => setTimeout(r, 400)); // Pace the logs
    }
}

async function typeToTerminal(text, container, type = 'normal') {
    const line = document.createElement('div');
    line.className = 'cmd-line';

    let promptHtml = '<span class="cmd-prompt">➜</span>';
    if (type === 'error') promptHtml = '<span class="cmd-prompt" style="color:red">➜</span>';

    line.innerHTML = `${promptHtml}<span class="typing"></span><span class="cursor"></span>`;
    container.appendChild(line);

    const span = line.querySelector('.typing');
    const cursor = line.querySelector('.cursor');

    // Simulate Typing
    for (let char of text) {
        span.textContent += char;
        container.scrollTop = container.scrollHeight;
        await new Promise(r => setTimeout(r, 15)); // Typing speed
    }

    // Remove cursor from this line after done
    line.removeChild(cursor);
}
