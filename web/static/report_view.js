// Report view page JavaScript

let currentSeverityFilter = '';
let currentScannerFilter = '';

document.addEventListener('DOMContentLoaded', () => {
    loadReport();
});

function applyFilters() {
    const cards = document.querySelectorAll('#findings-container .finding-card');
    cards.forEach(card => {
        const severity = (card.dataset.severity || '').toUpperCase();
        const scanner = (card.dataset.scanner || '').toLowerCase();
        const matchSev = !currentSeverityFilter || severity === currentSeverityFilter;
        const matchScan = !currentScannerFilter || scanner === currentScannerFilter;
        card.style.display = matchSev && matchScan ? '' : 'none';
    });
}

function setupFilters() {
    const bar = document.getElementById('filter-bar');
    const container = document.getElementById('findings-container');
    if (!bar || !container || !container.querySelector('.finding-card')) return;
    bar.style.display = 'flex';
    bar.querySelectorAll('.filter-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const filter = btn.dataset.filter;
            const value = (btn.dataset.value || '').toUpperCase();
            bar.querySelectorAll('.filter-btn[data-filter="' + filter + '"]').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            if (filter === 'severity') currentSeverityFilter = value;
            else if (filter === 'scanner') currentScannerFilter = value.toLowerCase();
            applyFilters();
        });
    });
}

function loadReport() {
    const report = getReportFromStorage(reportId);
    
    if (!report) {
        document.getElementById('report-subtitle').textContent = 'Report not found';
        const statsEl = document.getElementById('stats-container');
        const errEl = document.createElement('div');
        errEl.className = 'error';
        errEl.textContent = 'Report not found';
        statsEl.appendChild(errEl);
        return;
    }
    
    const date = report.generated_at || report.saved_at;
    const mode = report.mode || 'all';
    const path = report.path || 'N/A';
    
    document.getElementById('report-subtitle').textContent = `${mode.toUpperCase()} scan · ${path} · ${formatDate(date)}`;
    document.getElementById('report-title').textContent = `Report ${reportId.substring(0, 12)}`;
    
    displayResults(report);
    setupFilters();
}

function downloadReport() {
    const report = getReportFromStorage(reportId);
    if (!report) {
        alert('Report not found');
        return;
    }
    
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `vulnscan-report-${reportId}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}
