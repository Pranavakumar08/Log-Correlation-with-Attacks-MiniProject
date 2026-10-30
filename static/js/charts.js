// Charts Manager using Chart.js for SIEM Dashboard Visualizations

let sourceChart = null;
let severityChart = null;

const ChartsManager = {
    initCharts() {
        this.initSourceChart();
        this.initSeverityChart();
    },

    initSourceChart() {
        const ctx = document.getElementById('sourceStreamChart');
        if (!ctx) return;

        sourceChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: ['Auth', 'File/DLP', 'Endpoint', 'Badge', 'HR'],
                datasets: [{
                    label: 'Events Processed',
                    data: [0, 0, 0, 0, 0],
                    backgroundColor: [
                        'rgba(56, 189, 248, 0.65)',
                        'rgba(168, 85, 247, 0.65)',
                        'rgba(245, 158, 11, 0.65)',
                        'rgba(16, 185, 129, 0.65)',
                        'rgba(239, 68, 68, 0.65)'
                    ],
                    borderColor: [
                        '#38bdf8',
                        '#a855f7',
                        '#f59e0b',
                        '#10b981',
                        '#ef4444'
                    ],
                    borderWidth: 1.5,
                    borderRadius: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        backgroundColor: 'rgba(15, 23, 42, 0.95)',
                        titleColor: '#38bdf8',
                        bodyColor: '#f8fafc',
                        borderColor: 'rgba(56, 189, 248, 0.3)',
                        borderWidth: 1
                    }
                },
                scales: {
                    x: {
                        grid: { display: false },
                        ticks: { color: '#94a3b8', font: { family: 'Inter', size: 11 } }
                    },
                    y: {
                        beginAtZero: true,
                        grid: { color: 'rgba(255, 255, 255, 0.05)' },
                        ticks: { color: '#64748b', font: { family: 'JetBrains Mono', size: 10 }, precision: 0 }
                    }
                }
            }
        });
    },

    initSeverityChart() {
        const ctx = document.getElementById('severityChart');
        if (!ctx) return;

        severityChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low'],
                datasets: [{
                    data: [0, 0, 0, 0],
                    backgroundColor: [
                        'rgba(239, 68, 68, 0.85)',
                        'rgba(249, 115, 22, 0.85)',
                        'rgba(245, 158, 11, 0.85)',
                        'rgba(56, 189, 248, 0.85)'
                    ],
                    borderColor: '#0f172a',
                    borderWidth: 2,
                    hoverOffset: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '72%',
                plugins: {
                    legend: {
                        position: 'right',
                        labels: {
                            color: '#94a3b8',
                            font: { family: 'Inter', size: 11 },
                            boxWidth: 12,
                            padding: 10
                        }
                    },
                    tooltip: {
                        backgroundColor: 'rgba(15, 23, 42, 0.95)',
                        borderColor: 'rgba(255, 255, 255, 0.1)',
                        borderWidth: 1
                    }
                }
            }
        });
    },

    updateData(analytics) {
        if (!analytics) return;

        // Update Source Distribution
        if (sourceChart && analytics.source_breakdown) {
            const b = analytics.source_breakdown;
            sourceChart.data.datasets[0].data = [
                b['Authentication'] || 0,
                b['File / DLP'] || 0,
                b['Endpoint / Auditd'] || 0,
                b['Physical Badge'] || 0,
                b['HR Context'] || 0
            ];
            sourceChart.update('none');
        }

        // Update Severity Distribution
        if (severityChart && analytics.severity_breakdown) {
            const s = analytics.severity_breakdown;
            const crit = s['CRITICAL'] || 0;
            const high = s['HIGH'] || 0;
            const med = s['MEDIUM'] || 0;
            const low = s['LOW'] || 0;

            const total = crit + high + med + low;
            const totalEl = document.getElementById('totalSeverityCount');
            if (totalEl) totalEl.textContent = `${total} Incidents`;

            // If zero incidents, show empty placeholder slice
            if (total === 0) {
                severityChart.data.datasets[0].data = [0, 0, 0, 1];
                severityChart.data.datasets[0].backgroundColor = ['#ef4444', '#f97316', '#f59e0b', 'rgba(255, 255, 255, 0.05)'];
            } else {
                severityChart.data.datasets[0].data = [crit, high, med, low];
                severityChart.data.datasets[0].backgroundColor = [
                    'rgba(239, 68, 68, 0.85)',
                    'rgba(249, 115, 22, 0.85)',
                    'rgba(245, 158, 11, 0.85)',
                    'rgba(56, 189, 248, 0.85)'
                ];
            }
            severityChart.update('none');
        }
    }
};
