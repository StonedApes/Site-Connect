document.addEventListener('DOMContentLoaded', () => {
    if (typeof Chart === 'undefined') {
        console.error('Chart.js failed to load.');
        return;
    }

    const orderTrendCanvas = document.getElementById('orderTrendChart');
    const incidentSummaryCanvas = document.getElementById('incidentSummaryChart');

    if (!orderTrendCanvas || !incidentSummaryCanvas) {
        console.error('Canvas elements not found.');
        return;
    }

    try {
        const orderTrendsLabels = JSON.parse(orderTrendCanvas.dataset.labels || '[]');
        const orderTrendsData = JSON.parse(orderTrendCanvas.dataset.values || '[]');
        const incidentSummaryLabels = JSON.parse(incidentSummaryCanvas.dataset.labels || '[]');
        const incidentSummaryData = JSON.parse(incidentSummaryCanvas.dataset.values || '[]');

        new Chart(orderTrendCanvas, {
            type: 'line',
            data: {
                labels: orderTrendsLabels,
                datasets: [{
                    label: 'Orders Placed',
                    data: orderTrendsData,
                    borderColor: '#14B8A6',
                    backgroundColor: 'rgba(20, 184, 166, 0.2)',
                    fill: true,
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: { position: 'top' },
                    title: { display: true, text: 'Order Trends (Last 5 Days)' }
                },
                scales: {
                    y: { beginAtZero: true, title: { display: true, text: 'Orders' } },
                    x: {}
                }
            }
        });

        new Chart(incidentSummaryCanvas, {
            type: 'bar',
            data: {
                labels: incidentSummaryLabels,
                datasets: [{
                    label: 'Incident Summary',
                    data: incidentSummaryData,
                    backgroundColor: ['#EF4444', '#F97316', '#14B8A6'],
                    borderColor: ['#DC2626', '#EA580C', '#0D9488'],
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: { position: 'top' },
                    title: { display: true, text: 'Incident Summary by Type' }
                },
                scales: {
                    y: { beginAtZero: true, title: { display: true, text: 'Number of Incidents' } },
                    x: {}
                }
            }
        });
    } catch (error) {
        console.error('Error rendering charts:', error);
    }
});