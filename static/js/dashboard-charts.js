document.addEventListener('DOMContentLoaded', function () {
    if (!window.dashboardData) {
        console.error('dashboardData is undefined. Check template rendering.');
        return;
    }

    // Chart.js for Order Status (if needed)
    const orderStatusCtx = document.getElementById('orderStatusChart')?.getContext('2d');
    if (orderStatusCtx) {
        new Chart(orderStatusCtx, {
            type: 'pie',
            data: {
                labels: ['Pending', 'Received', 'In Production', 'Shipped'],
                datasets: [{
                    data: window.dashboardData.statusCounts || [0, 0, 0, 0],
                    backgroundColor: ['#1E90FF', '#32CD32', '#FFD700', '#C0C0C0'],
                    borderWidth: 1,
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: { position: 'top' },
                    tooltip: { enabled: true }
                }
            }
        });
    }

    // Chart.js for Incident Trends
    const incidentTrendsCtx = document.getElementById('incidentTrendsChart')?.getContext('2d');
    if (incidentTrendsCtx) {
        new Chart(incidentTrendsCtx, {
            type: 'line',
            data: {
                labels: ['Week 1', 'Week 2', 'Week 3', 'Week 4', 'Week 5'],
                datasets: [{
                    label: 'Incidents',
                    data: window.dashboardData.incidentTrends || [0, 0, 0, 0, 0],
                    borderColor: '#FF4500',
                    backgroundColor: 'rgba(255, 69, 0, 0.2)',
                    borderWidth: 2,
                    fill: true
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: { position: 'top' },
                    tooltip: { enabled: true }
                },
                scales: {
                    y: { beginAtZero: true }
                }
            }
        });
    }
});