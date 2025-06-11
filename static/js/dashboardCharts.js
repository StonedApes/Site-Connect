function getChartTextColor() {
    return document.body.classList.contains('dark-mode') ? '#b3b3b3' : '#000000';
}

function getChartBorderColor() {
    return document.body.classList.contains('dark-mode') ? '#333333' : '#dee2e6';
}

const vehiclesCanvas = document.getElementById('vehiclesChart');
if (vehiclesCanvas) {
    const vehiclesChart = new Chart(vehiclesCanvas.getContext('2d'), {
        type: 'bar',
        data: {
            labels: ['Trailers', 'Lorries', 'Concrete Lorries'],
            datasets: [
                {
                    label: 'In Factory',
                    data: [10, 20, 15], // Example data
                    backgroundColor: document.body.classList.contains('dark-mode') ? '#6c757d' : '#000000',
                    borderColor: getChartBorderColor(),
                    borderWidth: 1
                },
                {
                    label: 'On Road',
                    data: [5, 10, 8], // Example data
                    backgroundColor: document.body.classList.contains('dark-mode') ? '#17a2b8' : '#333333',
                    borderColor: getChartBorderColor(),
                    borderWidth: 1
                }
            ]
        },
        options: {
            scales: {
                x: { ticks: { color: getChartTextColor() }, grid: { color: getChartBorderColor() } },
                y: { ticks: { color: getChartTextColor() }, grid: { color: getChartBorderColor() } }
            },
            plugins: {
                legend: { labels: { color: getChartTextColor() } }
            }
        }
    });

    document.addEventListener('themeChanged', function () {
        vehiclesChart.options.scales.x.ticks.color = getChartTextColor();
        vehiclesChart.options.scales.y.ticks.color = getChartTextColor();
        vehiclesChart.options.plugins.legend.labels.color = getChartTextColor();
        vehiclesChart.data.datasets[0].backgroundColor = document.body.classList.contains('dark-mode') ? '#6c757d' : '#000000';
        vehiclesChart.data.datasets[1].backgroundColor = document.body.classList.contains('dark-mode') ? '#17a2b8' : '#333333';
        vehiclesChart.update();
    });
}