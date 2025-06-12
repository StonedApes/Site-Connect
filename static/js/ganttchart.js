document.addEventListener('DOMContentLoaded', function() {
    function getChartTextColor() {
        return document.body.classList.contains('dark-mode') ? '#b3b3b3' : '#000000';
    }

    function getChartBorderColor() {
        return document.body.classList.contains('dark-mode') ? '#333333' : '#dee2e6';
    }

    const ganttCanvas = document.getElementById('ganttChart');
    if (ganttCanvas) {
        const labels = JSON.parse(ganttCanvas.getAttribute('data-labels') || '[]');
        const startDates = JSON.parse(ganttCanvas.getAttribute('data-start-dates') || '[]');
        const dueDates = JSON.parse(ganttCanvas.getAttribute('data-due-dates') || '[]');
        const colors = JSON.parse(ganttCanvas.getAttribute('data-colors') || '[]');

        const data = labels.map((label, index) => ({
            x: [new Date(startDates[index]), new Date(dueDates[index])],
            y: label,
            backgroundColor: colors[index]
        }));

        const ganttChart = new Chart(ganttCanvas.getContext('2d'), {
            type: 'bar',
            data: {
                datasets: [{
                    label: 'Tasks',
                    data: data,
                    backgroundColor: colors,
                    borderColor: getChartBorderColor(),
                    borderWidth: 1
                }]
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                scales: {
                    x: {
                        type: 'time',
                        time: { unit: 'day' },
                        ticks: { color: getChartTextColor() },
                        grid: { color: getChartBorderColor() }
                    },
                    y: {
                        ticks: { color: getChartTextColor() },
                        grid: { color: getChartBorderColor() }
                    }
                },
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: { color: getChartTextColor(), font: { size: 14 } }
                    }
                }
            }
        });

        document.addEventListener('themeChanged', function() {
            ganttChart.options.scales.x.ticks.color = getChartTextColor();
            ganttChart.options.scales.x.grid.color = getChartBorderColor();
            ganttChart.options.scales.y.ticks.color = getChartTextColor();
            ganttChart.options.scales.y.grid.color = getChartBorderColor();
            ganttChart.options.plugins.legend.labels.color = getChartTextColor();
            ganttChart.options.datasets[0].borderColor = getChartBorderColor();
            ganttChart.update();
        });
    }
});