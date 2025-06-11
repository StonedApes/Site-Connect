document.addEventListener('DOMContentLoaded', function() {
    // Order Status Distribution Chart
    const orderStatusCanvas = document.getElementById('orderStatusChart');
    const statusCountsData = JSON.parse(orderStatusCanvas.getAttribute('data-status-counts') || '[]');
    const orderStatusChart = new Chart(orderStatusCanvas.getContext('2d'), {
        type: 'pie',
        data: {
            labels: ['Pending', 'Received', 'In Production', 'Shipped'],
            datasets: [{
                data: statusCountsData,
                backgroundColor: ['#dc3545', '#fd7e14', '#17a2b8', '#28a745'],
                borderColor: '#424242',
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    labels: {
                        color: '#E0E0E0'
                    }
                }
            }
        }
    });

    // Incident Types Chart
    const incidentTypesCanvas = document.getElementById('incidentTypesChart');
    const incidentCounts = JSON.parse(incidentTypesCanvas.getAttribute('data-incident-counts') || '[]');
    const incidentTypesChart = new Chart(incidentTypesCanvas.getContext('2d'), {
        type: 'bar',
        data: {
            labels: ['Incident', 'Near-Miss', 'Hazard'],
            datasets: [{
                label: 'Incidents',
                data: incidentCounts,
                backgroundColor: '#dc3545',
                borderColor: '#424242',
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            scales: {
                x: {
                    ticks: {
                        color: '#E0E0E0'
                    },
                    grid: {
                        color: '#424242'
                    }
                },
                y: {
                    ticks: {
                        color: '#E0E0E0'
                    },
                    grid: {
                        color: '#424242'
                    }
                }
            },
            plugins: {
                legend: {
                    labels: {
                        color: '#E0E0E0'
                    }
                }
            }
        }
    });

    // Vehicles Chart
    const vehiclesCanvas = document.getElementById('vehiclesChart');
    const vehiclesOnRoad = JSON.parse(vehiclesCanvas.getAttribute('data-vehicles-on-road') || '0');
    const vehiclesInYard = JSON.parse(vehiclesCanvas.getAttribute('data-vehicles-in-yard') || '0');
    const vehiclesChart = new Chart(vehiclesCanvas.getContext('2d'), {
        type: 'doughnut',
        data: {
            labels: ['On Road', 'In Yard'],
            datasets: [{
                data: [vehiclesOnRoad, vehiclesInYard],
                backgroundColor: ['#17a2b8', '#6c757d'],
                borderColor: '#424242',
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    labels: {
                        color: '#E0E0E0'
                    }
                }
            }
        }
    });

    // Orders Over Time Chart
    const ordersOverTimeCanvas = document.getElementById('ordersOverTimeChart');
    const orderDates = JSON.parse(ordersOverTimeCanvas.getAttribute('data-order-dates') || '[]');
    const orderCounts = JSON.parse(ordersOverTimeCanvas.getAttribute('data-order-counts') || '[]');
    const ordersOverTimeChart = new Chart(ordersOverTimeCanvas.getContext('2d'), {
        type: 'line',
        data: {
            labels: orderDates,
            datasets: [{
                label: 'Orders',
                data: orderCounts,
                borderColor: '#17a2b8',
                backgroundColor: 'rgba(23, 162, 184, 0.2)',
                fill: true,
                tension: 0.1
            }]
        },
        options: {
            responsive: true,
            scales: {
                x: {
                    ticks: {
                        color: '#E0E0E0'
                    },
                    grid: {
                        color: '#424242'
                    }
                },
                y: {
                    ticks: {
                        color: '#E0E0E0'
                    },
                    grid: {
                        color: '#424242'
                    }
                }
            },
            plugins: {
                legend: {
                    labels: {
                        color: '#E0E0E0'
                    }
                }
            }
        }
    });

    // Incident Severity Chart
    const severityCanvas = document.getElementById('severityChart');
    const severityCounts = JSON.parse(severityCanvas.getAttribute('data-severity-counts') || '[]');
    const severityChart = new Chart(severityCanvas.getContext('2d'), {
        type: 'bar',
        data: {
            labels: ['Low', 'Medium', 'High'],
            datasets: [{
                label: 'Incidents',
                data: severityCounts,
                backgroundColor: ['#28a745', '#fd7e14', '#dc3545'],
                borderColor: '#424242',
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            scales: {
                x: {
                    ticks: {
                        color: '#E0E0E0'
                    },
                    grid: {
                        color: '#424242'
                    }
                },
                y: {
                    ticks: {
                        color: '#E0E0E0'
                    },
                    grid: {
                        color: '#424242'
                    }
                }
            },
            plugins: {
                legend: {
                    labels: {
                        color: '#E0E0E0'
                    }
                }
            }
        }
    });

    // Subcontractor Approval Status Chart
    const subcontractorStatusCanvas = document.getElementById('subcontractorStatusChart');
    const subcontractorStatusCounts = JSON.parse(subcontractorStatusCanvas.getAttribute('data-subcontractor-status-counts') || '[]');
    const subcontractorStatusChart = new Chart(subcontractorStatusCanvas.getContext('2d'), {
        type: 'pie',
        data: {
            labels: ['Pending', 'Approved', 'Rejected'],
            datasets: [{
                data: subcontractorStatusCounts,
                backgroundColor: ['#fd7e14', '#28a745', '#dc3545'],
                borderColor: '#424242',
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    labels: {
                        color: '#E0E0E0'
                    }
                }
            }
        }
    });

    // Manpower Trend Chart
    const manpowerTrendCanvas = document.getElementById('manpowerTrendChart');
    const manpowerDates = JSON.parse(manpowerTrendCanvas.getAttribute('data-manpower-dates') || '[]');
    const manpowerValues = JSON.parse(manpowerTrendCanvas.getAttribute('data-manpower-values') || '[]');
    const manpowerTrendChart = new Chart(manpowerTrendCanvas.getContext('2d'), {
        type: 'line',
        data: {
            labels: manpowerDates,
            datasets: [{
                label: 'Manpower',
                data: manpowerValues,
                borderColor: '#28a745',
                backgroundColor: 'rgba(40, 167, 69, 0.2)',
                fill: true,
                tension: 0.1
            }]
        },
        options: {
            responsive: true,
            scales: {
                x: {
                    ticks: {
                        color: '#E0E0E0'
                    },
                    grid: {
                        color: '#424242'
                    }
                },
                y: {
                    ticks: {
                        color: '#E0E0E0'
                    },
                    grid: {
                        color: '#424242'
                    }
                }
            },
            plugins: {
                legend: {
                    labels: {
                        color: '#E0E0E0'
                    }
                }
            }
        }
    });
});