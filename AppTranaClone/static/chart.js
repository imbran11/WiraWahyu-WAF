// charts.js

// Function to initialize charts
function initCharts(protectionTrendData, detectionTrendData, vulnerabilityTrendData) {
    const protectionTrendCtx = document.getElementById('protectionTrendChart').getContext('2d');
    const detectionTrendCtx = document.getElementById('detectionTrendChart').getContext('2d');
    const vulnerabilityTrendCtx = document.getElementById('vulnerabilityTrendChart').getContext('2d');

    // Protection Trend Chart
    new Chart(protectionTrendCtx, {
        type: 'line',
        data: {
            labels: ['Day 1', 'Day 2', 'Day 3', 'Day 4', 'Day 5', 'Day 6', 'Day 7'],
            datasets: [{
                label: 'Protection Events',
                data: protectionTrendData,
                borderColor: 'rgba(75, 192, 192, 1)',
                fill: false,
            }]
        },
        options: {
            responsive: true,
            scales: {
                y: {
                    beginAtZero: true
                }
            }
        }
    });

    // Detection Trend Chart
    new Chart(detectionTrendCtx, {
        type: 'line',
        data: {
            labels: ['Day 1', 'Day 2', 'Day 3', 'Day 4', 'Day 5', 'Day 6', 'Day 7'],
            datasets: [{
                label: 'Detection Events',
                data: detectionTrendData,
                borderColor: 'rgba(255, 99, 132, 1)',
                fill: false,
            }]
        },
        options: {
            responsive: true,
            scales: {
                y: {
                    beginAtZero: true
                }
            }
        }
    });

    // Vulnerability Trend Chart
    new Chart(vulnerabilityTrendCtx, {
        type: 'line',
        data: {
            labels: ['Day 1', 'Day 2', 'Day 3', 'Day 4', 'Day 5', 'Day 6', 'Day 7'],
            datasets: [{
                label: 'Vulnerability Events',
                data: vulnerabilityTrendData,
                borderColor: 'rgba(153, 102, 255, 1)',
                fill: false,
            }]
        },
        options: {
            responsive: true,
            scales: {
                y: {
                    beginAtZero: true
                }
            }
        }
    });
}
