document.addEventListener('DOMContentLoaded', function() {
    const mapElement = document.getElementById('map');
    if (!mapElement) return; // Exit if map element is not found

    // Get data from HTML data attributes
    const latitude = parseFloat(mapElement.dataset.latitude);
    const longitude = parseFloat(mapElement.dataset.longitude);
    const trailerId = mapElement.dataset.trailerId;

    // Validate the data before initializing the map
    if (isNaN(latitude) || isNaN(longitude) || !trailerId) {
        console.error('Invalid latitude, longitude, or trailerId:', { latitude, longitude, trailerId });
        return;
    }

    // Initialize the Leaflet map
    const map = L.map('map').setView([latitude, longitude], 13);
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        attribution: '© <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>'
    }).addTo(map);
    L.marker([latitude, longitude]).addTo(map)
        .bindPopup('Trailer ' + trailerId).openPopup();
});