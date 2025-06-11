document.addEventListener('DOMContentLoaded', () => {
    const spinner = document.getElementById('loading-spinner');

    // Show spinner on page load
    spinner.style.display = 'block';

    // Hide spinner after 1 second (mock loading time)
    setTimeout(() => {
        spinner.style.display = 'none';
    }, 1000);
});