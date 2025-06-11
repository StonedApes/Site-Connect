document.addEventListener('DOMContentLoaded', () => {
    const body = document.body;
    const themeToggle = document.getElementById('theme-toggle');

    // Check local storage for theme preference
    const theme = localStorage.getItem('theme') || 'light-mode';
    body.classList.add(theme);
    themeToggle.innerHTML = theme === 'light-mode' ? '<i class="fas fa-moon"></i>' : '<i class="fas fa-sun"></i>';

    // Toggle theme on button click
    themeToggle.addEventListener('click', () => {
        body.classList.toggle('dark-mode');
        body.classList.toggle('light-mode');
        const newTheme = body.classList.contains('dark-mode') ? 'dark-mode' : 'light-mode';
        localStorage.setItem('theme', newTheme);
        themeToggle.innerHTML = newTheme === 'light-mode' ? '<i class="fas fa-moon"></i>' : '<i class="fas fa-sun"></i>';
    });
});