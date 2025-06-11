document.addEventListener('DOMContentLoaded', () => {
    const sidebar = document.getElementById('sidebar');
    const mainContent = document.querySelector('.main-content');
    const toggleButton = document.createElement('button');
    toggleButton.id = 'sidebar-toggle';
    toggleButton.className = 'fixed top-16 left-4 z-50 bg-primary-color text-white p-2 rounded-full md:hidden';
    toggleButton.innerHTML = '<i class="fas fa-bars"></i>';
    document.body.appendChild(toggleButton);

    const sidebarState = localStorage.getItem('sidebar_collapse');
    if (sidebarState === 'collapsed') {
        sidebar.classList.add('collapsed');
        mainContent.classList.add('no-sidebar');
        toggleButton.innerHTML = '<i class="fas fa-bars"></i>';
    }

    toggleButton.addEventListener('click', () => {
        sidebar.classList.toggle('collapsed');
        mainContent.classList.toggle('no-sidebar');
        const isCollapsed = sidebar.classList.contains('collapsed');
        toggleButton.innerHTML = isCollapsed ? '<i class="fas fa-bars"></i>' : '<i class="fas fa-times"></i>';
        localStorage.setItem('sidebar_collapse', isCollapsed ? 'collapsed' : 'expanded');
    });
});