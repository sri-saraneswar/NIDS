// Global State
window.appState = {
    isMonitoring: false
};

// Theme Management
function initTheme() {
    const savedTheme = localStorage.getItem('theme') || 'dark';
    document.documentElement.setAttribute('data-theme', savedTheme);
    const themeIcon = document.getElementById('theme-icon');
    if(themeIcon) {
        themeIcon.className = savedTheme === 'dark' ? 'fas fa-moon' : 'fas fa-sun';
    }
}

function toggleTheme() {
    const currentTheme = document.documentElement.getAttribute('data-theme');
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', newTheme);
    localStorage.setItem('theme', newTheme);
    
    const themeIcon = document.getElementById('theme-icon');
    if(themeIcon) {
        themeIcon.className = newTheme === 'dark' ? 'fas fa-moon' : 'fas fa-sun';
    }
    
    // Update charts if they exist
    if (typeof updateChartTheme === 'function') {
        updateChartTheme(newTheme);
    }
}

// Utility functions
function formatBytes(bytes, decimals = 2) {
    if (!+bytes) return '0 Bytes';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`;
}

function getSeverityBadge(severity) {
    const upper = severity.toUpperCase();
    if (upper === 'CRITICAL') return '<span class="badge-soc badge-critical">CRITICAL</span>';
    if (upper === 'HIGH') return '<span class="badge-soc badge-high">HIGH</span>';
    if (upper === 'MEDIUM') return '<span class="badge-soc badge-medium">MEDIUM</span>';
    return '<span class="badge-soc badge-low">LOW</span>';
}

// Initialize on load
document.addEventListener('DOMContentLoaded', () => {
    initTheme();
    
    const themeToggleBtn = document.getElementById('theme-toggle');
    if(themeToggleBtn) {
        themeToggleBtn.addEventListener('click', toggleTheme);
    }
});
