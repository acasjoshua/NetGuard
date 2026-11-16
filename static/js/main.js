/**
 * NetGuard IDS - Main Application JavaScript
 * Real-time Telemetry, Theme Management & Interactivity
 */

document.addEventListener('DOMContentLoaded', () => {
    initLiveClock();
    initThemeManager();
    initSidebarControls();
    initDropdowns();
    initAboutModal();
    initAutoTrafficPolling();
});

/* ==========================================================================
   1. Live Digital Clock
   ========================================================================== */
function initLiveClock() {
    const clockEl = document.getElementById('clockTime');
    if (!clockEl) return;

    function updateTime() {
        const now = new Date();
        const hours = String(now.getHours()).padStart(2, '0');
        const minutes = String(now.getMinutes()).padStart(2, '0');
        const seconds = String(now.getSeconds()).padStart(2, '0');
        clockEl.textContent = `${hours}:${minutes}:${seconds}`;
    }

    updateTime();
    setInterval(updateTime, 1000);
}

/* ==========================================================================
   2. Theme Manager (Dark / Light)
   ========================================================================== */
function initThemeManager() {
    const themeToggleBtn = document.getElementById('themeToggleBtn');
    const themeIcon = document.getElementById('themeIcon');
    const htmlEl = document.documentElement;

    // Check stored preference or default to dark
    const storedTheme = localStorage.getItem('netguard_theme') || 'dark';
    applyTheme(storedTheme);

    if (themeToggleBtn) {
        themeToggleBtn.addEventListener('click', () => {
            const currentTheme = htmlEl.getAttribute('data-theme') || 'dark';
            const nextTheme = currentTheme === 'dark' ? 'light' : 'dark';
            applyTheme(nextTheme);
            localStorage.setItem('netguard_theme', nextTheme);
        });
    }

    function applyTheme(theme) {
        htmlEl.setAttribute('data-theme', theme);
        document.body.className = `theme-${theme}`;
        if (themeIcon) {
            themeIcon.className = theme === 'dark' ? 'fa-solid fa-sun' : 'fa-solid fa-moon';
        }
    }
}

/* ==========================================================================
   3. Sidebar Controls (Responsive Mobile)
   ========================================================================== */
function initSidebarControls() {
    const toggleBtn = document.getElementById('sidebarToggleBtn');
    const closeBtn = document.getElementById('sidebarCloseBtn');
    const sidebar = document.getElementById('appSidebar');

    if (toggleBtn && sidebar) {
        toggleBtn.addEventListener('click', () => {
            sidebar.classList.toggle('show');
        });
    }

    if (closeBtn && sidebar) {
        closeBtn.addEventListener('click', () => {
            sidebar.classList.remove('show');
        });
    }

    // Close when clicking outside on mobile
    document.addEventListener('click', (e) => {
        if (sidebar && sidebar.classList.contains('show')) {
            if (!sidebar.contains(e.target) && !toggleBtn.contains(e.target)) {
                sidebar.classList.remove('show');
            }
        }
    });
}

/* ==========================================================================
   4. User Dropdown Menu
   ========================================================================== */
function initDropdowns() {
    const menuBtn = document.getElementById('userMenuBtn');
    const dropdownMenu = document.getElementById('userDropdownMenu');

    if (menuBtn && dropdownMenu) {
        menuBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            dropdownMenu.classList.toggle('show');
        });

        document.addEventListener('click', (e) => {
            if (!dropdownMenu.contains(e.target)) {
                dropdownMenu.classList.remove('show');
            }
        });
    }
}

/* ==========================================================================
   5. About / Project Objectives Modal
   ========================================================================== */
function initAboutModal() {
    const openBtn = document.getElementById('openAboutModalBtn');
    const closeBtn = document.getElementById('closeAboutModalBtn');
    const confirmBtn = document.getElementById('confirmAboutModalBtn');
    const modal = document.getElementById('aboutModal');

    if (!modal) return;

    if (openBtn) {
        openBtn.addEventListener('click', () => modal.classList.add('show'));
    }

    const closeModal = () => modal.classList.remove('show');

    if (closeBtn) closeBtn.addEventListener('click', closeModal);
    if (confirmBtn) confirmBtn.addEventListener('click', closeModal);

    modal.addEventListener('click', (e) => {
        if (e.target === modal) closeModal();
    });
}

/* ==========================================================================
   6. Auto-Refresh Real-time Traffic Polling
   ========================================================================== */
function initAutoTrafficPolling() {
    // Only poll if on dashboard page
    const liveThroughputEl = document.getElementById('liveThroughputStat');
    if (!liveThroughputEl) return;

    setInterval(() => {
        fetch('/api/traffic-stream/')
            .then(res => res.json())
            .then(data => {
                if (data.status === 'success') {
                    if (liveThroughputEl) {
                        liveThroughputEl.textContent = `${data.bandwidth_kbps} KB/s`;
                    }
                    const activeConnEl = document.getElementById('liveActiveConnStat');
                    if (activeConnEl) {
                        activeConnEl.textContent = data.active_connections;
                    }
                    const alertCountEl = document.getElementById('sidebarAlertCount');
                    if (alertCountEl) {
                        alertCountEl.textContent = data.unresolved_alerts;
                    }
                }
            })
            .catch(() => {
                // Silently skip if network error during polling
            });
    }, 6000);
}

/* ==========================================================================
   7. Global Alert Resolution Helper
   ========================================================================== */
window.resolveAlert = function(alertId, btnElement) {
    if (!confirm(`Acknowledge and mark Alert #${alertId} as resolved?`)) return;

    const csrfToken = getCookie('csrftoken');

    fetch(`/api/resolve-alert/${alertId}/`, {
        method: 'POST',
        headers: {
            'X-CSRFToken': csrfToken,
            'Content-Type': 'application/json'
        }
    })
    .then(res => res.json())
    .then(data => {
        if (data.status === 'success') {
            const row = document.getElementById(`alert-row-${alertId}`);
            if (row) {
                row.style.opacity = '0.5';
                const statusCell = row.querySelector('.status-cell');
                if (statusCell) {
                    statusCell.innerHTML = '<span class="pill pill-success"><i class="fa-solid fa-check"></i> Resolved</span>';
                }
                if (btnElement) btnElement.remove();
            } else {
                location.reload();
            }
        } else {
            alert('Failed to resolve alert: ' + data.message);
        }
    })
    .catch(err => alert('Error connecting to server: ' + err));
};

/* ==========================================================================
   8. Global Subnet Scanner Helper
   ========================================================================== */
window.triggerSubnetScan = function(btnElement) {
    if (btnElement) {
        btnElement.disabled = true;
        btnElement.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Scanning Subnet...';
    }

    const csrfToken = getCookie('csrftoken');

    fetch('/api/scan-devices/', {
        method: 'POST',
        headers: {
            'X-CSRFToken': csrfToken,
            'Content-Type': 'application/json'
        }
    })
    .then(res => res.json())
    .then(data => {
        if (data.status === 'success') {
            alert(data.message);
            location.reload();
        } else {
            alert('Scan error: ' + data.message);
            if (btnElement) {
                btnElement.disabled = false;
                btnElement.innerHTML = '<i class="fa-solid fa-radar"></i> Scan Subnet Now';
            }
        }
    })
    .catch(err => {
        alert('Scan error: ' + err);
        if (btnElement) {
            btnElement.disabled = false;
            btnElement.innerHTML = '<i class="fa-solid fa-radar"></i> Scan Subnet Now';
        }
    });
};

/* Utility: Retrieve Django CSRF Cookie */
function getCookie(name) {
    let cookieValue = null;
    if (document.cookie && document.cookie !== '') {
        const cookies = document.cookie.split(';');
        for (let i = 0; i < cookies.length; i++) {
            const cookie = cookies[i].trim();
            if (cookie.substring(0, name.length + 1) === (name + '=')) {
                cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                break;
            }
        }
    }
    return cookieValue;
}
