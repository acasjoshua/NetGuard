/**
 * WIDS - Wandering Intrusion Detection System JavaScript
 * Demo Telemetry, Theme Management & Interactivity
 */

document.addEventListener('DOMContentLoaded', () => {
    initLiveClock();
    initThemeManager();
    initSidebarControls();
    initDropdowns();
    initAboutModal();
    initAutoTrafficPolling();
    initLiveDiscoveryForms();
});

function initLiveDiscoveryForms() {
    document.querySelectorAll('.live-discovery-form').forEach((form) => {
        form.addEventListener('submit', async (event) => {
            event.preventDefault();
            const button = form.querySelector('button');
            const originalText = button.innerHTML;
            button.disabled = true;
            button.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Discovering...';
            try {
                const response = await fetch(form.action, {
                    method: 'POST',
                    headers: {
                        'X-CSRFToken': form.querySelector('[name=csrfmiddlewaretoken]').value,
                        'X-Requested-With': 'XMLHttpRequest',
                    },
                });
                const payload = await response.json();
                if (!response.ok) throw new Error(payload.message || 'Discovery failed');
                window.location.reload();
            } catch (error) {
                window.alert(error.message);
            } finally {
                button.disabled = false;
                button.innerHTML = originalText;
            }
        });
    });
}

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
   6. Auto-Refresh Simulated Traffic Polling
   ========================================================================== */
function initAutoTrafficPolling() {
    const liveThroughputEl = document.getElementById('liveThroughputStat');
    const runtimeSettings = document.getElementById('dashboardRuntimeSettings');
    if (!liveThroughputEl || !runtimeSettings) return;

    let lastAlertId = Number(runtimeSettings.dataset.alertCursor || 0);
    const refreshSeconds = Number(runtimeSettings.dataset.refreshInterval || 5);
    const refreshInterval = [3, 5, 10, 30].includes(refreshSeconds)
        ? refreshSeconds * 1000
        : 5000;

    function pollDashboard() {
        fetch(`/api/traffic-stream/?after_id=${lastAlertId}`)
            .then(res => {
                if (!res.ok) throw new Error(`Dashboard polling failed (${res.status})`);
                return res.json();
            })
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
                    data.new_alerts.forEach(alertItem => {
                        lastAlertId = Math.max(lastAlertId, alertItem.id);
                        if (data.sound_alerts) playAlertChime();
                        if (
                            data.desktop_alerts &&
                            'Notification' in window &&
                            Notification.permission === 'granted'
                        ) {
                            new Notification(alertItem.title, {
                                body: alertItem.message,
                                tag: `netguard-alert-${alertItem.id}`
                            });
                        }
                    });
                }
            })
            .catch(error => {
                console.error(error);
            });
    }

    window.setInterval(pollDashboard, refreshInterval);
}

function playAlertChime() {
    const AudioContextClass = window.AudioContext || window.webkitAudioContext;
    if (!AudioContextClass) return;

    try {
        const audioContext = new AudioContextClass();
        const oscillator = audioContext.createOscillator();
        const gain = audioContext.createGain();
        oscillator.frequency.value = 880;
        gain.gain.value = 0.08;
        oscillator.connect(gain);
        gain.connect(audioContext.destination);
        oscillator.addEventListener('ended', () => audioContext.close());
        audioContext.resume()
            .then(() => {
                oscillator.start();
                oscillator.stop(audioContext.currentTime + 0.18);
            })
            .catch(error => {
                console.error('Could not resume audio for the alert chime:', error);
                audioContext.close();
            });
    } catch (error) {
        console.error('Could not play the alert chime:', error);
    }
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
    alert('Live subnet discovery is not configured. The device inventory contains sample data.');
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
