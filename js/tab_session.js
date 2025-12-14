/**
 * TAB MANAGEMENT - Session Invalidation on Tab Close
 * 
 * This JavaScript ensures that when a user closes the tab or opens a new tab,
 * they will need to re-login.
 */

// Use sessionStorage (cleared when tab closes) instead of localStorage
// This ensures data is only valid for the current tab

/**
 * Initialize Tab Session
 * Creates a unique identifier for this tab
 */
function initTabSession() {
    // Generate unique tab ID if not exists
    if (!sessionStorage.getItem('tabId')) {
        const tabId = generateRandomId();
        sessionStorage.setItem('tabId', tabId);
        sessionStorage.setItem('loginTime', Date.now().toString());
        
        // Send tab ID to server
        sendTabIdToServer(tabId);
    }
    
    // Check if this is a new tab (sessionStorage is empty = new tab)
    if (!sessionStorage.getItem('isLoggedIn')) {
        // New tab detected - require login
        if (isOnProtectedPage()) {
            redirectToLogin();
        }
    } else {
        // Validate session is still active
        validateSession();
    }
}

/**
 * Generate Random ID
 * Creates a unique identifier for the tab
 */
function generateRandomId() {
    return 'tab_' + Math.random().toString(36).substr(2, 9) + '_' + Date.now();
}

/**
 * Check if current page is protected
 */
function isOnProtectedPage() {
    const protectedPages = [
        'dashboard.php',
        'request_evaluation.php',
        'my_requests.php',
        'admin_requests.php',
        'user_management.php',
        'system_reports.php'
    ];
    
    const currentPage = window.location.pathname.split('/').pop();
    return protectedPages.includes(currentPage);
}

/**
 * Redirect to login page
 */
function redirectToLogin() {
    window.location.href = 'login.php?error=session_expired';
}

/**
 * Send Tab ID to Server
 * Validates with server-side session
 */
function sendTabIdToServer(tabId) {
    fetch('validate_session.php', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ tabId: tabId })
    })
    .then(response => response.json())
    .then(data => {
        if (data.valid) {
            sessionStorage.setItem('isLoggedIn', 'true');
        } else {
            redirectToLogin();
        }
    })
    .catch(error => {
        console.error('Session validation error:', error);
    });
}

/**
 * Validate Session
 * Checks if session is still valid with server
 */
function validateSession() {
    fetch('validate_session.php?action=check', {
        method: 'GET',
        credentials: 'same-origin'
    })
    .then(response => response.json())
    .then(data => {
        if (!data.valid) {
            sessionStorage.clear();
            redirectToLogin();
        }
    })
    .catch(error => {
        console.error('Session validation error:', error);
    });
}

/**
 * Handle Tab Close/Refresh
 * Optionally invalidate session on close
 */
window.addEventListener('beforeunload', function(e) {
    // Option 1: Clear sessionStorage (automatic on close anyway)
    // sessionStorage.clear();
    
    // Option 2: Notify server to invalidate session
    // This ensures even if user uses back button, they must re-login
    navigator.sendBeacon('logout.php?auto=true');
});

/**
 * Handle Page Visibility
 * Check session when tab becomes visible again
 */
document.addEventListener('visibilitychange', function() {
    if (!document.hidden && isOnProtectedPage()) {
        validateSession();
    }
});

/**
 * Periodic Session Check
 * Check session every 60 seconds
 */
setInterval(function() {
    if (isOnProtectedPage() && sessionStorage.getItem('isLoggedIn')) {
        validateSession();
    }
}, 60000); // Check every 60 seconds

// Initialize when page loads
document.addEventListener('DOMContentLoaded', function() {
    initTabSession();
});

/**
 * Mark login successful
 * Call this after successful login
 */
function markLoginSuccessful() {
    sessionStorage.setItem('isLoggedIn', 'true');
    sessionStorage.setItem('loginTime', Date.now().toString());
}

// Export for use in login page
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { markLoginSuccessful };
}
