/**
 * SIMPLE TAB SESSION CHECK
 * Forces re-login when opening new tabs
 * 
 * HOW IT WORKS:
 * - sessionStorage is cleared when tab closes
 * - Each protected page checks for 'isLoggedIn' flag
 * - New tab = empty sessionStorage = redirect to login
 */

(function() {
    'use strict';
    
    // Check if this is a protected page
    const protectedPages = [
        'dashboard.php',
        'request_evaluation.php',
        'my_requests.php',
        'admin_requests.php',
        'user_management.php',
        'system_reports.php',
        'profile.php'
    ];
    
    const currentPage = window.location.pathname.split('/').pop();
    
    if (protectedPages.includes(currentPage)) {
        // Check if user has logged in this tab
        const isLoggedIn = sessionStorage.getItem('tab_logged_in');
        
        if (!isLoggedIn) {
            // New tab detected - require re-login
            console.log('New tab detected - redirecting to login');
            window.location.href = 'login.php?reason=new_tab';
        } else {
            // Validate session with server periodically
            validateSessionPeriodically();
        }
    }
    
    /**
     * Validate session with server every 30 seconds
     */
    function validateSessionPeriodically() {
        setInterval(function() {
            fetch('validate_session.php')
                .then(response => response.json())
                .then(data => {
                    if (!data.valid) {
                        sessionStorage.clear();
                        window.location.href = 'login.php?reason=session_expired';
                    }
                })
                .catch(error => {
                    console.error('Session validation failed:', error);
                });
        }, 30000); // Check every 30 seconds
    }
    
    /**
     * Clear session on tab close
     */
    window.addEventListener('beforeunload', function() {
        // Optional: Notify server to logout
        // Uncomment the next line if you want to force logout on tab close
        // navigator.sendBeacon('logout.php?auto=true');
    });
    
})();
