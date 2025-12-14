<!-- Tab Session Security -->
<script>
/**
 * Enhanced tab security - only blocks NEW tabs, not same tab navigation
 * This script checks sessionStorage which is cleared when tab closes
 * Also prevents back button bypass after logout
 */
(function() {
    'use strict';
    
    // Only run on protected pages
    const currentPage = window.location.pathname.split('/').pop();
    const protectedPages = [
        'dashboard.php',
        'request_evaluation.php',
        'my_requests.php', 
        'admin_requests.php',
        'user_management.php',
        'system_reports.php'
    ];
    
    if (protectedPages.includes(currentPage)) {
        // Check if user just logged in (from login page or 2FA verification)
        const referrer = document.referrer;
        const fromLoginPage = referrer.includes('login.php');
        const from2FAPage = referrer.includes('verify_2fa.php');
        const fromSetup2FA = referrer.includes('setup_2fa.php');
        
        // If coming from login or 2FA page, set the flag
        if (fromLoginPage || from2FAPage || fromSetup2FA) {
            sessionStorage.setItem('tab_logged_in', 'true');
            sessionStorage.setItem('login_time', Date.now());
            console.log('✅ Login/2FA detected - tab session established');
        }
        
        // Prevent page from being cached (stops back button bypass)
        window.addEventListener('pageshow', function(event) {
            if (event.persisted) {
                // Page was loaded from cache (back button used)
                console.log('⚠️ Page loaded from cache - checking session...');
                checkTabSession();
            }
        });
        
        // Initial check on page load
        checkTabSession();
        
        function checkTabSession() {
            // Check if this tab has logged in
            const tabLoggedIn = sessionStorage.getItem('tab_logged_in');
            
            if (!tabLoggedIn) {
                // New tab without login - destroy session on server
                console.log('🔒 New tab detected - destroying session...');
                
                // Clear sessionStorage immediately
                sessionStorage.clear();
                
                // Destroy server session via fetch (silent)
                fetch('logout_new_tab.php', {
                    method: 'POST',
                    credentials: 'same-origin'
                }).catch(err => console.error('Logout failed:', err));
                
                // Prevent back button from working
                window.history.pushState(null, '', window.location.href);
                window.onpopstate = function() {
                    window.history.pushState(null, '', window.location.href);
                };
                
                // Show alert and redirect (using replace to prevent back button)
                alert('For security reasons, please log in again when opening a new tab.');
                window.location.replace('login.php?reason=new_tab');
            } else {
                // Tab is logged in - set up session validation
                console.log('✅ Tab session valid');
                
                // Periodic check (every 60 seconds)
                if (!window._sessionCheckInterval) {
                    window._sessionCheckInterval = setInterval(function() {
                        fetch('validate_session.php')
                            .then(r => r.json())
                            .then(data => {
                                if (!data.valid) {
                                    sessionStorage.clear();
                                    window.location.replace('login.php?reason=session_expired');
                                }
                            })
                            .catch(err => console.error('Session check failed:', err));
                    }, 60000);
                }
            }
        }
    }
})();
</script>
