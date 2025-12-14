<?php
// Prevent directory listing
http_response_code(403);
header('HTTP/1.0 403 Forbidden');
exit('Access Denied');
