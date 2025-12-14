<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>reCAPTCHA 检查</title>
    <script src="https://www.google.com/recaptcha/api.js" async defer></script>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 50px auto;
            padding: 20px;
            background: #f5f5f5;
        }
        .box {
            background: white;
            padding: 30px;
            margin: 20px 0;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .status { padding: 10px; margin: 10px 0; border-radius: 5px; }
        .success { background: #d4edda; color: #155724; }
        .error { background: #f8d7da; color: #721c24; }
        .warning { background: #fff3cd; color: #856404; }
    </style>
</head>
<body>
    <div class="box">
        <h1>🔍 reCAPTCHA 完整检查</h1>
        
        <h3>步骤 1: 检查网络连接</h3>
        <div id="network-status" class="status warning">⏳ 检查中...</div>
        
        <h3>步骤 2: 检查 Google API</h3>
        <div id="api-status" class="status warning">⏳ 等待...</div>
        
        <h3>步骤 3: 显示 reCAPTCHA</h3>
        <div style="background: #e3f2fd; padding: 20px; border-radius: 8px; margin: 20px 0;">
            <p style="margin-bottom: 15px; font-weight: bold;">reCAPTCHA 应该显示在下面：</p>
            <div class="g-recaptcha" data-sitekey="6LdfeiQsAAAAAKlnBsLN1HccnQolZcnVBbG0Q4Jj"></div>
        </div>
        
        <h3>诊断信息：</h3>
        <pre id="diagnostics" style="background: #f4f4f4; padding: 15px; border-radius: 5px; overflow-x: auto;"></pre>
    </div>
    
    <script>
        let diagnostics = '';
        
        function log(message) {
            diagnostics += message + '\n';
            document.getElementById('diagnostics').textContent = diagnostics;
        }
        
        // Check 1: Network
        log('🔍 开始检查...');
        log('浏览器: ' + navigator.userAgent);
        log('时间: ' + new Date().toLocaleString());
        
        fetch('https://www.google.com/recaptcha/api.js')
            .then(response => {
                document.getElementById('network-status').className = 'status success';
                document.getElementById('network-status').textContent = '✅ 网络正常 - 可以访问 Google';
                log('✅ 网络连接正常');
            })
            .catch(error => {
                document.getElementById('network-status').className = 'status error';
                document.getElementById('network-status').textContent = '❌ 网络错误 - 无法访问 Google！';
                log('❌ 网络错误: ' + error);
            });
        
        // Check 2: Google API
        let checkCount = 0;
        const maxChecks = 50; // 5 seconds
        
        const apiCheck = setInterval(function() {
            checkCount++;
            
            if (typeof grecaptcha !== 'undefined') {
                clearInterval(apiCheck);
                document.getElementById('api-status').className = 'status success';
                document.getElementById('api-status').textContent = '✅ Google reCAPTCHA API 已加载';
                log('✅ grecaptcha 对象已加载');
                log('✅ API 版本: ' + (grecaptcha.enterprise ? 'Enterprise' : 'Standard'));
                
                // Check if widget rendered
                setTimeout(function() {
                    const recaptchaFrame = document.querySelector('iframe[src*="recaptcha"]');
                    if (recaptchaFrame) {
                        log('✅ reCAPTCHA iframe 已创建');
                        log('✅ 复选框应该可见！');
                    } else {
                        log('⚠️ 未找到 reCAPTCHA iframe');
                    }
                }, 2000);
                
            } else if (checkCount >= maxChecks) {
                clearInterval(apiCheck);
                document.getElementById('api-status').className = 'status error';
                document.getElementById('api-status').textContent = '❌ Google API 加载超时';
                log('❌ grecaptcha 对象未加载（超时 5 秒）');
                log('可能原因:');
                log('  1. 广告拦截器阻止了 Google 脚本');
                log('  2. 防火墙阻止了 Google 域名');
                log('  3. 网络问题');
                log('  4. 在中国大陆可能需要 VPN');
            }
        }, 100);
        
        // Additional checks
        window.addEventListener('load', function() {
            log('✅ 页面完全加载');
        });
        
        // Check for ad blockers
        const testAd = document.createElement('div');
        testAd.className = 'ad banner-ad';
        testAd.style.position = 'absolute';
        testAd.style.top = '-1px';
        document.body.appendChild(testAd);
        
        setTimeout(function() {
            if (testAd.offsetHeight === 0) {
                log('⚠️ 检测到广告拦截器！这可能会阻止 reCAPTCHA');
            } else {
                log('✅ 未检测到广告拦截器');
            }
            testAd.remove();
        }, 1000);
    </script>
</body>
</html>
