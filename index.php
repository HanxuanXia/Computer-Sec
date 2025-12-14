<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Welcome - Lovejoy's Antique Evaluation</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        
        .container {
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            padding: 50px;
            max-width: 600px;
            width: 100%;
            text-align: center;
        }
        
        .logo {
            font-size: 64px;
            margin-bottom: 20px;
        }
        
        h1 {
            color: #333;
            font-size: 36px;
            margin-bottom: 10px;
        }
        
        .tagline {
            color: #666;
            font-size: 18px;
            margin-bottom: 40px;
        }
        
        .features {
            text-align: left;
            margin-bottom: 40px;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 10px;
        }
        
        .features h3 {
            color: #333;
            margin-bottom: 15px;
        }
        
        .features ul {
            list-style: none;
            padding: 0;
        }
        
        .features li {
            padding: 8px 0;
            color: #666;
            padding-left: 25px;
            position: relative;
        }
        
        .features li:before {
            content: "✓";
            position: absolute;
            left: 0;
            color: #27ae60;
            font-weight: bold;
        }
        
        .btn-group {
            display: flex;
            gap: 15px;
            justify-content: center;
        }
        
        .btn {
            padding: 15px 35px;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            text-decoration: none;
            transition: transform 0.2s;
            display: inline-block;
        }
        
        .btn-primary {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }
        
        .btn-secondary {
            background: white;
            color: #667eea;
            border: 2px solid #667eea;
        }
        
        .btn:hover {
            transform: translateY(-3px);
        }
        
        .security-badge {
            margin-top: 30px;
            padding: 15px;
            background: #e8f5e9;
            border: 1px solid #4caf50;
            border-radius: 8px;
            font-size: 14px;
            color: #2e7d32;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">🏺</div>
        <h1>Lovejoy's Antiques</h1>
        <p class="tagline">Professional Antique Evaluation Services</p>
        
        <div class="features">
            <h3>Why Choose Us?</h3>
            <ul>
                <li>Expert evaluation by certified professionals</li>
                <li>Secure online submission process</li>
                <li>Fast turnaround time</li>
                <li>Detailed appraisal reports</li>
                <li>Confidential and secure</li>
            </ul>
        </div>
        
        <div class="btn-group">
            <a href="login.php" class="btn btn-primary">Login</a>
            <a href="register.php" class="btn btn-secondary">Register</a>
        </div>
        
        <div class="security-badge">
            <strong>🔒 Enterprise-Grade Security</strong><br>
            Your data is protected with industry-leading security measures
        </div>
    </div>
</body>
</html>
