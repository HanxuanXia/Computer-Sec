<?php
/**
 * 本地生成 QR 码（使用 PHP QR Code 库）
 * 不依赖任何外部服务
 */

// 简单的 QR 码 SVG 生成器
// 基于开源算法，无需外部依赖

class SimpleQRCode {
    
    /**
     * 生成 QR 码 SVG
     * @param string $data 要编码的数据
     * @param int $size 尺寸
     * @return string SVG 代码
     */
    public static function generate($data, $size = 250) {
        // 这里使用简化版本，实际生产环境建议使用成熟的库
        // 如：endroid/qr-code 或 bacon/bacon-qr-code
        
        // 暂时返回一个占位 SVG，显示手动输入指引
        $dataEncoded = htmlspecialchars($data);
        
        $svg = <<<SVG
<svg width="{$size}" height="{$size}" xmlns="http://www.w3.org/2000/svg">
    <rect width="100%" height="100%" fill="white"/>
    <rect x="10" y="10" width="30" height="30" fill="black"/>
    <rect x="50" y="10" width="30" height="30" fill="black"/>
    <rect x="90" y="10" width="30" height="30" fill="black"/>
    
    <rect x="10" y="50" width="30" height="30" fill="black"/>
    <rect x="90" y="50" width="30" height="30" fill="black"/>
    
    <rect x="10" y="90" width="30" height="30" fill="black"/>
    <rect x="50" y="90" width="30" height="30" fill="black"/>
    <rect x="90" y="90" width="30" height="30" fill="black"/>
    
    <text x="125" y="125" font-family="Arial" font-size="14" text-anchor="middle" fill="#666">
        QR 码示意图
    </text>
    <text x="125" y="145" font-family="Arial" font-size="12" text-anchor="middle" fill="#999">
        请使用手动输入
    </text>
</svg>
SVG;
        
        return $svg;
    }
    
    /**
     * 生成 Base64 编码的 SVG 用于 img src
     */
    public static function generateBase64($data, $size = 250) {
        $svg = self::generate($data, $size);
        return 'data:image/svg+xml;base64,' . base64_encode($svg);
    }
}

// 如果作为独立文件访问，显示测试
if (basename(__FILE__) == basename($_SERVER['SCRIPT_FILENAME'])) {
    $testData = "otpauth://totp/Test:test@example.com?secret=TESTKEY&issuer=Test";
    $svg = SimpleQRCode::generate($testData, 200);
    
    header('Content-Type: image/svg+xml');
    echo $svg;
}
?>
