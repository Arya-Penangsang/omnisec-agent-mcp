<?php
/**
 * OmniSec Agent MCP Server (Universal Cyber & Caveman Token Optimizer)
 * Standard Model Context Protocol (MCP) JSON-RPC 2.0 over Stdio
 * 
 * Capabilities:
 * - Token Optimization: Caveman Mode (lite, full, ultra, off)
 * - Purple Teaming: WAF / Triad audit (Red probes + Blue checks), threat emulation, defense validation
 * - Malware Triage: Static PE32/PE32+ analysis, Shannon entropy, packer detection, suspicious API detection
 * - Digital Forensics: USB history triage (USBSTOR registry), Windows Event Log triage (wevtutil)
 * 
 * Multi-Platform: Windows (Office PC / Local), Linux, macOS
 * Zero-dependency: Pure PHP standard library (cURL optional for network probes)
 */

error_reporting(0);
ini_set('display_errors', '0');

if (function_exists('ob_implicit_flush')) {
    ob_implicit_flush(true);
}

// Global state for Cave Mode
$currentCaveLevel = 'full'; // 'lite' | 'full' | 'ultra' | 'off'

// -----------------------------------------------------------------------------
// UNIVERSAL CAVE INSTRUCTIONS (Model-Agnostic)
// -----------------------------------------------------------------------------
function getCaveSystemPrompt($level = 'full') {
    return "[CAVEMAN TOKEN OPTIMIZATION MODE: $level]\n" .
        "Goal: Preserve output tokens and prevent context bloat without losing technical accuracy.\n" .
        "- Strict Negative Constraints: No greetings (Halo, Hi), no compliments (Great question), no re-stating user prompts, no outro/closing filler (Semoga membantu, Let me know).\n" .
        "- Preserve 100% exactness: code, file paths, commands, IPs, hashes, CVEs, numbers.\n" .
        "- Level lite: Plain short sentences, zero filler.\n" .
        "- Level full (default): Short telegraphic sentences/fragments. Direct answer first.\n" .
        "- Level ultra: Bare minimum keywords, symbols (->), one-liners where possible.\n" .
        "- Safety exception: Use complete clear sentences only for destructive actions or critical safety warnings.";
}

// -----------------------------------------------------------------------------
// MITRE ATT&CK WEB KNOWLEDGE BASE
// -----------------------------------------------------------------------------
$mitreDb = array(
    'T1595' => array(
        'name' => 'Active Scanning',
        'tactic' => 'Reconnaissance',
        'description' => 'Probing and port scanning web endpoints, seeking open files, dotfiles, and technology stack info.',
        'red_scenario' => 'Requesting /.env, /.git/HEAD, /phpinfo.php, /config.json, /actuator/env to detect information leaks.',
        'blue_mitigation' => 'Deny access to all hidden files and directories (^/\.) in Web Server configuration; remove debug endpoints.',
        'sigma_rule' => "title: Web Dotfile Access Attempt\nstatus: stable\nlogsource:\n  category: webserver\ndetection:\n  selection:\n    cs-method: 'GET'\n    cs-uri-stem|contains:\n      - '/.env'\n      - '/.git'\n  condition: selection"
    ),
    'T1190' => array(
        'name' => 'Exploit Public-Facing Application',
        'tactic' => 'Initial Access',
        'description' => 'Exploiting input validation flaws such as SQL Injection (SQLi) and Reflected/Stored Cross-Site Scripting (XSS).',
        'red_scenario' => "Injecting `' OR 1=1--` into input fields or `<script>alert(1)</script>` into query parameters.",
        'blue_mitigation' => 'Use Prepared Statements (PDO) for all SQL queries; apply strict HTML escaping and Content-Security-Policy (CSP).',
        'sigma_rule' => "title: Potential Web Application Injection\nstatus: stable\nlogsource:\n  category: webserver\ndetection:\n  selection:\n    cs-uri-query|contains:\n      - 'union select'\n      - '<script>'\n  condition: selection"
    ),
    'T1110' => array(
        'name' => 'Brute Force / Password Guessing',
        'tactic' => 'Credential Access',
        'description' => 'Automated attempts to guess passwords on administrative and user authentication forms.',
        'red_scenario' => 'Sending bursts of POST login attempts to /login or /api/auth without delay.',
        'blue_mitigation' => 'Enforce IP rate limiting (HTTP 429 Too Many Requests), account lockout policies, and CAPTCHA / 2FA.',
        'sigma_rule' => "title: High Rate Login Attempts\nstatus: stable\nlogsource:\n  category: webserver\ndetection:\n  selection:\n    cs-method: 'POST'\n    cs-uri-stem|endswith: '/login'\n  timeframe: 1m\n  condition: selection | count() > 10"
    ),
    'T1505.003' => array(
        'name' => 'Web Shell Drop',
        'tactic' => 'Persistence',
        'description' => 'Uploading and executing arbitrary server-side code (PHP, ASPX, JSP) within web-accessible upload directories.',
        'red_scenario' => 'Uploading files with executable extensions or polyglot files into /uploads.',
        'blue_mitigation' => 'Store uploads outside webroot or disable script execution in upload folders via .htaccess (`php_flag engine off`). Validate real MIME type.',
        'sigma_rule' => "title: Web Shell Execution in Uploads Directory\nstatus: stable\nlogsource:\n  category: process_creation\ndetection:\n  selection:\n    CommandLine|contains: '/uploads/'\n  condition: selection"
    ),
    'T1036' => array(
        'name' => 'Masquerading File Extension',
        'tactic' => 'Defense Evasion',
        'description' => 'Bypassing upload filters using double extensions (e.g., shell.php.jpg) or null bytes.',
        'red_scenario' => 'Submitting multipart upload with Content-Type image/jpeg but filename payload.php.png.',
        'blue_mitigation' => 'Re-encode images (e.g. imagecreatefromjpeg), strip original filename, and assign random UUID filename with hardcoded extension.',
        'sigma_rule' => "title: Double Extension Upload Detected\nstatus: stable\nlogsource:\n  category: webserver\ndetection:\n  selection:\n    cs-uri-stem|re: '.*\.(php|phtml|phar)\.(jpg|png|gif)$'\n  condition: selection"
    ),
    'T1083' => array(
        'name' => 'File and Directory Discovery',
        'tactic' => 'Discovery',
        'description' => 'Scanning for unindexed directories, backup archives (.zip, .tar.gz, .sql), and database dumps.',
        'red_scenario' => 'Brute forcing paths: /backup.sql, /db_dump.sql, /www.zip, /admin/backup/.',
        'blue_mitigation' => 'Disable directory browsing (`Options -Indexes`), configure web server to forbid downloads of .sql, .bak, .swp, .old files.',
        'sigma_rule' => "title: Sensitive Backup File Discovery\nstatus: stable\nlogsource:\n  category: webserver\ndetection:\n  selection:\n    cs-uri-stem|endswith:\n      - '.sql'\n      - '.bak'\n      - '.tar.gz'\n  condition: selection"
    )
);

// -----------------------------------------------------------------------------
// HELPER: HTTP PROBE VIA CURL
// -----------------------------------------------------------------------------
function sendHttpProbe($url, $method = 'GET', $headers = array(), $postData = null, $timeout = 6) {
    if (!preg_match('/^https?:\/\//i', $url)) {
        return array('code' => 0, 'headers' => array(), 'body' => '', 'error' => 'Blocked protocol: Only HTTP/HTTPS permitted (SSRF guard)');
    }
    if (preg_match('/169\.254\.169\.254|metadata\.google\.internal/i', $url)) {
        return array('code' => 0, 'headers' => array(), 'body' => '', 'error' => 'Access to cloud instance metadata service is blocked (SSRF guard)');
    }

    if (!function_exists('curl_init')) {
        return array('code' => 0, 'headers' => array(), 'body' => '', 'error' => 'cURL extension is not installed');
    }

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HEADER, true);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
    curl_setopt($ch, CURLOPT_TIMEOUT, $timeout);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);

    $reqHeaders = array('User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) OmniSecAgentMCP/2.0');
    foreach ($headers as $h) {
        $reqHeaders[] = $h;
    }
    curl_setopt($ch, CURLOPT_HTTPHEADER, $reqHeaders);

    if ($postData !== null) {
        curl_setopt($ch, CURLOPT_POSTFIELDS, $postData);
    }

    $raw = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
    $err = curl_error($ch);
    curl_close($ch);

    if ($raw === false) {
        return array('code' => 0, 'headers' => array(), 'body' => '', 'error' => $err);
    }

    $headerStr = substr($raw, 0, $headerSize);
    $body = substr($raw, $headerSize);
    $parsedHeaders = array();
    $rawCookies = array();

    $lines = explode("\r\n", $headerStr);
    foreach ($lines as $line) {
        if (strpos($line, ':') !== false) {
            $parts = explode(':', $line, 2);
            $key = strtolower(trim($parts[0]));
            $val = trim($parts[1]);
            if ($key === 'set-cookie') {
                $rawCookies[] = $val;
            } else {
                $parsedHeaders[$key] = $val;
            }
        }
    }
    if (!empty($rawCookies)) {
        $parsedHeaders['set-cookie'] = $rawCookies;
    }

    return array('code' => $httpCode, 'headers' => $parsedHeaders, 'body' => $body, 'error' => null);
}

// -----------------------------------------------------------------------------
// HELPER: SHANNON ENTROPY CALCULATION
// -----------------------------------------------------------------------------
function calculateEntropy($data) {
    $len = strlen($data);
    if ($len === 0) return 0.0;
    $counts = count_chars($data, 1);
    $entropy = 0.0;
    foreach ($counts as $count) {
        $p = $count / $len;
        $entropy -= $p * log($p, 2);
    }
    return round($entropy, 4);
}

// -----------------------------------------------------------------------------
// DENSE FORMATTERS (TOKEN SAVERS)
// -----------------------------------------------------------------------------
function formatAuditOutput($audit, $level) {
    if ($level === 'off') {
        return json_encode($audit, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    }

    if ($level === 'ultra') {
        $defended = 0;
        foreach ($audit['red_team_probes'] as $p) {
            if ($p['status'] === 'DEFENDED') $defended++;
        }
        $missing = array();
        foreach ($audit['blue_team_checks'] as $k => $c) {
            if (!$c['configured']) {
                $missing[] = ($k === 'banner_disclosure' ? 'BannerLeak' : $k);
            }
        }
        return "TARGET: {$audit['target_url']} | SCORE: {$audit['summary']['overall_score']} ({$audit['summary']['posture']}) | RED: {$defended}/" . count($audit['red_team_probes']) . " DEFENDED | MISSING: " . implode(',', $missing);
    }

    if ($level === 'full') {
        $lines = array();
        $lines[] = "Target: {$audit['target_url']}";
        $lines[] = "Score: {$audit['summary']['overall_score']} (Posture: {$audit['summary']['posture']})";
        
        $probes = array();
        foreach ($audit['red_team_probes'] as $name => $p) {
            $probes[] = "{$name}: {$p['status']} ({$p['http_status']})";
        }
        $lines[] = "Red Probes: " . implode(' | ', $probes);

        $missing = array();
        foreach ($audit['blue_team_checks'] as $k => $c) {
            if (!$c['configured']) $missing[] = $k;
        }
        $lines[] = "Missing Defense: " . implode(', ', $missing);
        $lines[] = "Action: Apply mod_headers in .htaccess (CSP, X-Frame, HSTS, ServerSignature Off)";
        return implode("\n", $lines);
    }

    $lines = array();
    $lines[] = "Audit for {$audit['target_url']} completed.";
    $lines[] = "Overall security score is {$audit['summary']['overall_score']} ({$audit['summary']['posture']}).";
    $lines[] = "Red Team resistance: {$audit['summary']['red_defense_score']} defended.";
    $lines[] = "Blue Team hardening: {$audit['summary']['blue_hardening_score']} applied.";
    $missing = array();
    foreach ($audit['blue_team_checks'] as $k => $c) {
        if (!$c['configured']) $missing[] = $c['header'];
    }
    $lines[] = "Missing controls: " . implode(', ', $missing) . ".";
    $lines[] = "Priority: Configure HTTP security headers and disable banner leakage in web server.";
    return implode("\n", $lines);
}

function formatPeOutput($info, $level) {
    if (isset($info['error'])) {
        return "ERROR: " . $info['error'];
    }

    if ($level === 'off') {
        return json_encode($info, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    }

    if ($level === 'ultra') {
        $suspStr = empty($info['suspicious_indicators']) ? 'None' : implode(',', array_slice($info['suspicious_indicators'], 0, 4));
        return "PE: {$info['file_name']} | {$info['architecture']} | ENTROPY: {$info['overall_entropy']} (Packer: {$info['packer_name']}) | RISK: {$info['risk_classification']} | SUSP: $suspStr";
    }

    if ($level === 'full') {
        $lines = array();
        $lines[] = "File: {$info['file_name']} (" . number_format($info['file_size']) . " bytes)";
        $lines[] = "SHA256: {$info['sha256']}";
        $lines[] = "Arch: {$info['architecture']} | Format: {$info['format']} | Subsystem: {$info['subsystem']}";
        $lines[] = "Entropy: {$info['overall_entropy']} (Packer: {$info['packer_name']})";
        
        $secNames = array();
        foreach ($info['sections'] as $sec) {
            $secNames[] = "{$sec['name']} (ent: {$sec['entropy']})";
        }
        $lines[] = "Sections: " . implode(', ', $secNames);
        
        $susp = empty($info['suspicious_indicators']) ? 'None' : implode(', ', $info['suspicious_indicators']);
        $lines[] = "Suspicious Indicators: $susp";
        $lines[] = "Risk: {$info['risk_classification']}";
        return implode("\n", $lines);
    }

    $lines = array();
    $lines[] = "Portable Executable Analysis for {$info['file_name']}:";
    $lines[] = "- Architecture: {$info['architecture']}, Format: {$info['format']}";
    $lines[] = "- SHA256: {$info['sha256']}";
    $lines[] = "- Shannon Entropy: {$info['overall_entropy']} (Packed/Encrypted: " . ($info['packer_detected'] ? "Yes - {$info['packer_name']}" : "No") . ")";
    $lines[] = "- Detected Sections: " . count($info['sections']);
    $lines[] = "- Suspicious APIs / Strings: " . (empty($info['suspicious_indicators']) ? 'None' : implode(', ', $info['suspicious_indicators']));
    $lines[] = "- Overall Risk Assessment: {$info['risk_classification']}";
    return implode("\n", $lines);
}

function formatUsbOutput($devices, $level) {
    if (isset($devices['error'])) {
        return "ERROR: " . $devices['error'];
    }

    if ($level === 'off') {
        return json_encode($devices, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    }

    $count = count($devices);
    if ($level === 'ultra') {
        if ($count === 0) return "USBSTOR: 0 devices connected.";
        $items = array();
        foreach ($devices as $d) {
            $items[] = "{$d['friendly_name']} (SN: {$d['instance_id']})";
        }
        return "USBSTOR: $count devices | " . implode(' | ', $items);
    }

    if ($level === 'full') {
        if ($count === 0) return "USB History: No removable mass storage devices found in USBSTOR registry.";
        $lines = array();
        $lines[] = "USBSTOR History: $count devices registered";
        foreach ($devices as $idx => $d) {
            $num = $idx + 1;
            $lines[] = "$num. {$d['friendly_name']} [Vendor: {$d['vendor']}, Product: {$d['product']}]";
            $lines[] = "   Instance/Serial: {$d['instance_id']}";
            if (!empty($d['container_id'])) {
                $lines[] = "   ContainerID: {$d['container_id']}";
            }
        }
        return implode("\n", $lines);
    }

    if ($count === 0) return "Digital Forensics Audit: No USB mass storage devices discovered in registry.";
    $lines = array();
    $lines[] = "Digital Forensics Audit - USB Storage Devices ($count found):";
    foreach ($devices as $d) {
        $lines[] = "- Device: {$d['friendly_name']}";
        $lines[] = "  Vendor: {$d['vendor']}, Product: {$d['product']}, Revision: {$d['revision']}";
        $lines[] = "  Serial / Instance ID: {$d['instance_id']}";
    }
    return implode("\n", $lines);
}

function formatLogsOutput($logs, $category, $level) {
    if (isset($logs['error'])) {
        return "ERROR: " . $logs['error'];
    }

    if ($level === 'off') {
        return json_encode($logs, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    }

    $count = count($logs);
    if ($level === 'ultra') {
        if ($count === 0) return "LOGS ($category): 0 events.";
        $items = array();
        foreach ($logs as $evt) {
            $items[] = "EID:{$evt['event_id']} ({$evt['user']}, {$evt['task']})";
        }
        return "LOGS ($category): $count events | " . implode(' | ', array_slice($items, 0, 5));
    }

    if ($level === 'full') {
        if ($count === 0) return "Log Triage ($category): No matching events found.";
        $lines = array();
        $lines[] = "Log Triage ($category, $count events):";
        foreach (array_slice($logs, 0, 10) as $evt) {
            $lines[] = "[{$evt['date']}] EID:{$evt['event_id']} ({$evt['task']}) - User: {$evt['user']}";
            if (!empty($evt['description'])) {
                $lines[] = "  " . substr($evt['description'], 0, 90) . "...";
            }
        }
        return implode("\n", $lines);
    }

    if ($count === 0) return "Log Triage: No events retrieved for category '$category'.";
    $lines = array();
    $lines[] = "Event Log Triage ($category, $count events):";
    foreach ($logs as $evt) {
        $lines[] = "- [{$evt['date']}] Event {$evt['event_id']} ({$evt['level']})";
        $lines[] = "  Computer: {$evt['computer']}, User: {$evt['user']}";
        $lines[] = "  Summary: " . substr($evt['description'], 0, 120);
    }
    return implode("\n", $lines);
}

// -----------------------------------------------------------------------------
// TOOL HANDLERS
// -----------------------------------------------------------------------------
function handleSetCaveMode($args) {
    global $currentCaveLevel;
    $level = isset($args['level']) ? strtolower(trim($args['level'])) : 'full';
    if (!in_array($level, array('lite', 'full', 'ultra', 'off'))) {
        $level = 'full';
    }
    $currentCaveLevel = $level;

    return array(
        'cave_mode' => $currentCaveLevel,
        'status' => "Cave mode set to $currentCaveLevel.",
        'instruction_for_model' => getCaveSystemPrompt($currentCaveLevel)
    );
}

function handleAuditTriad($args) {
    global $mitreDb, $currentCaveLevel;
    $targetUrl = isset($args['target_url']) ? rtrim($args['target_url'], '/') : '';
    if (empty($targetUrl)) {
        return array('error' => 'target_url is required');
    }

    $results = array(
        'target_url' => $targetUrl,
        'timestamp' => date('Y-m-d H:i:s'),
        'executor' => 'OmniSec Agent MCP',
        'red_team_probes' => array(),
        'blue_team_checks' => array(),
        'summary' => array()
    );

    // Root Check
    $root = sendHttpProbe($targetUrl . '/');
    $rootHeaders = $root['headers'];

    $evalProbe = function($probe, $signatureCheck) {
        if ($probe['code'] === 0 && !empty($probe['error'])) {
            return array('status' => 'DEFENDED', 'code' => 'TCP_RESET', 'details' => 'Dropped by Firewall/WAF (' . $probe['error'] . ')');
        }
        if (in_array($probe['code'], array(400, 401, 403, 404, 405, 429, 500, 502, 503))) {
            return array('status' => 'DEFENDED', 'code' => $probe['code'], 'details' => 'Blocked by Web Server (HTTP ' . $probe['code'] . ')');
        }
        if ($probe['code'] === 200 && $signatureCheck($probe['body'])) {
            return array('status' => 'EXPOSED', 'code' => 200, 'details' => 'Sensitive contents readable by public!');
        }
        return array('status' => 'DEFENDED', 'code' => $probe['code'], 'details' => 'Safe default route / sanitized.');
    };

    // RED TEAM PROBES
    // Dotfiles
    $dotProbe = sendHttpProbe($targetUrl . '/.env');
    $dotEval = $evalProbe($dotProbe, function($b) { return (strpos($b, 'APP_') !== false || strpos($b, 'DB_') !== false); });
    $results['red_team_probes']['dotfiles'] = array('technique' => 'T1595', 'http_status' => $dotEval['code'], 'status' => $dotEval['status']);

    // Git Leak
    $gitProbe = sendHttpProbe($targetUrl . '/.git/HEAD');
    $gitEval = $evalProbe($gitProbe, function($b) { return (strpos($b, 'ref:') !== false); });
    $results['red_team_probes']['git_leak'] = array('technique' => 'T1595', 'http_status' => $gitEval['code'], 'status' => $gitEval['status']);

    // Backup
    $bakProbe = sendHttpProbe($targetUrl . '/backup.sql');
    $bakEval = $evalProbe($bakProbe, function($b) { return (stripos($b, 'CREATE TABLE') !== false); });
    $results['red_team_probes']['backup'] = array('technique' => 'T1083', 'http_status' => $bakEval['code'], 'status' => $bakEval['status']);

    // Reflected XSS
    $xssMarker = 'ptxss' . rand(1000, 9999);
    $xssProbe = sendHttpProbe($targetUrl . '/?q=%3Cscript%3E' . $xssMarker . '%3C/script%3E');
    $xssReflected = (strpos($xssProbe['body'], '<script>' . $xssMarker . '</script>') !== false);
    $results['red_team_probes']['xss'] = array('technique' => 'T1190', 'http_status' => $xssProbe['code'], 'status' => $xssReflected ? 'VULNERABLE' : 'DEFENDED');

    // BLUE TEAM CHECKS
    $secHeaders = array(
        'csp' => 'content-security-policy',
        'x_frame' => 'x-frame-options',
        'x_content_type' => 'x-content-type-options',
        'hsts' => 'strict-transport-security',
        'referrer' => 'referrer-policy'
    );
    foreach ($secHeaders as $alias => $hKey) {
        $results['blue_team_checks'][$alias] = array(
            'header' => $hKey,
            'configured' => isset($rootHeaders[$hKey]),
            'value' => isset($rootHeaders[$hKey]) ? $rootHeaders[$hKey] : null
        );
    }

    $hasHttpOnly = false;
    $hasSecure = false;
    if (isset($rootHeaders['set-cookie'])) {
        $cookieArr = is_array($rootHeaders['set-cookie']) ? $rootHeaders['set-cookie'] : array($rootHeaders['set-cookie']);
        foreach ($cookieArr as $cStr) {
            if (stripos($cStr, 'httponly') !== false) $hasHttpOnly = true;
            if (stripos($cStr, 'secure') !== false) $hasSecure = true;
        }
    }
    $results['blue_team_checks']['cookie_httponly'] = array('header' => 'Cookie HttpOnly', 'configured' => $hasHttpOnly);
    $results['blue_team_checks']['cookie_secure'] = array('header' => 'Cookie Secure', 'configured' => $hasSecure);

    $serverHeader = isset($rootHeaders['server']) ? $rootHeaders['server'] : null;
    $results['blue_team_checks']['banner_disclosure'] = array(
        'header' => 'Banner Leakage',
        'configured' => ($serverHeader === null),
        'value' => $serverHeader
    );

    // Scoring
    $passedRed = 0;
    foreach ($results['red_team_probes'] as $r) {
        if ($r['status'] === 'DEFENDED') $passedRed++;
    }
    $redScore = round(($passedRed / count($results['red_team_probes'])) * 100);

    $passedBlue = 0;
    foreach ($results['blue_team_checks'] as $b) {
        if ($b['configured']) $passedBlue++;
    }
    $blueScore = round(($passedBlue / count($results['blue_team_checks'])) * 100);
    $overall = round(($redScore * 0.6) + ($blueScore * 0.4));

    $results['summary'] = array(
        'overall_score' => $overall . '/100',
        'red_defense_score' => $redScore . '%',
        'blue_hardening_score' => $blueScore . '%',
        'posture' => ($overall >= 80) ? 'EXCELLENT' : (($overall >= 50) ? 'MODERATE' : 'CRITICAL_RISK')
    );

    return formatAuditOutput($results, $currentCaveLevel);
}

function handleEmulateThreat($args) {
    global $mitreDb, $currentCaveLevel;
    $targetUrl = isset($args['target_url']) ? rtrim($args['target_url'], '/') : '';
    $techniqueId = isset($args['technique_id']) ? strtoupper(trim($args['technique_id'])) : 'T1595';
    $customPayload = isset($args['custom_payload']) ? $args['custom_payload'] : null;

    if (empty($targetUrl)) return array('error' => 'target_url required');

    $emulationUrl = $targetUrl;
    $method = 'GET';
    $postData = null;

    if ($techniqueId === 'T1595') {
        $emulationUrl .= $customPayload ? $customPayload : '/.env';
    } elseif ($techniqueId === 'T1190') {
        $emulationUrl .= '/?id=' . ($customPayload ? urlencode($customPayload) : '%27%20OR%201=1--');
    } elseif ($techniqueId === 'T1083') {
        $emulationUrl .= $customPayload ? $customPayload : '/backup.sql';
    } elseif ($techniqueId === 'T1110') {
        $method = 'POST';
        $emulationUrl .= '/login';
        $postData = 'username=admin&password=Password123!';
    }

    $probe = sendHttpProbe($emulationUrl, $method, array(), $postData);
    $blocked = in_array($probe['code'], array(401, 403, 404, 429)) || ($probe['code'] === 0 && !empty($probe['error']));

    if ($currentCaveLevel === 'ultra') {
        return "THREAT {$techniqueId} -> " . ($blocked ? "DEFENDED (HTTP {$probe['code']})" : "UNBLOCKED_RISK");
    }
    if ($currentCaveLevel === 'full') {
        return "Technique: {$techniqueId}\nTarget: {$emulationUrl}\nStatus: " . ($blocked ? "BLOCKED/DEFENDED" : "UNBLOCKED") . "\nCode: {$probe['code']}";
    }

    return array(
        'technique' => $techniqueId,
        'url' => $emulationUrl,
        'http_status' => $probe['code'],
        'status' => $blocked ? 'DEFENDED' : 'UNBLOCKED'
    );
}

function handleValidateDefense($args) {
    global $currentCaveLevel;
    $targetUrl = isset($args['target_url']) ? rtrim($args['target_url'], '/') : '';
    if (empty($targetUrl)) return array('error' => 'target_url required');

    $probe = sendHttpProbe($targetUrl . '/');
    $h = $probe['headers'];

    $missing = array();
    if (!isset($h['content-security-policy'])) $missing[] = 'Content-Security-Policy';
    if (!isset($h['x-frame-options'])) $missing[] = 'X-Frame-Options';
    if (!isset($h['x-content-type-options'])) $missing[] = 'X-Content-Type-Options';
    if (!isset($h['strict-transport-security'])) $missing[] = 'Strict-Transport-Security';

    $fixSnippet = "Header set X-Content-Type-Options \"nosniff\"\nHeader set X-Frame-Options \"SAMEORIGIN\"\nHeader set Content-Security-Policy \"default-src 'self';\"\nServerSignature Off";

    if ($currentCaveLevel === 'ultra') {
        return "HTTP: {$probe['code']} | MISSING: " . implode(',', $missing) . " | FIX:\n$fixSnippet";
    }
    if ($currentCaveLevel === 'full') {
        return "Status: HTTP {$probe['code']}\nMissing Headers: " . implode(', ', $missing) . "\nHardening Snippet:\n$fixSnippet";
    }

    return array(
        'target_url' => $targetUrl,
        'status' => $probe['code'],
        'missing_headers' => $missing,
        'hardening_apache' => $fixSnippet
    );
}

function handleApplyFix($args) {
    global $currentCaveLevel;
    $targetType = isset($args['target_type']) ? strtolower(trim($args['target_type'])) : 'apache';
    $filePath = isset($args['file_path']) ? trim($args['file_path']) : '';

    if ($targetType === 'nginx') {
        $snippet = "# OmniSec Nginx Hardening Configuration\n" .
            "add_header X-Content-Type-Options \"nosniff\" always;\n" .
            "add_header X-Frame-Options \"SAMEORIGIN\" always;\n" .
            "add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;\n" .
            "add_header Content-Security-Policy \"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';\" always;\n" .
            "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;\n" .
            "server_tokens off;\n" .
            "location ~ /\\.(env|git|htaccess|htpasswd|ini|log|conf|bak|sql) {\n    deny all;\n    return 404;\n}\n";
    } elseif ($targetType === 'iis') {
        $snippet = "<!-- OmniSec IIS web.config Hardening -->\n" .
            "<configuration>\n  <system.webServer>\n    <httpProtocol>\n      <customHeaders>\n" .
            "        <add name=\"X-Content-Type-Options\" value=\"nosniff\" />\n" .
            "        <add name=\"X-Frame-Options\" value=\"SAMEORIGIN\" />\n" .
            "        <add name=\"Content-Security-Policy\" value=\"default-src 'self';\" />\n" .
            "      </customHeaders>\n    </httpProtocol>\n  </system.webServer>\n</configuration>\n";
    } else {
        $targetType = 'apache';
        $snippet = "# OmniSec Apache .htaccess Hardening Rules\n" .
            "<IfModule mod_headers.c>\n" .
            "    Header always set X-Content-Type-Options \"nosniff\"\n" .
            "    Header always set X-Frame-Options \"SAMEORIGIN\"\n" .
            "    Header always set Referrer-Policy \"strict-origin-when-cross-origin\"\n" .
            "    Header always set Content-Security-Policy \"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';\"\n" .
            "    Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains\"\n" .
            "</IfModule>\n" .
            "ServerSignature Off\n" .
            "<FilesMatch \"^\\.(env|git|htaccess|htpasswd|ini|log|conf|bak|sql)\">\n" .
            "    Order allow,deny\n    Deny from all\n</FilesMatch>\n";
    }

    $written = false;
    $message = "Generated $targetType hardening rules.";
    if (!empty($filePath)) {
        $real = realpath($filePath) ? realpath($filePath) : $filePath;
        $base = strtolower(basename($filePath));
        $allowed = array('.htaccess', 'nginx.conf', 'web.config');
        $isSystem = (stripos($real, 'c:\\windows') === 0 || stripos($real, 'c:\\program files') === 0);

        if (in_array($base, $allowed) && !$isSystem) {
            if (file_exists($filePath)) {
                @copy($filePath, $filePath . '.bak');
            }
            $written = @file_put_contents($filePath, $snippet, FILE_APPEND | LOCK_EX) !== false;
            $message = $written ? "Hardening snippet appended to $filePath (backup created)." : "Failed to write to $filePath.";
        } else {
            $message = "Target file rejected by path security policy (only .htaccess, nginx.conf, web.config allowed).";
        }
    }

    if ($currentCaveLevel === 'ultra') {
        return "FIX: {$targetType} -> " . ($written ? "WRITTEN ({$filePath})" : "SNIPPET_READY");
    }
    if ($currentCaveLevel === 'full') {
        return "Remediation ($targetType):\n$message\nRules:\n$snippet";
    }

    return array(
        'target_type' => $targetType,
        'written' => $written,
        'file_path' => $filePath,
        'snippet' => $snippet,
        'status' => $message
    );
}

// -----------------------------------------------------------------------------
// TOOL HANDLER: MALWARE INSPECT PE
// -----------------------------------------------------------------------------
function handleMalwareInspectPe($args) {
    global $currentCaveLevel;
    $filePath = isset($args['file_path']) ? trim($args['file_path']) : '';
    if (empty($filePath)) {
        return array('error' => 'file_path is required');
    }

    // Expand environment variables (e.g. %SystemRoot%)
    if (preg_match('/%([^%]+)%/', $filePath, $m)) {
        $envVal = getenv($m[1]);
        if ($envVal) {
            $filePath = str_replace($m[0], $envVal, $filePath);
        }
    }

    if (!file_exists($filePath)) {
        return array('error' => "File not found: $filePath");
    }

    $size = filesize($filePath);
    if ($size > 100 * 1024 * 1024) {
        return array('error' => 'File size exceeds 100MB limit for static triage.');
    }
    $fp = fopen($filePath, 'rb');
    if (!$fp) {
        return array('error' => "Cannot open file: $filePath");
    }

    // 1. DOS Header
    $dosHeader = fread($fp, 64);
    if (strlen($dosHeader) < 64 || substr($dosHeader, 0, 2) !== 'MZ') {
        fclose($fp);
        return array('error' => 'Not a valid DOS/MZ executable');
    }

    $e_lfanew = unpack('V', substr($dosHeader, 0x3C, 4))[1];
    if ($e_lfanew >= $size) {
        fclose($fp);
        return array('error' => 'Invalid PE offset (e_lfanew out of bounds)');
    }

    // 2. PE Signature
    fseek($fp, $e_lfanew);
    $peSig = fread($fp, 4);
    if ($peSig !== "PE\0\0") {
        fclose($fp);
        return array('error' => 'Missing PE signature');
    }

    // 3. COFF File Header (20 bytes)
    $coffData = fread($fp, 20);
    $coff = unpack('vMachine/vNumberOfSections/VTimeDateStamp/VPointerToSymbolTable/VNumberOfSymbols/vSizeOfOptionalHeader/vCharacteristics', $coffData);

    $machineNames = array(
        0x014c => 'x86 (32-bit)',
        0x8664 => 'x64 (AMD64)',
        0x01c0 => 'ARM',
        0xaa64 => 'ARM64'
    );
    $arch = isset($machineNames[$coff['Machine']]) ? $machineNames[$coff['Machine']] : sprintf('Unknown (0x%04X)', $coff['Machine']);
    $compileTime = date('Y-m-d H:i:s', $coff['TimeDateStamp']);

    // 4. Optional Header (if present)
    $subsystemName = 'Unknown';
    $entryPoint = 0;
    $optMagic = 0;
    if ($coff['SizeOfOptionalHeader'] > 0) {
        $optData = fread($fp, $coff['SizeOfOptionalHeader']);
        $optMagic = unpack('v', substr($optData, 0, 2))[1];
        if ($optMagic === 0x010b || $optMagic === 0x020b) {
            $entryPoint = unpack('V', substr($optData, 16, 4))[1];
            $subsystem = unpack('v', substr($optData, 68, 2))[1];
            $subsystems = array(
                1 => 'Native/Driver',
                2 => 'Windows GUI',
                3 => 'Windows Console/CUI',
                7 => 'POSIX CUI',
                9 => 'Windows CE GUI'
            );
            $subsystemName = isset($subsystems[$subsystem]) ? $subsystems[$subsystem] : "Subsystem ($subsystem)";
        }
    }

    // 5. Section Headers (each 40 bytes)
    $sections = array();
    $packerDetected = false;
    $packerName = null;
    $packerSignatures = array(
        'UPX' => array('UPX0', 'UPX1', 'UPX2', '.upx'),
        'ASPack' => array('.aspack', '.adata'),
        'PECompact' => array('pec1', 'pec2', 'pecompact'),
        'MPRESS' => array('.mpress1', '.mpress2'),
        'Themida' => array('.themida'),
        'VMProtect' => array('.vmp0', '.vmp1')
    );

    for ($i = 0; $i < $coff['NumberOfSections']; $i++) {
        $secData = fread($fp, 40);
        if (strlen($secData) < 40) break;
        $name = trim(substr($secData, 0, 8), "\0 ");
        $sec = unpack('VVirtualSize/VVirtualAddress/VSizeOfRawData/VPointerToRawData', substr($secData, 8, 16));

        // Calculate entropy of this section
        $secEntropy = 0.0;
        if ($sec['SizeOfRawData'] > 0 && $sec['PointerToRawData'] < $size) {
            $currentPos = ftell($fp);
            fseek($fp, $sec['PointerToRawData']);
            $readLen = min($sec['SizeOfRawData'], 512 * 1024);
            $secBytes = fread($fp, $readLen);
            $secEntropy = calculateEntropy($secBytes);
            fseek($fp, $currentPos);
        }

        // Check packer signatures
        foreach ($packerSignatures as $pName => $patterns) {
            foreach ($patterns as $pat) {
                if (stripos($name, $pat) !== false) {
                    $packerDetected = true;
                    $packerName = $pName;
                }
            }
        }

        $sections[] = array(
            'name' => $name,
            'virtual_size' => $sec['VirtualSize'],
            'raw_size' => $sec['SizeOfRawData'],
            'entropy' => $secEntropy
        );
    }

    // 6. Overall File Entropy
    fseek($fp, 0);
    $sampleData = fread($fp, min($size, 1024 * 1024));
    $overallEntropy = calculateEntropy($sampleData);

    if ($overallEntropy > 7.2 && !$packerDetected) {
        $packerDetected = true;
        $packerName = 'High Entropy (>7.2) - Packed/Encrypted';
    }

    // 7. Suspicious Strings / APIs
    fseek($fp, 0);
    $chunk = fread($fp, min($size, 2 * 1024 * 1024));
    fclose($fp);

    $suspiciousApis = array(
        'VirtualAlloc', 'VirtualProtect', 'WriteProcessMemory', 'CreateRemoteThread',
        'NtUnmapViewOfSection', 'URLDownloadToFile', 'HttpSendRequest', 'InternetOpen',
        'WinExec', 'ShellExecute', 'IsDebuggerPresent', 'CheckRemoteDebuggerPresent',
        'cmd.exe', 'powershell.exe', 'vssadmin.exe'
    );
    $foundApis = array();
    foreach ($suspiciousApis as $api) {
        if (strpos($chunk, $api) !== false) {
            $foundApis[] = $api;
        }
    }

    // Risk Classification
    $risk = 'LOW';
    if ($packerDetected && count($foundApis) >= 2) {
        $risk = 'CRITICAL';
    } elseif ($packerDetected || count($foundApis) >= 3) {
        $risk = 'HIGH';
    } elseif (count($foundApis) > 0 || $overallEntropy > 6.8) {
        $risk = 'MEDIUM';
    }

    $info = array(
        'file_name' => basename($filePath),
        'file_path' => $filePath,
        'file_size' => $size,
        'sha256' => hash_file('sha256', $filePath),
        'md5' => hash_file('md5', $filePath),
        'architecture' => $arch,
        'format' => ($optMagic === 0x020b) ? 'PE32+ (64-bit)' : 'PE32 (32-bit)',
        'compile_timestamp' => $compileTime,
        'subsystem' => $subsystemName,
        'entry_point' => sprintf('0x%08X', $entryPoint),
        'overall_entropy' => $overallEntropy,
        'packer_detected' => $packerDetected,
        'packer_name' => $packerName ? $packerName : 'None',
        'sections' => $sections,
        'suspicious_indicators' => $foundApis,
        'risk_classification' => $risk
    );

    return formatPeOutput($info, $currentCaveLevel);
}

// -----------------------------------------------------------------------------
// TOOL HANDLER: FORENSICS AUDIT USB (USBSTOR Registry)
// -----------------------------------------------------------------------------
function handleForensicsAuditUsb($args) {
    global $currentCaveLevel;
    $includeAllUsb = isset($args['include_all_usb']) ? (bool)$args['include_all_usb'] : false;

    if (PHP_OS_FAMILY !== 'Windows') {
        // Fallback for non-Windows (Linux / macOS)
        if (file_exists('/sys/bus/usb/devices')) {
            $devices = array();
            $dirs = glob('/sys/bus/usb/devices/*');
            foreach ($dirs as $d) {
                if (file_exists("$d/product")) {
                    $prod = trim(file_get_contents("$d/product"));
                    $mfg = file_exists("$d/manufacturer") ? trim(file_get_contents("$d/manufacturer")) : 'Unknown';
                    $serial = file_exists("$d/serial") ? trim(file_get_contents("$d/serial")) : 'N/A';
                    $devices[] = array(
                        'friendly_name' => $prod,
                        'vendor' => $mfg,
                        'product' => $prod,
                        'revision' => 'N/A',
                        'instance_id' => $serial,
                        'container_id' => basename($d)
                    );
                }
            }
            return formatUsbOutput($devices, $currentCaveLevel);
        }
        return array('error' => 'USB registry triage is supported natively on Windows systems.');
    }

    // Windows Native: Query USBSTOR registry
    $regCmd = 'reg query "HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR" /s 2>&1';
    $output = shell_exec($regCmd);

    $devices = array();
    $currentDevice = null;
    $lines = explode("\n", str_replace("\r", "", (string)$output));

    foreach ($lines as $line) {
        $trimmed = trim($line);
        if (empty($trimmed)) continue;

        if (stripos($trimmed, 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR\\') === 0) {
            $parts = explode('\\', $trimmed);
            if (count($parts) >= 7) {
                $devKey = $parts[5];
                $instanceId = $parts[6];
                $idKey = $devKey . '__' . $instanceId;

                if (!isset($devices[$idKey])) {
                    $vendor = 'Unknown';
                    $product = 'Unknown';
                    $revision = 'Unknown';
                    if (preg_match('/Ven_([^_&]+)/i', $devKey, $m)) $vendor = trim($m[1]);
                    if (preg_match('/Prod_([^_&]+)/i', $devKey, $m)) $product = trim($m[1]);
                    if (preg_match('/Rev_([^_&]+)/i', $devKey, $m)) $revision = trim($m[1]);

                    $devices[$idKey] = array(
                        'device_key' => $devKey,
                        'instance_id' => $instanceId,
                        'vendor' => $vendor,
                        'product' => $product,
                        'revision' => $revision,
                        'friendly_name' => 'Generic USB Storage Device',
                        'hardware_id' => null,
                        'container_id' => null,
                        'service' => 'disk'
                    );
                }
                $currentDevice = &$devices[$idKey];
            } else {
                $currentDevice = null;
            }
        } elseif ($currentDevice !== null && (strpos($line, "    ") === 0 || strpos($line, "\t") === 0)) {
            $tokens = preg_split('/\s{2,}|\t+/', trim($line));
            if (count($tokens) >= 3) {
                $valName = $tokens[0];
                $valData = $tokens[2];
                if (strcasecmp($valName, 'FriendlyName') === 0) {
                    $currentDevice['friendly_name'] = $valData;
                } elseif (strcasecmp($valName, 'HardwareID') === 0) {
                    $currentDevice['hardware_id'] = $valData;
                } elseif (strcasecmp($valName, 'ContainerID') === 0) {
                    $currentDevice['container_id'] = $valData;
                } elseif (strcasecmp($valName, 'Service') === 0) {
                    $currentDevice['service'] = $valData;
                }
            }
        }
    }

    return formatUsbOutput(array_values($devices), $currentCaveLevel);
}

// -----------------------------------------------------------------------------
// TOOL HANDLER: FORENSICS TRIAGE LOGS (Windows Event Log)
// -----------------------------------------------------------------------------
function handleForensicsTriageLogs($args) {
    global $currentCaveLevel;
    $category = isset($args['category']) ? strtolower(trim($args['category'])) : 'logon';
    $count = isset($args['count']) ? max(1, min(50, (int)$args['count'])) : 5;

    if (PHP_OS_FAMILY !== 'Windows') {
        return array('error' => 'Windows Event Log triage requires a Windows host with wevtutil.');
    }

    $logName = 'Security';
    $query = '';

    if ($category === 'logon') {
        $logName = 'Security';
        $query = ' /q:"*[System[(EventID=4624 or EventID=4625)]]"';
    } elseif ($category === 'service') {
        $logName = 'System';
        $query = ' /q:"*[System[(EventID=7045 or EventID=7040)]]"';
    } elseif ($category === 'audit_tamper') {
        $logName = 'Security';
        $query = ' /q:"*[System[(EventID=1102)]]"';
    } elseif ($category === 'system') {
        $logName = 'System';
        $query = '';
    } elseif ($category === 'security') {
        $logName = 'Security';
        $query = '';
    } elseif ($category === 'application') {
        $logName = 'Application';
        $query = '';
    }

    $cmd = "wevtutil qe $logName$query /c:$count /rd:true /f:text 2>&1";
    $output = shell_exec($cmd);

    $events = array();
    $currentEvent = null;
    $lines = explode("\n", str_replace("\r", "", (string)$output));

    foreach ($lines as $line) {
        $trimmed = trim($line);
        if (strpos($trimmed, 'Event[') === 0) {
            if ($currentEvent !== null) {
                $events[] = $currentEvent;
            }
            $currentEvent = array(
                'log_name' => $logName,
                'date' => 'Unknown',
                'event_id' => '0',
                'task' => 'N/A',
                'level' => 'Information',
                'user' => 'N/A',
                'computer' => 'N/A',
                'description' => ''
            );
        } elseif ($currentEvent !== null) {
            if (strpos($trimmed, 'Date:') === 0) {
                $currentEvent['date'] = trim(substr($trimmed, 5));
            } elseif (strpos($trimmed, 'Event ID:') === 0) {
                $currentEvent['event_id'] = trim(substr($trimmed, 9));
            } elseif (strpos($trimmed, 'Task:') === 0) {
                $currentEvent['task'] = trim(substr($trimmed, 5));
            } elseif (strpos($trimmed, 'Level:') === 0) {
                $currentEvent['level'] = trim(substr($trimmed, 6));
            } elseif (strpos($trimmed, 'User Name:') === 0) {
                $currentEvent['user'] = trim(substr($trimmed, 10));
            } elseif (strpos($trimmed, 'Account Name:') !== false && $currentEvent['user'] === 'N/A') {
                $parts = explode(':', $trimmed, 2);
                $currentEvent['user'] = trim($parts[1]);
            } elseif (strpos($trimmed, 'Computer:') === 0) {
                $currentEvent['computer'] = trim(substr($trimmed, 9));
            } elseif (strpos($trimmed, 'Description:') === 0) {
                $currentEvent['description'] = trim(substr($trimmed, 12));
            } elseif (!empty($trimmed) && empty($currentEvent['description']) && strpos($trimmed, ':') === false) {
                $currentEvent['description'] = $trimmed;
            }
        }
    }
    if ($currentEvent !== null) {
        $events[] = $currentEvent;
    }

    return formatLogsOutput($events, $category, $currentCaveLevel);
}

// -----------------------------------------------------------------------------
// MCP TOOL DEFINITIONS
// -----------------------------------------------------------------------------
$tools = array(
    array(
        'name' => 'set_cave_mode',
        'description' => 'Ubah gaya respon AI dan output MCP menjadi mode Caveman hemat token (lite / full / ultra / off). Menghemat hingga 80% token output.',
        'inputSchema' => array(
            'type' => 'object',
            'properties' => array(
                'level' => array(
                    'type' => 'string',
                    'enum' => array('lite', 'full', 'ultra', 'off'),
                    'description' => 'full: telegrafik ringkas (default), ultra: simbol/keyword ekstrem, lite: tanpa basa-basi, off: normal JSON'
                )
            ),
            'required' => array('level')
        )
    ),
    array(
        'name' => 'purple_audit_triad',
        'description' => 'Audit triad keamanan menyeluruh (Red probes + Blue checks + scoring) dengan output terkompresi hemat token.',
        'inputSchema' => array(
            'type' => 'object',
            'properties' => array(
                'target_url' => array(
                    'type' => 'string',
                    'description' => 'URL target web (contoh: http://10.0.1.67 atau http://localhost:8080)'
                )
            ),
            'required' => array('target_url')
        )
    ),
    array(
        'name' => 'purple_emulate_threat',
        'description' => 'Simulasi serangan spesifik MITRE ATT&CK (T1595 dotfiles, T1190 injection, T1110 brute force, T1083 backup).',
        'inputSchema' => array(
            'type' => 'object',
            'properties' => array(
                'target_url' => array('type' => 'string'),
                'technique_id' => array('type' => 'string'),
                'custom_payload' => array('type' => 'string')
            ),
            'required' => array('target_url', 'technique_id')
        )
    ),
    array(
        'name' => 'purple_validate_defense',
        'description' => 'Audit pasif HTTP security headers dan dapatkan kode pengerasan server Apache/Nginx.',
        'inputSchema' => array(
            'type' => 'object',
            'properties' => array(
                'target_url' => array('type' => 'string')
            ),
            'required' => array('target_url')
        )
    ),
    array(
        'name' => 'malware_inspect_pe',
        'description' => 'Analisis statis binary PE32/PE32+ (Windows EXE/DLL): arsitektur, Shannon entropy, deteksi packer (UPX, ASPack), suspicious APIs, dan klasifikasi risiko.',
        'inputSchema' => array(
            'type' => 'object',
            'properties' => array(
                'file_path' => array(
                    'type' => 'string',
                    'description' => 'Path absolut ke file binary executable Windows (.exe atau .dll)'
                )
            ),
            'required' => array('file_path')
        )
    ),
    array(
        'name' => 'forensics_audit_usb',
        'description' => 'Triage forensik digital riwayat flashdisk/perangkat penyimpanan eksternal (USBSTOR Registry) pada Windows host.',
        'inputSchema' => array(
            'type' => 'object',
            'properties' => array(
                'include_all_usb' => array(
                    'type' => 'boolean',
                    'description' => 'Sertakan perangkat USB umum selain mass storage (default: false)'
                )
            )
        )
    ),
    array(
        'name' => 'forensics_triage_logs',
        'description' => 'Triage cepat Windows Event Log (Security / System / Application) menggunakan wevtutil untuk investigasi insiden DFIR.',
        'inputSchema' => array(
            'type' => 'object',
            'properties' => array(
                'category' => array(
                    'type' => 'string',
                    'enum' => array('logon', 'service', 'audit_tamper', 'security', 'system', 'application'),
                    'description' => 'Kategori log: logon (EID 4624/4625), service (EID 7045), audit_tamper (EID 1102)'
                ),
                'count' => array(
                    'type' => 'integer',
                    'description' => 'Jumlah log terbaru yang diambil (default: 5, max: 50)'
                )
            ),
            'required' => array('category')
        )
    ),
    array(
        'name' => 'purple_apply_fix',
        'description' => 'Terapkan atau dapatkan snippet kode pengerasan WAF/Server 1-klik (.htaccess / Nginx / IIS) untuk mengamankan host target.',
        'inputSchema' => array(
            'type' => 'object',
            'properties' => array(
                'target_type' => array(
                    'type' => 'string',
                    'enum' => array('apache', 'nginx', 'iis'),
                    'description' => 'Jenis web server (default: apache)'
                ),
                'file_path' => array(
                    'type' => 'string',
                    'description' => 'Path file tujuan untuk langsung menulis aturan (opsional, misal: .htaccess)'
                )
            )
        )
    )
);

// -----------------------------------------------------------------------------
// MAIN JSON-RPC 2.0 LOOP
// -----------------------------------------------------------------------------
$stdin = fopen('php://stdin', 'r');

while ($line = fgets($stdin)) {
    $line = trim($line);
    if ($line === '') continue;

    $req = json_decode($line, true);
    if (!$req || !isset($req['method'])) continue;

    $id = isset($req['id']) ? $req['id'] : null;
    $method = $req['method'];

    if ($method === 'initialize') {
        $res = array(
            'jsonrpc' => '2.0',
            'id' => $id,
            'result' => array(
                'protocolVersion' => '2024-11-05',
                'capabilities' => array(
                    'tools' => new stdClass(),
                    'prompts' => new stdClass(),
                    'resources' => new stdClass()
                ),
                'serverInfo' => array(
                    'name' => 'omnisec-agent-mcp',
                    'version' => '2.1.0'
                )
            )
        );
        echo json_encode($res) . "\n";
        flush();
    } elseif ($method === 'notifications/initialized') {
        // Notification, no reply
    } elseif ($method === 'ping') {
        echo json_encode(array('jsonrpc' => '2.0', 'id' => $id, 'result' => new stdClass())) . "\n";
        flush();
    } elseif ($method === 'tools/list') {
        echo json_encode(array('jsonrpc' => '2.0', 'id' => $id, 'result' => array('tools' => $tools))) . "\n";
        flush();
    } elseif ($method === 'prompts/list') {
        $prompts = array(
            array(
                'name' => 'cave_mode',
                'description' => 'Aktifkan gaya respons Caveman hemat token untuk menghemat token output hingga 80%.',
                'arguments' => array(
                    array('name' => 'level', 'description' => 'lite, full, atau ultra', 'required' => false)
                )
            )
        );
        echo json_encode(array('jsonrpc' => '2.0', 'id' => $id, 'result' => array('prompts' => $prompts))) . "\n";
        flush();
    } elseif ($method === 'prompts/get') {
        $pParams = isset($req['params']) ? $req['params'] : array();
        $pLevel = isset($pParams['arguments']['level']) ? $pParams['arguments']['level'] : 'full';
        $res = array(
            'jsonrpc' => '2.0',
            'id' => $id,
            'result' => array(
                'description' => 'Caveman Mode System Prompt',
                'messages' => array(
                    array(
                        'role' => 'user',
                        'content' => array(
                            'type' => 'text',
                            'text' => getCaveSystemPrompt($pLevel)
                        )
                    )
                )
            )
        );
        echo json_encode($res) . "\n";
        flush();
    } elseif ($method === 'resources/list') {
        $resources = array(
            array(
                'uri' => 'resource://skills/cave',
                'name' => 'Universal Cave Skill Guide',
                'mimeType' => 'text/markdown',
                'description' => 'Panduan lengkap dan aturan mode respons hemat token Caveman.'
            ),
            array(
                'uri' => 'resource://skills/purple-team',
                'name' => 'Purple Team Triad Assessment Runbook',
                'mimeType' => 'text/markdown',
                'description' => 'Panduan metodologi audit Red + Blue + Purple Triad.'
            ),
            array(
                'uri' => 'resource://skills/malware-triage',
                'name' => 'Malware Triage PE & Entropy Runbook',
                'mimeType' => 'text/markdown',
                'description' => 'Panduan analisis statis PE header, Shannon entropy, dan packer detection.'
            ),
            array(
                'uri' => 'resource://skills/digital-forensics',
                'name' => 'Digital Forensics Incident Response Runbook',
                'mimeType' => 'text/markdown',
                'description' => 'Panduan forensik USBSTOR registry dan triage event log Windows.'
            )
        );
        echo json_encode(array('jsonrpc' => '2.0', 'id' => $id, 'result' => array('resources' => $resources))) . "\n";
        flush();
    } elseif ($method === 'resources/read') {
        $rParams = isset($req['params']) ? $req['params'] : array();
        $uri = isset($rParams['uri']) ? $rParams['uri'] : '';
        $text = '';
        if ($uri === 'resource://skills/cave') {
            $text = getCaveSystemPrompt('full');
        } elseif ($uri === 'resource://skills/purple-team') {
            $text = "PURPLE TEAM TRIAD RUNBOOK:\n1. Threat Emulation (T1595, T1190, T1083)\n2. Defense Verification (Headers, Cookies, WAF)\n3. Remediation Tuning.";
        } elseif ($uri === 'resource://skills/malware-triage') {
            $text = "MALWARE TRIAGE RUNBOOK:\n1. Static PE header inspection (MZ, PE, COFF)\n2. Shannon entropy analysis (>7.2 = packed/encrypted)\n3. Packer identification (UPX, ASPack, Themida)\n4. Suspicious API imports extraction.";
        } elseif ($uri === 'resource://skills/digital-forensics') {
            $text = "DIGITAL FORENSICS RUNBOOK:\n1. USBSTOR registry triage for removable media audit\n2. Security Event Log analysis (EID 4624/4625 logons, EID 7045 new service)\n3. Timeline MACB reconstruction.";
        } else {
            $text = "Resource not found: $uri";
        }
        echo json_encode(array(
            'jsonrpc' => '2.0',
            'id' => $id,
            'result' => array(
                'contents' => array(
                    array('uri' => $uri, 'mimeType' => 'text/markdown', 'text' => $text)
                )
            )
        )) . "\n";
        flush();
    } elseif ($method === 'tools/call') {
        $params = isset($req['params']) ? $req['params'] : array();
        $name = isset($params['name']) ? $params['name'] : '';
        $arguments = isset($params['arguments']) ? $params['arguments'] : array();

        $toolResult = null;
        if ($name === 'set_cave_mode') {
            $toolResult = handleSetCaveMode($arguments);
        } elseif ($name === 'purple_audit_triad') {
            $toolResult = handleAuditTriad($arguments);
        } elseif ($name === 'purple_emulate_threat') {
            $toolResult = handleEmulateThreat($arguments);
        } elseif ($name === 'purple_validate_defense') {
            $toolResult = handleValidateDefense($arguments);
        } elseif ($name === 'malware_inspect_pe') {
            $toolResult = handleMalwareInspectPe($arguments);
        } elseif ($name === 'forensics_audit_usb') {
            $toolResult = handleForensicsAuditUsb($arguments);
        } elseif ($name === 'forensics_triage_logs') {
            $toolResult = handleForensicsTriageLogs($arguments);
        } elseif ($name === 'purple_apply_fix') {
            $toolResult = handleApplyFix($arguments);
        } else {
            $toolResult = array('error' => 'Unknown tool: ' . $name);
        }

        $formattedText = is_string($toolResult) ? $toolResult : json_encode($toolResult, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

        echo json_encode(array(
            'jsonrpc' => '2.0',
            'id' => $id,
            'result' => array(
                'content' => array(
                    array('type' => 'text', 'text' => $formattedText)
                ),
                'isError' => isset($toolResult['error'])
            )
        )) . "\n";
        flush();
    }
}

fclose($stdin);
