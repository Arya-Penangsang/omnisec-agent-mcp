<?php
/**
 * Universal Cyber & Caveman Token-Saving MCP Server
 * Standard Model Context Protocol (MCP) JSON-RPC 2.0 over Stdio
 * Runs on Office PC (PRESERVASI-BPMN) with PHP 8.5.12
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

    $reqHeaders = array('User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) UniversalCyberMCP/2.0 (Office-PC)');
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
// DENSE OUTPUT FORMATTER (TOKEN SAVER)
// -----------------------------------------------------------------------------
function formatAuditOutput($audit, $level) {
    if ($level === 'off') {
        return json_encode($audit, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    }

    // Ultra Mode (Max 35-50 tokens)
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

    // Full Mode (Telegraphic, ~80 tokens)
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

    // Lite Mode (~140 tokens)
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
        'executor' => 'Office PC (PRESERVASI-BPMN)',
        'red_team_probes' => array(),
        'blue_team_checks' => array(),
        'summary' => array()
    );

    // 1. Root Check
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
                    'name' => 'universal-cyber-cave-mcp',
                    'version' => '2.0.0'
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
            )
        );
        echo json_encode(array('jsonrpc' => '2.0', 'id' => $id, 'result' => array('resources' => $resources))) . "\n";
        flush();
    } elseif ($method === 'resources/read') {
        $rParams = isset($req['params']) ? $req['params'] : array();
        $uri = isset($rParams['uri']) ? $rParams['uri'] : '';
        $text = ($uri === 'resource://skills/cave') ? getCaveSystemPrompt('full') : "PURPLE TEAM TRIAD RUNBOOK:\n1. Threat Emulation (T1595, T1190, T1083)\n2. Defense Verification (Headers, Cookies, WAF)\n3. Remediation Tuning.";
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
