<?php
// V AI CHECK 진단 API
//   POST url=홈페이지주소  →  JSON
//   CLI 테스트: php check.php https://example.com

// PHP 경고 문구가 JSON 응답에 섞이지 않도록 화면 출력은 끄고 로그로만 남긴다
@ini_set('display_errors', '0');

require __DIR__ . '/config.php';
require __DIR__ . '/aic_lib.php';

// 허용한 도메인의 페이지에서만 호출 가능 (config.php 의 cors_origins)
if (PHP_SAPI !== 'cli') {
    $origin = isset($_SERVER['HTTP_ORIGIN']) ? $_SERVER['HTTP_ORIGIN'] : '';
    if ($origin !== '' && in_array($origin, $AIC['cors_origins'], true)) {
        header('Access-Control-Allow-Origin: ' . $origin);
        header('Vary: Origin');
        header('Access-Control-Allow-Methods: POST, OPTIONS');
        header('Access-Control-Allow-Headers: Content-Type');
    }
    if (isset($_SERVER['REQUEST_METHOD']) && $_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
        http_response_code(204);
        exit;
    }
}

@set_time_limit(90);
$is_cli = PHP_SAPI === 'cli';
$started = microtime(true);
$AIC['deadline'] = $started + $AIC['fetch_budget'];
$AIC['deadline_all'] = $started + $AIC['total_budget'];

function aic_out($data)
{
    global $is_cli;
    if (!$is_cli) header('Content-Type: application/json; charset=utf-8');
    $flags = JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE | ($is_cli ? JSON_PRETTY_PRINT : 0);
    echo json_encode($data, $flags);
    exit;
}

function aic_dir($sub)
{
    global $AIC;
    $root = $AIC['data_dir'];
    if (!is_dir($root)) @mkdir($root, 0755, true);
    // 기록·캐시 파일 외부 접근 차단 (Apache)
    if (!is_file($root . '/.htaccess')) {
        @file_put_contents($root . '/.htaccess', "Require all denied\n<IfModule !mod_authz_core.c>\nDeny from all\n</IfModule>\n");
        @file_put_contents($root . '/index.html', '');
    }
    $d = $root . '/' . $sub;
    if (!is_dir($d)) @mkdir($d, 0755, true);
    return $d;
}

// 파일 카운터를 잠금 상태에서 1 올린다. 상한에 도달했으면 false
function aic_take($file, $limit)
{
    $fh = @fopen($file, 'c+');
    if (!$fh) return false;   // 기록을 못 하면 제한도 못 지키므로 막는다
    flock($fh, LOCK_EX);
    $n = (int)stream_get_contents($fh);
    $ok = $n < $limit;
    if ($ok) {
        ftruncate($fh, 0);
        rewind($fh);
        fwrite($fh, (string)($n + 1));
        fflush($fh);
    }
    flock($fh, LOCK_UN);
    fclose($fh);
    return $ok;
}

// IPv6 는 /48 단위로 묶어서 센다 (VPS 하나가 /48 을 통째로 받는 경우가 있어 /64 로는 우회 가능)
function aic_client_key($ip)
{
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
        $bin = inet_pton($ip);
        return 'v6_' . bin2hex(substr($bin, 0, 6));
    }
    return 'v4_' . $ip;
}

if ($is_cli) {
    $input = isset($argv[1]) ? $argv[1] : '';
    $ip = 'cli';
} else {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        http_response_code(405);
        aic_out(array('ok' => false, 'code' => 'method', 'message' => 'POST 로 요청해주세요.'));
    }
    $input = isset($_POST['url']) && is_string($_POST['url']) ? $_POST['url'] : '';
    $ip = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '';
    // Cloudflare 등 프록시 뒤에 둘 때만 설정 (그 외에는 위조 가능하므로 비워둠)
    $h = $AIC['client_ip_header'];
    if ($h !== '' && !empty($_SERVER[$h]) && filter_var($_SERVER[$h], FILTER_VALIDATE_IP)) $ip = $_SERVER[$h];
}

$url = aic_normalize_url($input);
if (!$url) aic_out(array('ok' => false, 'code' => 'invalid', 'message' => '홈페이지 주소를 정확히 입력해주세요.'));
$try_http = !preg_match('#^https?://#i', trim($input));

// 캐시 (같은 주소는 하루 동안 같은 결과)
$cache_file = aic_dir('cache') . '/' . md5('v3|' . $url) . '.json';   // v2: AI 의견(review) 추가, v3: 서브페이지 포함 채점
if (is_file($cache_file) && filemtime($cache_file) > time() - $AIC['cache_ttl']) {
    $cached = json_decode(file_get_contents($cache_file), true);
    if (is_array($cached)) {
        $cached['cached'] = true;
        aic_out($cached);
    }
}

// 1일 횟수 제한 (IP별 + 사이트 전체)
if (!$is_cli) {
    $rate = aic_dir('rate');
    if (!is_dir($rate) || !is_writable($rate)) {
        error_log('[AI CHECK] 기록 폴더에 쓸 수 없습니다: ' . $rate);
        aic_out(array('ok' => false, 'code' => 'server', 'message' => '일시적으로 진단을 이용할 수 없습니다. 상담을 신청하시면 직접 진단해드립니다.'));
    }
    $client = md5(aic_client_key($ip));
    // 같은 IP 의 동시 진단은 1건만 (느린 사이트로 서버 작업자를 붙잡아두는 것 방지)
    $lock = @fopen($rate . '/run_' . $client . '.lock', 'c');
    if (!$lock || !flock($lock, LOCK_EX | LOCK_NB)) {
        aic_out(array('ok' => false, 'code' => 'running', 'message' => '이미 진단이 진행 중입니다. 잠시 후 다시 시도해주세요.'));
    }
    if (!aic_take($rate . '/' . date('Ymd') . '_' . $client . '.txt', $AIC['daily_limit'])) {
        aic_out(array('ok' => false, 'code' => 'rate_limited', 'message' => '오늘 진단 가능 횟수를 모두 사용했습니다. 내일 다시 이용해주세요.'));
    }
}

$result = aic_diagnose($url, $AIC, $try_http);
if (!$result['ok']) aic_out($result);

// 사이트 전체 상한은 AI 호출(비용 발생) 직전에만 차감. 넘으면 점수는 그대로 주고 AI 문구만 기본 문구로
$ai_allowed = $is_cli || aic_take(aic_dir('rate') . '/' . date('Ymd') . '_all.txt', $AIC['daily_total']);
$ai = $ai_allowed && aic_ai_write($result, $AIC);
if (!$ai_allowed) $result['_ai_error'] = 'daily_total';
if (!$ai) $result['suggest'] = aic_fallback_suggest($result['_site']['brand']);
$result['ai'] = $ai;
$result['cached'] = false;

// 진단 기록 (영업 참고용)
$log = array(date('Y-m-d H:i:s'), $ip, $url, $result['total'], $ai ? 'ai' : 'no-ai',
    isset($result['_usage']['input_tokens']) ? $result['_usage']['input_tokens'] : '',
    isset($result['_usage']['output_tokens']) ? $result['_usage']['output_tokens'] : '',
    isset($result['_ai_error']) ? $result['_ai_error'] : '',
    round(microtime(true) - $started, 1),
    isset($result['_review_downgraded']) ? $result['_review_downgraded'] : '');
@file_put_contents(aic_dir('log') . '/' . date('Y-m') . '.csv', implode(',', array_map(function ($v) {
    return '"' . str_replace('"', '""', (string)$v) . '"';
}, $log)) . "\n", FILE_APPEND | LOCK_EX);

if ($is_cli && isset($result['_ai_error'])) fwrite(STDERR, 'AI: ' . $result['_ai_error'] . "\n");
unset($result['_site'], $result['_usage'], $result['_ai_error'], $result['_review_downgraded']);

// AI 실패 결과는 캐시하지 않음 (다음 요청에서 다시 시도)
if ($ai) @file_put_contents($cache_file, json_encode($result, JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE), LOCK_EX);
aic_out($result);
