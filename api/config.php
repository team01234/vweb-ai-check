<?php
// V AI CHECK 설정
// API 키 등 비밀값은 config.local.php 에 넣는다 (git 제외)

// PHP 7.0·7.1 호환 (7.2 부터 있는 상수)
if (!defined('JSON_INVALID_UTF8_SUBSTITUTE')) define('JSON_INVALID_UTF8_SUBSTITUTE', 0);

$AIC = array(
    'api_key'      => '',                    // config.local.php 에서 지정
    'model'        => 'claude-haiku-5-5',
    'daily_limit'  => 30,                    // IP당 1일 진단 횟수 (캐시 응답은 제외)
    'daily_total'  => 1000,                  // 사이트 전체 1일 진단 상한 (API 비용 보호)
    'cache_ttl'    => 86400,                 // 같은 주소 결과 재사용 시간(초)
    'timeout'      => 10,                    // 사이트 요청 1건 제한 시간(초)
    'fetch_budget' => 25,                    // 사이트 요청 전체 제한 시간(초)
    'total_budget' => 55,                    // AI 호출 포함 전체 제한 시간(초)
    'max_html'     => 3 * 1024 * 1024,       // 가져올 HTML 최대 크기
    'user_agent'   => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36',
    'data_dir'     => '',                    // 비워두면 추측하기 어려운 이름으로 자동 지정. 가능하면 웹 루트 밖 경로 권장
    'cors_origins' => array(                 // 다른 도메인(GitHub Pages 등)의 페이지에서 이 API 를 부르도록 허용할 주소. 같은 도메인이면 불필요
        'https://team01234.github.io',
    ),
    'client_ip_header' => '',                // Cloudflare 뒤에 둘 때만 'HTTP_CF_CONNECTING_IP'
);

if (is_file(__DIR__ . '/config.local.php')) {
    include __DIR__ . '/config.local.php';
}

if ($AIC['data_dir'] === '') {
    // API 키·경로로 만든 이름 (키가 비밀이라 추측 불가. 키를 바꾸면 폴더가 바뀌어 횟수·캐시가 초기화됨)
    $AIC['data_dir'] = __DIR__ . '/_data_' . substr(hash('sha256', 'aic|' . $AIC['api_key'] . '|' . __DIR__), 0, 16);
}
