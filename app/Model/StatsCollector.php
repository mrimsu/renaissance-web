<?php

// i'm sorry i ai coded this

declare(strict_types=1);

namespace App\Model;

use Nette\Http\Client;

class StatsCollector
{
    private string $baseUrl;
    private string $outputFile;

    public function __construct(string $mrimRestApiUrl) {
        $this->baseUrl = rtrim($mrimRestApiUrl, '/');
        $this->outputFile = __DIR__ . '/../../log/statistics.json';
    }

    public function run(): void
    {
        $context = stream_context_create([
            'http' => [
                'timeout' => 5,
            ]
        ]);

        $url = $this->baseUrl . '/users/online';

        $response = file_get_contents($url, false, $context);
        if ($response === false) {
            throw new \RuntimeException("Server is offline");
        }

        $json = json_decode($response, true);

        if (!$json || !isset($json['users'])) {
            throw new \RuntimeException('Invalid or missing data from server');
        }

        $stats = $this->collect($json);
        file_put_contents($this->outputFile, json_encode($stats, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
    }

    private function collect(array $users): array
    {
        $clientNames = [
            'magent'      => 'Agent Mail.ru для Windows',
            'macagent'    => 'Agent Mail.ru для Mac',
            'jagent'      => 'Agent Mail.ru для Java',
            'webagent'    => 'Веб-Агент',
            'android'     => 'Мобильный Агент для Android',
            'iphoneagent' => 'Мобильный Агент для iPhone',
            'sagent'      => 'Мобильный Агент для Symbian',
            'wpagent'     => 'Мобильный Агент для Windows Phone'
        ];

        $stats = ["count" => $users['count']];

        $stats['clients'] = [];

        foreach ($users['users'] as $u) {
            $ua = $u['userAgent'];

            preg_match('/client="([^"]+)"/', $ua, $mClient);
            preg_match('/version="([0-9\.\(\) a-zA-Z]+)"/', $ua, $mVer);

            $client = $mClient[1] ?? 'Неизвестный клиент';
            $version = $mVer[1] ?? 'неизвестна';

            preg_match('/build="([0-9]+)"/', $ua, $mBuild);
            $build = $mBuild[1] ?? null;

            $verKey = $version;

            if ($build != null) {
                $verKey = $verKey . ' (сборка ' . $build . ')';
            }

            $prettyClient = $clientNames[$client] ?? $client;

            $clientFullName = $prettyClient . ', версия ' . $verKey;

            $arrayIndex = array_search($clientFullName, array_column($stats['clients'], 'name'));

            if ($arrayIndex === false) {
                array_push($stats['clients'], ["name" => $clientFullName, "count" => 0]);
                $arrayIndex = array_key_last($stats['clients']);
            }

            $stats['clients'][$arrayIndex]['count']++;
        }

        return $stats;
    }
}
