<?php

/**
 * Created by Flexbe Team.
 * Author: Sergiets Dmitry
 * Email: sergietsdmitry@gmail.com
 * Date: 7/16/2018
 * Time: 10:01 AM
 */

namespace Sergiets\LescriptWildcard\Src\Client;

use Sergiets\LescriptWildcard\Src\Client\ClientInterface;

class Client implements ClientInterface
{
    private $lastCode;
    private $lastHeader;

    private $base;

    private $last_nounce = null;

    public function __construct($base)
    {
        $this->base = $base;
    }

    public function getBase()
    {
        return $this->base;
    }

    private function curl($method, $url, $data = null)
    {
        $headers = [
            'Accept: application/json',
            'Content-Type: application/jose+json'
        ];

        $handle  = curl_init();

        curl_setopt($handle, CURLOPT_URL, preg_match('~^http~', $url) ? $url : $this->base . $url);
        curl_setopt($handle, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($handle, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($handle, CURLOPT_HEADER, true);
        // curl_setopt($handle, CURLOPT_VERBOSE, true);

        switch ($method)
        {
            case 'GET':
                break;
            case 'POST':
                curl_setopt($handle, CURLOPT_POST, true);
                curl_setopt($handle, CURLOPT_POSTFIELDS, $data);
                break;
        }

        $response = curl_exec($handle);

        //d($response);

        if (curl_errno($handle))
        {
            throw new \RuntimeException('Curl: ' . curl_error($handle));
        }

        $header_size = curl_getinfo($handle, CURLINFO_HEADER_SIZE);

        $header = substr($response, 0, $header_size);
        $body   = substr($response, $header_size);

        $this->lastHeader = $header;
        $this->lastCode   = curl_getinfo($handle, CURLINFO_HTTP_CODE);

        if (preg_match('~Replay\-Nonce: (.+)~i', $this->lastHeader, $matches))
        {
            $this->last_nounce = trim($matches[1]);
        }

        $data = json_decode($body, true);

        return $data === null ? $body : $data;
    }

    public function post($url, $data)
    {
        return $this->curl('POST', $url, $data);
    }

    public function get($url)
    {
        return $this->curl('GET', $url);
    }

    public function getLastNonce()
    {
        if (preg_match('~Replay\-Nonce: (.+)~i', $this->lastHeader, $matches))
        {
            $this->last_nounce = trim($matches[1]);

            return $this->last_nounce;
        }

        return $this->last_nounce;
    }

    public function getLastLocation()
    {
        if (preg_match('~Location: (.+)~i', $this->lastHeader, $matches))
        {
            return trim($matches[1]);
        }

        return null;
    }

    public function getLastCode()
    {
        return $this->lastCode;
    }

    public function getLastLinks()
    {
        preg_match_all('~Link: <(.+)>;rel="up"~', $this->lastHeader, $matches);

        return $matches[1];
    }
}