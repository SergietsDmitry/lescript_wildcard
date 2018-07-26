<?php

namespace Sergiets\LescriptWildcard;

use Psr\Log\LoggerInterface;
use Sergiets\LescriptWildcard\Src\Client\Client;
use Sergiets\LescriptWildcard\Src\Client\ClientInterface;
use Sergiets\LescriptWildcard\Src\Base64UrlSafeEncoder;
use Sergiets\LescriptWildcard\Src\Processors\DnsProcessorInterface;
use Sergiets\LescriptWildcard\Src\Processors\BaseDnsProcessor;
use Sergiets\LescriptWildcard\Src\Definition\WildcardDefinition;

class WildcardLibrary implements WildcardDefinition
{
    public $ca = 'https://acme-v02.api.letsencrypt.org';
    //public $ca = 'https://acme-staging-v02.api.letsencrypt.org'; // testing

    public $suffix = '_acme2';
    //public $suffix = '_acme2_test'; // testing

    public $contact     = []; // optional
    //public $contact = array("mailto:cert-admin@example.com", "tel:+12025551212")

    public $supported_challenges_ordered_by_priority = [];

    private $certificatesDir;
    private $webRootDir;

    /** @var \Psr\Log\LoggerInterface */
    private $logger;
    private $client;
    private $dnsProcessor;
    private $accountKeyPath;
    private $accountIdPath;

    private $first_post = true;
    private $account_id = 0;

    private $basename = null;

    /**
     * WildcardLibrary constructor.
     *
     * @param $certificatesDir
     * @param $webRootDir
     * @param DnsProcessorInterface|null $dns_processor
     * @param LoggerInterface|null $logger
     * @param ClientInterface|null $client
     */
    public function __construct(
        $certificatesDir,
        $webRootDir,
        DnsProcessorInterface $dns_processor = null,
        LoggerInterface $logger = null,
        ClientInterface $client = null
    )
    {
        $this->certificatesDir = $certificatesDir;
        $this->webRootDir      = $webRootDir;
        $this->logger          = $logger;
        $this->client          = $client ? $client : new Client($this->ca);
        $this->accountKeyPath  = $certificatesDir . '/' . $this->suffix . '_account/private.pem';
        $this->accountIdPath   = $certificatesDir . '/' . $this->suffix . '_account/account_id.txt';
        $this->dnsProcessor    = !is_null($dns_processor) ? $dns_processor : new BaseDnsProcessor();

        $this->supported_challenges_ordered_by_priority = [
            $this::CHALLENGE_TYPE_HTTP,
            $this::CHALLENGE_TYPE_DNS
        ];
    }

    /**
     * Get base name
     *
     * @param array $domains
     *
     * @return null|string
     */
    public function getBaseName($domains = [])
    {
        if (!is_null($this->basename) || count($domains) == 0)
        {
            return $this->basename ?? '';
        }

        $this->basename = current(array_filter($domains, function($element)
        {
            if (substr($element, 0, 2) == '*.')
            {
                return $element;
            }
        }));

        $this->basename = (!$this->basename)
            ? reset($domains)
            : $this->basename;
    }

    /**
     * Request sertificate
     *
     * @param array $domains
     * @param boolean $reuse_csr
     *
     * @return bool
     */
    public function requestSertificate($domains, $reuse_csr = false)
    {
        $this->getBaseName($domains);

        $is_account_key_exist = is_file($this->accountKeyPath);
        $is_account_id_exist  = is_file($this->accountIdPath);
        $this->account_id     = intval($is_account_id_exist ? @file_get_contents($this->accountIdPath) : 0);

        // Check account registration
        if (!$is_account_key_exist || !$is_account_id_exist || $this->account_id <= 0)
        {
            // generate and save new private key for account
            $this->generateKey(dirname($this->accountKeyPath));

            // Register account
            $account = $this->registerAccount();

            if ($this->account_id > 0)
            {
                $this->saveAccountId($this->accountIdPath, $this->account_id);
            }
        }
        else
        {
            $this->log('Account already registered. Continuing.');
        }

        // Order certificate for domain name
        $order = $this->orderCertificate($domains);

        $this->processOrder($order, $domains, $reuse_csr);

        return true;
    }

    /**
     * Save account id
     *
     * @param $account_id_path
     * @param $account_id
     */
    private function saveAccountId($account_id_path, $account_id)
    {
        $outputDirectory = dirname($account_id_path);

        if (!is_dir($outputDirectory))
        {
            @mkdir($outputDirectory, 0700, true);
        }

        if (!is_dir($outputDirectory))
        {
            throw new \RuntimeException("Cant't create directory $outputDirectory");
        }

        @unlink($account_id_path);

        file_put_contents($account_id_path, $account_id);
    }

    /**
     * Register account
     *
     * @return array|bool|mixed|string
     */
    private function registerAccount()
    {
        $this->log('>>> Starting new account registration.');

        $payload = [
            "termsOfServiceAgreed" => true
        ];

        if (!$this->contact)
        {
            $payload['contact'] = $this->contact;
        }

        $result = $this->signedRequest("/acme/new-acct", $payload, 201);

        if ($result && isset($result['id']) && isset($result['status']) && $result['status'] == 'valid')
        {
            $this->account_id = $result['id'];

            $this->log('New account certificate registered.');

            return $result;
        }

        $this->log('Can\'t register new account.');

        throw new \RuntimeException('Can\'t register new account. Result: '
                                    . print_r([
                'payload' => $payload ?? null,
                'result'  => $result ?? null
            ], 1)
        );
    }

    /**
     * Order certificate
     *
     * @param array $domains
     *
     * @return array|bool
     */
    private function orderCertificate(array $domains)
    {
        $this->log('>>> Ordering certificate for ' . $this->getBaseName() . '.');

        $identifiers = [];

        foreach($domains as $domain)
        {
            array_push($identifiers, [
                "type" => "dns",
                "value" => $domain
            ]);
        }

        $result = $this->signedRequest("/acme/new-order", [
            'identifiers' => $identifiers
        ], 201);

        if (!$result || !isset($result["status"]) || !isset($result["finalize"])
            || !isset($result["identifiers"])
            || !isset($result["authorizations"]))
        {
            throw new \RuntimeException(
                'Data:' . print_r([
                    'result' => $result ?? null
                ], 1)
            );
        }

        if ($result["status"] == "processing")
        {
            $this->log('The server is still processing the previous request: '
                       . str_replace("/finalize-order", "", $result["finalize"]) . '.'
            );

            throw new \RuntimeException(
                'The server is still processing the previous request. Data:' . print_r([
                    'result' => $result ?? null
                ], 1)
            );

            // throw new \RuntimeException('The server is still processing the previous request: '
            //     . str_replace("/finalize-order", "", $result["finalize"]) . '.');
        }

        foreach ($result["identifiers"] as $i => $identifier)
        {
            list(, , , , , $authorization) = explode("/", $result["authorizations"][$i], 6);
            $result["identifiers"][$i]["authorization"] = $authorization;
        }

        return [
            "identifiers" => $result["identifiers"],
            "finalize"    => $result["finalize"]
        ];
    }

    /**
     * Authorize host
     *
     * @param array $challenge
     * @param array $identifier
     *
     * @return bool
     */
    public function authorizeHost($challenge, $identifier)
    {
        $path = "/acme/challenge/" . $challenge["challenge"];

        $payload = [
            "keyAuthorization" => $challenge["key"]
        ];

        if (($result = $this->signedRequest($path, $payload)) == false)
        {
            $this->log('Error authorizing host ' . $identifier["value"] . '.');

            throw new \RuntimeException('Error authorizing host ' . $identifier["value"] . '. Data: '
                                        . print_r([
                    'path'    => $path,
                    'payload' => $payload,
                    'result'  => $result
                ], 1)
            );
        }

        return true;
    }

    /**
     * Poll authorization is valid
     *
     * @param array $order
     *
     * @return bool
     */
    public function authorizationValid($order, $type = null)
    {
        $path = "/acme/authz/" . $order["authorization"];

        if (($result = $this->client->get($path)) === false)
        {
            return [
                'is_success' => false,
                'result'     => $result
            ];
        }

        foreach ($result["challenges"] as $challenge)
        {
            if (is_null($type) && $challenge["type"] != $type)
            {
                continue;
            }

            if ($challenge["status"] == "valid")
            {
                return [
                    'is_success' => true
                ];
            }

            if (empty($challenge['status']) || $challenge['status'] == "invalid")
            {
                throw new \RuntimeException("Verification ended with error: " . json_encode($challenge));
            }
        }

        return [
            'is_success' => false,
            'result'     => $result
        ];
    }

    /**
     * Finalize
     *
     * @param array $order
     * @param string $csr
     *
     * @return array|bool
     */
    public function finalizeOrder($order, $csr)
    {
        $path = $this->getPath($order['finalize']);

        $payload = [
            'csr' => Base64UrlSafeEncoder::encode($csr)
        ];

        if (($result = $this->signedRequest($path, $payload, 200)) == false)
        {
            $this->log('Error finalizing order. Signed request error.');

            throw new \RuntimeException('Error finalizing order. Signed request error. Data: '
                                        . print_r([
                    'path'    => $path ?? null,
                    'payload' => $payload ?? null,
                    'result'  => $result ?? null
                ], 1)
            );
        }

        return [
            "status"   => $result["status"],
            "location" => $this->getPath($this->client->getLastLocation()),
            "download" => $this->getPath($result["certificate"])
        ];
    }

    /**
     * Get path part from URI
     *
     * @param string $uri
     *
     * @return bool|string
     */
    private function getPath($uri)
    {
        list( , , $hostname, $path) = explode("/", $uri, 4);

        $base = $this->client->getBase();

        $clear_hostname = str_replace([
            'https://',
            'http://'
        ], '', trim($base));

        if ($hostname != $clear_hostname)
        {
            $this->log('Hostname ' . $clear_hostname . ' in URL does not match.');

            throw new \RuntimeException('Error finalizing order. Signed request error. Data: '
                                        . print_r([
                    'uri'            => $uri ?? null,
                    'base'           => $base ?? null,
                    'clear_hostname' => $clear_hostname ?? null,
                    'hostname'       => $hostname,
                    'path'           => $path ?? null
                ], 1)
            );
        }

        return "/" . $path;
    }

    /**
     * Poll certificate is ready
     *
     * @param string $path
     *
     * @return bool
     */
    public function certificateReady($path)
    {
        if (($result = $this->client->get($path)) === false)
        {
            return [
                'is_success' => false,
                'result'     => $result
            ];
        }

        if (($result["status"] ?? false) != "valid")
        {
            return [
                'is_success' => false,
                'result'     => $result
            ];
        }

        return [
            'is_success' => true
        ];
    }

    /**
     * Get certificate
     *
     * @param string $certificate
     *
     * @return array|bool|mixed|string
     */
    public function getCertificate($certificate)
    {
        if (($result = $this->client->get($certificate)) == false)
        {
            $this->log('Error downloading certificate.');

            throw new \RuntimeException('Error downloading certificate.. Result: '
                                        . print_r([
                    'result' => $result ?? null
                ], 1)
            );
        }

        return $result;
    }

    /**
     * Process order
     *
     * @param array $order
     * @param array $domains
     * @param boolean $reuse_csr
     *
     * @return bool|string
     */
    private function processOrder($order, $domains, $reuse_csr)
    {
        if (!isset($order['identifiers']) || !is_array($order['identifiers']))
        {
            $this->log('Can\'t find identifiers in Order.');

            throw new \RuntimeException('Can\'t find identifiers in Order. Data: '
                                        . print_r([
                    'order' => $order ?? null
                ], 1)
            );
        }

        $directory = $this->webRootDir . '/.well-known/acme-challenge';

        $i = 0;

        foreach ($order["identifiers"] as $identifier)
        {
            /* Get authorization challenge
             */
            $this->log('>>> Getting authorization challenge for ' . $identifier["value"] . '.');

            $challenge = $this->getChallenge($identifier);

            try
            {
                switch ($challenge['type'])
                {
                    case $this::CHALLENGE_TYPE_HTTP:

                        $tokenPath = $directory . '/' . $challenge['token'];

                        if (!file_exists($directory) && !@mkdir($directory, 0755, true))
                        {
                            $this->log('Couldn\'t create directory to expose challenge: ' . $tokenPath . '.');

                            throw new \RuntimeException('Couldn\'t create directory to expose challenge: ' . $tokenPath . '. Data: '
                                                        . print_r([
                                    'directory' => $directory ?? null,
                                    'tokenPath' => $tokenPath ?? null
                                ], 1)
                            );
                        }

                        file_put_contents($tokenPath, $challenge['key']);

                        chmod($tokenPath, 0644);

                        $uri = 'http://' . str_replace('*.', '', $identifier['value']) . '/.well-known/acme-challenge/' . $challenge['token'];

                        $this->log('Token for ' . str_replace('*.', '', $identifier['value'])
                                   . ' saved at ' . $tokenPath . ' and should be available at ' . $uri);

                        sleep(2);

                        $ch = curl_init();
                        curl_setopt($ch,CURLOPT_URL, $uri);
                        curl_setopt($ch,CURLOPT_RETURNTRANSFER,1);
                        $key_from_file = curl_exec($ch);
                        curl_close($ch);

                        // simple self check
                        if ($challenge['key'] !== trim($key_from_file))
                        {
                            throw new \RuntimeException('Please check ' . $uri . ' - token not available');
                        }

                        break;
                    case $this::CHALLENGE_TYPE_DNS:

                        $dns_record_name = '_acme-challenge.' . str_replace('*.', '', $identifier['value']);

                        $this->log('Change dns txt record: '
                                   . print_r([
                                'domain'      => str_replace('*.', '', $identifier['value']),
                                'record_name' => $dns_record_name,
                                'value'       => $challenge['key']
                            ], 1)
                        );

                        $this->dnsProcessor->addDnsTxtRecord(
                            str_replace('*.', '', $identifier['value']),
                            $dns_record_name,
                            $challenge['key']
                        );

                        $sleep_time = ($i == 0)
                            ? 15
                            : 60;

                        sleep($sleep_time);

                        $i++;
                        break;
                }

                /* Request authorization
                 */
                $this->log('Requesting authorization for host.');

                $this->authorizeHost($challenge, $identifier);

                /**
                 * Poll authorization is valid
                 */
                $this->log('Polling authorization status.');

                $timer = self::MAX_POLL_DELAY;

                do
                {
                    $result = $this->authorizationValid($identifier, $challenge['type']);

                    if (($result['is_success'] ?? false) === true)
                    {
                        break;
                    }

                    printf(".");
                    sleep(5);
                }
                while (--$timer > 0);

                if (($result['is_success'] ?? false) == false)
                {
                    $this->log('Polling timed out.');

                    throw new \RuntimeException('Polling timed out. Data: '
                                                . print_r([
                            'result' => $result ?? null
                        ], 1)
                    );
                }

                $this->log('Removing challenge responses.');

                $this->removeChallengeResponses(
                    $challenge,
                    $tokenPath ?? '',
                    $identifier ?? null,
                    $dns_record_name ?? null
                );
            }
            catch (\Exception $ex)
            {
                $this->log('Removing challenge responses.');

                $this->removeChallengeResponses(
                    $challenge,
                    $tokenPath ?? '',
                    $identifier ?? null,
                    $dns_record_name ?? null
                );

                throw $ex;
            }
        }

        /**
         * Finalize order
         */
        $this->log('Finalizing order.');

        $domainPath = $this->getDomainPath($this->getBaseName());

        // generate private key for domain if not exist
        if (!is_dir($domainPath) || !is_file($domainPath . '/private.pem'))
        {
            $this->generateKey($domainPath);
        }

        $private_domain_key = $this->readPrivateKey($domainPath . '/private.pem');

        $csr = $reuse_csr && is_file($domainPath . "/last.csr")
            ? $this->getCsrContent($domainPath . "/last.csr")
            : $this->generateCSR($private_domain_key, $domains);

        $cert_info = $this->finalizeOrder($order, $csr);

        if ($cert_info["status"] != "valid")
        {
            /* Poll certificate is ready
             */
            $this->log('Polling certificate readiness.');

            $timer = self::MAX_POLL_DELAY;

            do
            {
                $result = $this->certificateReady($cert_info["location"]);

                if (($result['is_success'] ?? false) === true)
                {
                    break;
                }

                $this->log('.');

                sleep(1);
            }
            while (--$timer > 0);

            if (($result['is_success'] ?? false) == false)
            {
                $this->log('Polling timed out.');

                throw new \RuntimeException('Polling timed out. Data: '
                                            . print_r([
                        'result' => $result ?? null
                    ], 1)
                );
            }
        }

        /**
         * Download certificates
         */
        printf("Downloading certificates.\n");

        $certificate = $this->getCertificate($cert_info["download"]);

        if ($this->isPemFormat($certificate) == false)
        {
            $certificate = $this->convertToPem($certificate);
        }

        $this->log("Got certificate! YAY!");

        $certificate  = str_replace("\r", "", $certificate);
        $certificates = explode(PHP_EOL . PHP_EOL, $certificate);

        // Write certificates

        if (count($certificates) == 2)
        {
            $this->log("Saving fullchain.pem");
            file_put_contents($domainPath . '/fullchain.pem', implode("\n", $certificates));

            $this->log("Saving cert.pem");
            file_put_contents($domainPath . '/cert.pem', array_shift($certificates));

            $this->log("Saving chain.pem");
            file_put_contents($domainPath . "/chain.pem", implode("\n", $certificates));
        }
        else
        {
            $this->log("Saving fullchain.pem");
            file_put_contents($domainPath . '/fullchain.pem', $certificate);
        }

        $this->log("Done !!§§!");

        return true;
    }

    /**
     * @param array $challenge
     * @param null|string $tokenPath
     * @param null|array $identifier
     * @param null|string $dns_record_name
     */
    private function removeChallengeResponses(
        $challenge, $tokenPath = null, $identifier = null, $dns_record_name = null
    )
    {
        switch ($challenge['type'])
        {
            case $this::CHALLENGE_TYPE_HTTP:
                @unlink($tokenPath);
                break;
            case $this::CHALLENGE_TYPE_DNS:
                $this->dnsProcessor->removeDnsTxtRecord(
                    str_replace('*.', '', $identifier['value']),
                    $dns_record_name,
                    $challenge['key']
                );
                break;
        }
    }

    /**
     * Check if certificate is in PEM format
     *
     * @param string $cert
     *
     * @return bool
     */
    private function isPemFormat($cert)
    {
        return substr($cert, 0, 10) == "-----BEGIN";
    }

    /**
     * Get challenge
     *
     * @param array $order
     *
     * @return array|bool
     */
    private function getChallenge($order)
    {
        $path = "/acme/authz/" . $order["authorization"];

        if (($result = $this->client->get($path)) === false)
        {
            $this->log('Error getting challange for ' . $order["value"] . '.');

            throw new \RuntimeException('Error getting challange for ' . $order["value"] . '. Data: '
                                        . print_r([
                    'order'  => $order ?? null,
                    'path'   => $path ?? null,
                    'result' => $result
                ], 1)
            );
        }

        $privateKey = $this->readPrivateKey($this->accountKeyPath);
        $details    = openssl_pkey_get_details($privateKey);

        $challenge_by_type = null;

        foreach($this->supported_challenges_ordered_by_priority as $type)
        {
            foreach ($result["challenges"] as $challenge)
            {
                if ($challenge["type"] == $type)
                {
                    $challenge_by_type = $challenge;

                    break;
                }
            }

            if (!is_null($challenge_by_type))
            {
                break;
            }
        }

        if (is_null($challenge_by_type))
        {
            $this->log('No supported HTTP challenge was found.');

            throw new \RuntimeException('No supported HTTP challenge was found. Data: '
                                        . print_r([
                    'challenge_by_type'    => $challenge_by_type ?? null,
                    'supported_challenges' => $this->supported_challenges_ordered_by_priority,
                    'result'               => $result
                ], 1)
            );
        }

        list ( , , , , , $chal) = explode("/", $challenge["url"], 6);

        $data = [
            "e"   => Base64UrlSafeEncoder::encode($details["rsa"]["e"]),
            "kty" => "RSA",
            "n"   => Base64UrlSafeEncoder::encode($details["rsa"]["n"])
        ];

        $digest           = Base64UrlSafeEncoder::encode(hash("sha256", json_encode($data), true));
        $keyAuthorization = $challenge["token"] . '.' . $digest;

        switch(strtolower($challenge_by_type['type']))
        {
            case $this::CHALLENGE_TYPE_HTTP:
                return [
                    'type'       => $this::CHALLENGE_TYPE_HTTP,
                    'challenge'  => $chal,
                    'key'        => $keyAuthorization,
                    'token'      => $challenge["token"]
                ];
                break;
            case $this::CHALLENGE_TYPE_DNS:
                $key = Base64UrlSafeEncoder::encode(hash('sha256', $keyAuthorization, true));

                return [
                    'type'       => $this::CHALLENGE_TYPE_DNS,
                    'challenge' => $chal,
                    'key'        => $key,
                    'token'      => $challenge["token"]
                ];
                break;
        }
    }

    /**
     * Signed Request
     *
     * @param string $uri
     * @param array $payload
     * @param int $expected_status
     *
     * @return array|bool|mixed|string
     */
    private function signedRequest($uri, array $payload, $expected_status = 200)
    {
        if ($this->first_post)
        {
            /**
             * Get first nonce
             */
            $create_new_nonce = $this->client->get("/acme/new-nonce");

            if ($this->client->getLastCode() !== 204)
            {
                $this->log('Error connecting to Let\'s Encrypt CA server.');

                throw new \RuntimeException('Error connecting to Let\'s Encrypt CA server. Data: '
                                            . print_r([
                        'create_new_nonce' => $create_new_nonce ?? null
                    ], 1)
                );
            }

            $this->first_post = false;
        }

        $privateKey = $this->readPrivateKey($this->accountKeyPath);
        $details    = openssl_pkey_get_details($privateKey);

        $protected = ["alg" => "RS256"];

        if (in_array($uri, ["/acme/new-acct"]))
        {
            $protected["jwk"] = [
                "kty" => "RSA",
                "n" => Base64UrlSafeEncoder::encode($details["rsa"]["n"]),
                "e" => Base64UrlSafeEncoder::encode($details["rsa"]["e"]),
            ];
        }
        else
        {
            if ($this->account_id == 0)
            {
                $this->log('Account not registered yet');

                throw new \RuntimeException('Account not registered yet. Data: '
                                            . print_r([
                        'account_id' => $this->account_id ?? null
                    ], 1)
                );
            }

            $protected["kid"] = $this->client->getBase() . '/acme/acct/' . $this->account_id;
        }

        $protected["nonce"] = $this->client->getLastNonce();
        $protected["url"]   = preg_match('~^http~', $uri) ? $uri : $this->client->getBase() . $uri;

        $payload64   = Base64UrlSafeEncoder::encode(str_replace('\\/', '/', json_encode($payload)));
        $protected64 = Base64UrlSafeEncoder::encode(json_encode($protected));

        openssl_sign($protected64 . '.' . $payload64, $signed, $privateKey, "SHA256");

        $signed64 = Base64UrlSafeEncoder::encode($signed);

        $data = [
            'protected' => $protected64,
            'payload' => $payload64,
            'signature' => $signed64
        ];

        $this->log("Sending signed request to $uri");

        $result = $this->client->post($uri, json_encode($data));

        if ($expected_status != $this->client->getLastCode())
        {
            throw new \RuntimeException('Signed request status code in response <> ' . $expected_status . '. Data: '
                                        . print_r([
                    'result'    => $result ?? null,
                    'last_code' => $this->client->getLastCode()
                ], 1)
            );
        }

        return $result;
    }

    /**
     * Read private key
     *
     * @param string $path
     *
     * @return bool|resource
     */
    private function readPrivateKey($path)
    {
        if (($key = openssl_pkey_get_private('file://' . $path)) === false)
        {
            throw new \RuntimeException(openssl_error_string());
        }

        return $key;
    }

    /**
     * Get domain path
     *
     * @param string $domain
     *
     * @return string
     */
    private function getDomainPath($domain)
    {
        $clean_domain = str_replace('*.', '', $domain);

        return $this->certificatesDir . '/' . $clean_domain;
    }

    /**
     * Generate Certificate Signing Request
     *
     * @param string $privateKey
     * @param array $domains
     *
     * @return string
     */
    private function generateCSR($privateKey, array $domains)
    {
        if(in_array($this->getBaseName(), $domains))
        {
            $CN = $this->getBaseName();
        }
        elseif(in_array('*.' . $this->getBaseName(), $domains))
        {
            $CN = '*.' . $this->getBaseName();
        }
        else
        {
            $CN = reset($domains);
        }

        $dn = [
            "commonName"   => $CN,
            "emailAddress" => ACCOUNT_EMAIL_ADDRESS
        ];

        $san = implode(",", array_map(function ($dns) {
            return "DNS:" . $dns;
        }, $domains));

        $tmpConf     = tmpfile();
        $tmpConfMeta = stream_get_meta_data($tmpConf);
        $tmpConfPath = $tmpConfMeta["uri"];

        // workaround to get SAN working
        fwrite($tmpConf, 'HOME = .
RANDFILE = $ENV::HOME/.rnd
[ req ]
default_bits = 4096
default_keyfile = privkey.pem
distinguished_name = req_distinguished_name
req_extensions = v3_req
[ req_distinguished_name ]
countryName = Country Name (2 letter code)
[ v3_req ]
basicConstraints = CA:FALSE
subjectAltName = ' . $san . '
keyUsage = nonRepudiation, digitalSignature, keyEncipherment');

        $csr = openssl_csr_new($dn, $privateKey, [
            "config" => $tmpConfPath,
            "digest_alg" => "sha256"
        ]);

        if (!$csr)
        {
            throw new \RuntimeException("CSR couldn't be generated! " . openssl_error_string());
        }

        openssl_csr_export($csr, $csr);
        fclose($tmpConf);

        $csrPath = $this->getDomainPath($this->getBaseName()) . "/last.csr";

        file_put_contents($csrPath, $csr);

        return $this->getCsrContent($csrPath);
    }

    /**
     * Get csr content
     *
     * @param string $csrPath
     *
     * @return bool|string
     */
    private function getCsrContent($csrPath)
    {
        $csr = file_get_contents($csrPath);

        preg_match('~REQUEST-----(.*)-----END~s', $csr, $matches);

        return base64_decode($matches[1]);

        //return trim(Base64UrlSafeEncoder::encode(base64_decode($matches[1])));
    }

    /**
     * Generate key
     *
     * @param string $outputDirectory
     */
    private function generateKey($outputDirectory)
    {
        $res = openssl_pkey_new([
            "private_key_type" => OPENSSL_KEYTYPE_RSA,
            "private_key_bits" => 4096,
        ]);

        if (!openssl_pkey_export($res, $privateKey))
        {
            throw new \RuntimeException("Key export failed!");
        }

        $details = openssl_pkey_get_details($res);

        if (!is_dir($outputDirectory))
        {
            @mkdir($outputDirectory, 0700, true);
        }

        if (!is_dir($outputDirectory))
        {
            throw new \RuntimeException('Cant\'t create directory' . $outputDirectory);
        }

        @unlink($outputDirectory . '/private.pem');
        @unlink($outputDirectory . '/public.pem');

        file_put_contents($outputDirectory . '/private.pem', $privateKey);
        file_put_contents($outputDirectory . '/public.pem', $details['key']);
    }

    /**
     * Log
     *
     * @param string $message
     */
    protected function log($message)
    {
        if ($this->logger)
        {
            $this->logger->info($message);
        }
        else
        {
            echo $message . "\n";
        }
    }
}