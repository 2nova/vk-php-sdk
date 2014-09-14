<?php

namespace Novanova\VK;

/**
 * Class VK
 * @package Novanova\VK
 */
class VK
{

    /**
     * @var string
     */
    private $app_id;
    /**
     * @var string
     */
    private $secret;
    /**
     * @var string
     */
    private $version;
    /**
     * @var string
     */
    private $lang;
    /**
     * @var int
     */
    private $https;
    /**
     * @var string|null
     */
    private $access_token = null;

    /**
     * @var array
     *      array['send_secret'] bool
     */
    private $options = [
        'send_secret' => true,
    ];

    /**
     * @param string $app_id
     * @param string $secret
     * @param string $version
     * @param string $lang
     * @param int    $https
     */
    public function __construct($app_id, $secret, $version = '5.24', $lang = 'ru', $https = 1)
    {
        $this->app_id = $app_id;
        $this->secret = $secret;
        $this->version = $version;
        $this->lang = $lang;
        $this->https = $https;
    }

    /**
     * @param  array $options
     * @return $this
     */
    public function setOptions(array $options)
    {
        $this->options = array_merge($this->options, $options);

        return $this;
    }

    /**
     * @return string
     */
    public function app_id()
    {
        return $this->app_id;
    }

    /**
     * @param $viewer_id
     * @return string
     */
    public function calculateAuthKey($viewer_id)
    {
        return md5($this->app_id . '_' . $viewer_id . '_' . $this->secret);
    }

    /**
     * @param $method
     * @param  array $params
     * @return mixed
     */
    public function no_auth_api($method, array $params)
    {
        return $this->api($method, $params, true, false);
    }

    /**
     * @param  string      $method
     * @param  array       $params
     * @param  bool        $auth_by_token
     * @param  bool        $auth
     * @return mixed
     * @throws VKException
     */
    public function api($method, array $params, $auth_by_token = false, $auth = true)
    {
        $response = null;

        $params['v'] = $this->version;
        $params['lang'] = $this->lang;
        $params['https'] = $this->https;

        if (!$auth) {
            $response = file_get_contents('https://api.vk.com/method/' . $method . '?' . http_build_query($params));
        } else {
            if ($auth_by_token) {

                if (!$this->access_token) {
                    $this->access_token = $this->getServerAccessToken();
                }

                if ($this->options['send_secret']) {
                    $params['client_secret'] = $this->secret;
                }
                $params['access_token'] = $this->access_token;

                $response = file_get_contents('https://api.vk.com/method/' . $method . '?' . http_build_query($params));
            } else {

                $params['api_id'] = $this->app_id;
                $params['method'] = $method;
                $params['format'] = 'json';
                $params['random'] = rand(1, 9999);
                $params['timestamp'] = time();
                $params['sig'] = $this->sign($params);

                $response = file_get_contents('https://api.vk.com/api.php?' . http_build_query($params));
            }
        }

        $response = json_decode($response);
        if (!$response || JSON_ERROR_NONE !== json_last_error()) {
            throw new VKException('VK API error');
        }

        if (!empty($response->error->error_code) && !empty($response->error->error_msg)) {
            throw new VKException($response->error->error_msg, $response->error->error_code);
        }

        if (!isset($response->response)) {
            throw new VKException('VK API error');
        }

        $response = $response->response;

        return $response;
    }

    /**
     * @param $access_token
     */
    public function setAccessToken($access_token)
    {
        $this->access_token = $access_token;
    }

    /**
     * @return mixed
     * @throws VKException
     */
    public function getServerAccessToken()
    {

        $params = array(
            'client_id' => $this->app_id,
            'client_secret' => $this->secret,
            'v' => $this->version,
            'grant_type' => 'client_credentials',
        );

        $response = file_get_contents('https://oauth.vk.com/access_token?' . http_build_query($params));

        if (!$response = json_decode($response)) {
            throw new VKException('VK API error');
        }

        if (empty($response->access_token)) {
            throw new VKException('VK API error');
        }

        return $response->access_token;
    }

    /**
     * @return array
     * @throws VKException
     */
    public function parseCookie()
    {
        if (empty($_COOKIE['vk_app_' . $this->app_id])) {
            throw new VKException('No cookie');
        }
        $cookie = $_COOKIE['vk_app_' . $this->app_id];
        $pairs = explode('&', $cookie, 10);
        if (!is_array($pairs)) {
            throw new VKException('Bad cookie');
        }
        $session = array();
        $valid_keys = array('expire', 'mid', 'secret', 'sid', 'sig');
        foreach ($pairs as $pair) {
            list($key, $value) = explode('=', $pair, 2);
            if (empty($key) || empty($value) || !in_array($key, $valid_keys)) {
                continue;
            }
            $session[$key] = $value;
        }
        foreach ($valid_keys as $key) {
            if (!isset($session[$key])) {
                throw new VKException('No ' . $key . ' parameter');
            }
        }

        $secret = $session['sig'];
        unset($session['sig']);

        if ($secret !== $this->sign($session)) {
            throw new VKException('Bad sign');
        }
        if ($session['expire'] <= time()) {
            throw new VKException('Session expired');
        }

        return array(
            'id' => $session['mid'],
            'secret' => $session['secret'],
            'sid' => $session['sid']
        );
    }

    /**
     * @param $params
     * @return string
     */
    private function sign($params)
    {
        $sign = '';
        ksort($params);
        foreach ($params as $key => $value) {
            $sign .= $key . '=' . $value;
        }
        $sign .= $this->secret;

        return md5($sign);
    }
}
