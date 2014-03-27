<?php

namespace Novanova\VK;


/**
 * Class VK
 * @package Novanova\VK
 */
class VK
{

    private $app_id;
    private $secret;
    private $version;
    private $lang;
    private $https;
    private $access_token = null;

    public function __construct($app_id, $secret, $version = '5.16', $lang = 'ru', $https = 1)
    {
        $this->app_id = $app_id;
        $this->secret = $secret;
        $this->version = $version;
        $this->lang = $lang;
        $this->https = $https;
    }

    public function app_id()
    {
        return $this->app_id;
    }

    public function calculateAuthKey($viewer_id)
    {
        return md5($this->app_id . '_' . $viewer_id . '_' . $this->secret);
    }

    public function api($method, $params, $auth_by_token = false)
    {
        $response = null;

        $params['v'] = $this->version;

        if($auth_by_token){

            if (!$this->access_token) {
                $this->access_token = $this->getServerAccessToken();
            }

            $params['client_secret'] = $this->secret;
            $params['access_token'] = $this->access_token;

            $response = file_get_contents('https://api.vk.com/method/' . $method . '?' . http_build_query($params));
        }
        else{

            $params['api_id'] = $this->app_id;
            $params['method'] = $method;
            $params['format'] = 'json';
            $params['random'] = rand(1, 9999);
            $params['timestamp'] = time();
            $params['sig'] = $this->sign($params);

            $response = file_get_contents('https://api.vk.com/api.php?' . http_build_query($params));
        }


        $response = json_decode($response);
        if (!$response || JSON_ERROR_NONE !== json_last_error()) {
            throw new VKException('VK API error');
        }

        return $response;
    }

    public function getServerAccessToken()
    {

        $params = array(
            'client_id' => $this->app_id,
            'client_secret' => $this->secret,
            'v' => $this->verion,
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
