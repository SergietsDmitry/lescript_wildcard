<?php

/**
 * Created by Flexbe Team.
 * Author: Sergiets Dmitry
 * Email: sergietsdmitry@gmail.com
 * Date: 7/16/2018
 * Time: 11:44 AM
 */

namespace Sergiets\LescriptWildcard\Src\Logger;

use Sergiets\LescriptWildcard\Src\Logger\LoggerInterface;

/**
 * HTTPS для доменов
 * - Получение сертификатов с помощью сервиса letsencrypt
 * - Проверка доступности доменов по https
 *
 * Class Logger
 * @package Sergiets\LescriptWildcard\Src\Logger
 */
class Logger implements LoggerInterface
{
    public $list = [];

    public function __call($name, $arguments)
    {
        $this->list[] = $name . ': ' . $arguments[0];

        if (count($this->list) > 30)
        {
            $this->list = array_slice($this->list, -30, 30);
        }

        echo date('Y-m-d H:i:s') . " [$name] ${arguments[0]}\n";
    }
}