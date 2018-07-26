<?php

/**
 * Created by Flexbe Team.
 * Author: Sergiets Dmitry
 * Email: sergietsdmitry@gmail.com
 * Date: 7/16/2018
 * Time: 11:46 AM
 */

namespace Sergiets\LescriptWildcard\Src\Logger;

interface LoggerInterface
{
    /**
     * Log process by action ($name) with description $arguments
     *
     * @param $name
     * @param $arguments
     *
     * @return mixed
     */
    public function __call($name, $arguments);
}