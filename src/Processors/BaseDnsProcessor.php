<?php

/**
 * Created by Flexbe Team.
 * Author: Sergiets Dmitry
 * Email: sergietsdmitry@gmail.com
 * Date: 7/19/2018
 * Time: 10:19 AM
 */

namespace Sergiets\LescriptWildcard\Src\Processors;

use Sergiets\LescriptWildcard\Src\Processors\DnsProcessorInterface;

class BaseDnsProcessor implements DnsProcessorInterface
{

    public function addDnsTxtRecord($domain_name, $record_name, $value)
    {
        return false;
    }

    public function removeDnsTxtRecord($domain_name, $record_name, $value)
    {
        return false;
    }
}