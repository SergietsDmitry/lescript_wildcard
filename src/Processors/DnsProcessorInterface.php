<?php

/**
 * Created by Flexbe Team.
 * Author: Sergiets Dmitry
 * Email: sergietsdmitry@gmail.com
 * Date: 7/19/2018
 * Time: 10:13 AM
 */

namespace Sergiets\LescriptWildcard\Src\Processors;

interface DnsProcessorInterface
{
    public function addDnsTxtRecord($domain_name, $record_name, $value);
    public function removeDnsTxtRecord($domain_name, $record_name, $value);
}