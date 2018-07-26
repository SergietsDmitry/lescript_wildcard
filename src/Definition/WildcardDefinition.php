<?php

/**
 * Created by Flexbe Team.
 * Author: Sergiets Dmitry
 * Email: sergietsdmitry@gmail.com
 * Date: 7/19/2018
 * Time: 4:06 PM
 */

namespace Sergiets\LescriptWildcard\Src\Definition;

interface WildcardDefinition
{
    const MAX_POLL_DELAY = 5;

    const CHALLENGE_TYPE_HTTP = 'http-01';
    const CHALLENGE_TYPE_DNS  = 'dns-01';
}