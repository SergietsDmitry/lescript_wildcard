<?php

/**
 * Created by Flexbe Team.
 * Author: Sergiets Dmitry
 * Email: sergietsdmitry@gmail.com
 * Date: 7/16/2018
 * Time: 10:10 AM
 */

namespace Sergiets\LescriptWildcard\Src;

class Base64UrlSafeEncoder
{
    public static function encode($input)
    {
        return str_replace('=', '', strtr(base64_encode($input), '+/', '-_'));
    }

    public static function decode($input)
    {
        $remainder = strlen($input) % 4;
        if ($remainder)
        {
            $padlen = 4 - $remainder;
            $input  .= str_repeat('=', $padlen);
        }

        return base64_decode(strtr($input, '-_', '+/'));
    }
}