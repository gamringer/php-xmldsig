<?php

namespace gamringer\xmldsig\Util;

use DOMElement;

class CertificateCodec
{
	public static function b642pem(string $b64): string
	{
		$pem = chunk_split($b64, 64, "\n");
		$pem = "-----BEGIN CERTIFICATE-----\n" . $pem . "-----END CERTIFICATE-----\n";

		return $pem;
	}

	public static function pem2der($pem): string
    {
       $begin = "CERTIFICATE-----";
       $end   = "-----END";
       $pem = substr($pem, strpos($pem, $begin) + strlen($begin));
       $pem = substr($pem, 0, strpos($pem, $end));
       $der = base64_decode($pem);
       return $der;
    }

    public static function der2pem($der): string
    {
        return b642pem(base64_encode($der));
    }

    public static function issuerString(array $parts): string
    {
        $outputElements = [];

        foreach ($parts as $fieldName => $part) {
        	if (!is_array($part)) {
        		$part = [$part];
        	}
        	foreach ($part as $element) {
        		$outputElements[] = $fieldName . ' = ' . $element;
        	}
        }

        return implode(',', $outputElements);
    }
}