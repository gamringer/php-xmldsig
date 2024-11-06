<?php

namespace gamringer\xmldsig\Util;

use DOMElement;

class Digest
{
	public static function getSignatureDigestMethod(string $sigAlgId): string
	{
		return match ($sigAlgId) {
			'http://www.w3.org/2001/04/xmldsig-more#rsa-sha224' => 'sha224',
			'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256' => 'sha256',
			'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384' => 'sha384',
			'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512' => 'sha512',
			'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha224' => 'sha224',
			'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256' => 'sha256',
			'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384' => 'sha384',
			'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512' => 'sha512',
		};
	}

	public static function getDigestMethod(string $digestId): string
	{
		return match ($digestId) {
			'http://www.w3.org/2001/04/xmldsig-more#sha256' => 'sha256',
			'http://www.w3.org/2001/04/xmldsig-more#sha384' => 'sha384',
			'http://www.w3.org/2001/04/xmldsig-more#sha512' => 'sha512',
		};
	}

	public static function hash(string $digestId, $data): string
	{
		return hash(self::getDigestMethod($digestId), $data, true);
	}
}