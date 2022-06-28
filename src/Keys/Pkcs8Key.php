<?php

namespace gamringer\xmldsig\Keys;

class Pkcs8Key extends AbstractKey implements signsXml
{
	protected $pkey;

	public function __construct(string $encoded, ?string $password = null)
	{
		$this->pkey = openssl_pkey_get_private($encoded, $password);
	}

	public static function fromFile(string $path, ?string $password = null): self
	{
		return new self(file_get_contents($path), $password);
	}

	protected function signData(string $data): string
	{
		openssl_sign($data, $signature, $this->pkey, \OPENSSL_ALGO_SHA256);

		return $signature;
	}

	protected function getSigningMethod(): string
	{
		$details = openssl_pkey_get_details($this->pkey);
		if ($details['type'] ==  \OPENSSL_KEYTYPE_RSA) {
			return 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
		}

		if ($details['type'] ==  \OPENSSL_KEYTYPE_EC) {
			if ($details['curve_name'] ==  'prime256v1 ') {
				return 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256';
			}
			if ($details['curve_name'] ==  'secp384r1 ') {
				return 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384';
			}
			if ($details['curve_name'] ==  'secp521r1 ') {
				return 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512';
			}
		}

		throw new \Exception('Unknown key type');
	}
}