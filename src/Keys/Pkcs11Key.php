<?php

namespace gamringer\xmldsig\Keys;

use gamringer\xmldsig\Exceptions\KeyMaterialException;

class Pkcs11Key extends AbstractKey implements signsXml
{
	protected $keyObject;

	public function __construct(\Pkcs11\Key $keyObject)
	{
		$this->keyObject = $keyObject;
	}

	public static function fromUri(\Pkcs11\Session $session, string $uri): self
	{
		$privateKeySearchResult = $session->openUri($uri);

		return new self($privateKeySearchResult[0]);
	}

	protected function signData(string $data): string
	{
		$mechanismId = [
			'http://www.w3.org/2001/04/xmldsig-more#rsa-sha224' => \Pkcs11\CKM_SHA224_RSA_PKCS,
			'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256' => \Pkcs11\CKM_SHA256_RSA_PKCS,
			'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384' => \Pkcs11\CKM_SHA384_RSA_PKCS,
			'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512' => \Pkcs11\CKM_SHA512_RSA_PKCS,
			'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha224' => \Pkcs11\CKM_ECDSA_SHA224,
			'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256' => \Pkcs11\CKM_ECDSA_SHA256,
			'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384' => \Pkcs11\CKM_ECDSA_SHA384,
			'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512' => \Pkcs11\CKM_ECDSA_SHA512,
		][$this->getSigningMethod()];

		$mechanism = new \Pkcs11\Mechanism($mechanismId);
		$signature = $this->keyObject->sign($mechanism, $data);

		return $signature;
	}

	protected function getSigningMethod(): string
	{
		$keyType = $this->keyObject->getAttributeValue([\Pkcs11\CKA_KEY_TYPE])[\Pkcs11\CKA_KEY_TYPE];

		if ($keyType == \Pkcs11\CKK_RSA) {
			return 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
		}

		if ($keyTypeValues == \Pkcs11\CKK_ECDSA) {
			$ecParams = bin2hex($this->keyObject->getAttributeValue([\Pkcs11\CKA_EC_PARAMS])[\Pkcs11\CKA_EC_PARAMS]);
			if ($ecParams == '06082A8648CE3D030107') {
				return 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256';
			}
			if ($ecParams == '06052B81040022') {
				return 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384';
			}
			if ($ecParams == '06052B81040023') {
				return 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512';
			}
		}

		throw new KeyMaterialException('Unknown key type');
	}
}