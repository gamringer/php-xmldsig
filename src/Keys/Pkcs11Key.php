<?php

namespace gamringer\xmldsig\Keys;

use gamringer\xmldsig\SignatureNode;

class Pkcs11Key
{
	protected $keyObject;
	protected $cert;
	protected $chain;

	public function __construct(\Pkcs11\Key $keyObject)
	{
		$this->keyObject = $keyObject;
	}

	public static function fromUri(\Pkcs11\Session $session, string $uri): self
	{
		$privateKeySearchResult = $session->openUri($uri);

		return new self($privateKeySearchResult[0]);
	}

	public function setCertificate(string $cert, array $chain = []): void
	{
		$this->cert = $this->stripPem($cert);
		$this->chain = [];
		foreach ($chain as $element) {
			$this->chain[] = $this->stripPem($element);
		}
	}

	private function stripPem(string $pem): string
	{
		$begin = strpos($pem, '-----BEGIN CERTIFICATE-----') + 28;
		$end = strpos($pem, '-----END CERTIFICATE-----') - 1;
		return str_replace("\n", '', substr($pem, $begin, $end - $begin));
	}

	public function sign(SignatureNode $dsigNode): void
	{
		$method = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
		$data = $dsigNode->getSignatureData($method);

		$mechanism = new \Pkcs11\Mechanism(\Pkcs11\CKM_SHA256_RSA_PKCS);
		$signature = $this->keyObject->sign($mechanism, $data);

		$dsigNode->setSignature(base64_encode($signature), $this->cert, $this->chain);
	}
}