<?php

namespace gamringer\xmldsig\Keys;

use gamringer\xmldsig\SignatureNode;

class Pkcs8Key
{
	protected $pkey;
	protected $cert;
	protected $chain;

	public function __construct(string $encoded, ?string $password = null)
	{
		$this->pkey = openssl_pkey_get_private($encoded, $password);
	}

	public static function fromFile(string $path, ?string $password = null): self
	{
		return new self(file_get_contents($path), $password);
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

		openssl_sign($data, $signature, $this->pkey, \OPENSSL_ALGO_SHA256);

		$dsigNode->setSignature(base64_encode($signature), $this->cert, $this->chain);
	}
}