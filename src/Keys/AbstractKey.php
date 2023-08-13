<?php

namespace gamringer\xmldsig\Keys;

use gamringer\xmldsig\SignatureNode;

class AbstractKey
{
	protected $cert;
	protected $chain;

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
		$method = $this->getSigningMethod();
		$data = $dsigNode->produceSignatureData($method);

		$signature = $this->signData($data);

		$dsigNode->setSignature(base64_encode($signature), $this->cert, $this->chain);
	}
}