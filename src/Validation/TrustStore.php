<?php

namespace gamringer\xmldsig\Validation;

class TrustStore
{
	protected array $certs = [];

	public function addCertificate(string $certificate): void
	{
		$this->certs[] = $certificate;
	}

	public function addCertificateFile(string $path): void
	{
		$this->addCertificate(file_get_contents($path));
	}

	public function getCertificates(): array
	{
		return $this->certs;
	}
}