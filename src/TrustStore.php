<?php

namespace gamringer\xmldsig;

class TrustStore
{
	protected $certs = [];

	public function addCertificate(string $certificate): void
	{
		$this->certs[] = $certificate;
	}

	public function addCertificateFile(string $path): void
	{
		$this->addCertificate(file_get_contents($path));
	}
}