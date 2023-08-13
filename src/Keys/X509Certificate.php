<?php

namespace gamringer\xmldsig\Keys;

class X509Certificate
{
	protected $resource;
	protected $issuer;
	protected $parsed;

	public function __construct(string $encoded)
	{
		$this->resource = openssl_x509_read($encoded);
		$this->parsed = openssl_x509_parse($this->resource);
	}

	public static function fromFile(string $path): self
	{
		return new self(file_get_contents($path));
	}

	public function setIssuer(self $issuer): void
	{
		$this->issuer = $issuer;
	}

	public function getIssuer(): self
	{
		return $this->issuer;
	}

	public function getParsed(): array
	{
		return $this->parsed;
	}

	public function getResource(): \OpenSSLCertificate
	{
		return $this->resource;
	}
}