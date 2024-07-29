<?php

namespace gamringer\xmldsig\Validation;

use gamringer\xmldsig\Keys\X509Certificate;

class OpenSSLCertificateValidator implements CertificateValidator
{
	protected array $extraArgs;

	public function __construct(
		public TrustStore $trustStore,
		array $extraArgs = [],
	) {
		$this->extraArgs = array_map('escapeshellarg', $extraArgs);
	}

	public function validate(X509Certificate $certificate): bool
	{
		$args = $this->extraArgs;

		$trustList = '';
		foreach ($this->trustStore->getCertificates() as $trustedCertificate) {
			$trustList .= $trustedCertificate . PHP_EOL . PHP_EOL;
		}
		$trustListFile = tempnam(sys_get_temp_dir(), 'trustlist');
		if (!empty($trustList)) {
			file_put_contents($trustListFile, $trustList);
			$args[] = '-CAfile ' . $trustListFile;
		}

		$i = $certificate;
		$chainList = '';
		while($issuer = $i->getIssuer()) {
			$chainList .= $issuer->getEncoded() . PHP_EOL . PHP_EOL;
			$i = $issuer;
		}
		$chainListFile = tempnam(sys_get_temp_dir(), 'chainlist');
		if (!empty($chainList)) {
			file_put_contents($chainListFile, $chainList);
			$args[] = '-untrusted ' . $chainListFile;
		}

		$certificateFile = tempnam(sys_get_temp_dir(), 'certificate');
		file_put_contents($certificateFile, $certificate->getEncoded());

		$cmd = 'openssl verify ' . implode(' ', $args) . ' ' . $certificateFile;
		if (!exec($cmd, $output, $resultCode)) {
			throw new ValidationRuntimeError('OpenSSL returned an error validating the certificate');
		}

		unlink($trustListFile);
		unlink($chainListFile);
		unlink($certificateFile);

		return $resultCode == 0;
	}
}