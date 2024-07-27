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
		$trustList = '';
		foreach ($this->trustStore->getCertificates() as $trustedCertificate) {
			$trustList .= $trustedCertificate . PHP_EOL . PHP_EOL;
		}
		$trustListFile = tempnam(sys_get_temp_dir(), 'trustlist');
		file_put_contents($trustListFile, $trustList);

		$i = $certificate;
		$chainList = '';
		while($issuer = $i->getIssuer()) {
			$chainList .= $issuer->getEncoded() . PHP_EOL . PHP_EOL;
			$i = $issuer;
		}
		$chainListFile = tempnam(sys_get_temp_dir(), 'chainlist');
		file_put_contents($chainListFile, $chainList);

		$certificateFile = tempnam(sys_get_temp_dir(), 'certificate');
		file_put_contents($certificateFile, $certificate->getEncoded());

		$args = array_merge($this->extraArgs, [
			'-CAfile ' . $trustListFile,
			'-untrusted ' . $chainListFile,
		]);

		$cmd = 'openssl verify ' . implode(' ', $args) . ' ' . $certificateFile;
		echo $cmd, PHP_EOL;
		if (!exec($cmd, $output, $resultCode)) {
			// throw
		}

		unlink($trustListFile);
		unlink($chainListFile);
		unlink($certificateFile);

		return $resultCode == 0;
	}
}