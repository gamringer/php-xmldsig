<?php

namespace gamringer\xmldsig\Validation;

use gamringer\xmldsig\Keys\X509Certificate;

class NullCertificateValidator implements CertificateValidator
{
	public function validate(X509Certificate $certificate): bool
	{
		return true;
	}
}