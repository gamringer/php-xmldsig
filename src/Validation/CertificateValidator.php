<?php

namespace gamringer\xmldsig\Validation;

use gamringer\xmldsig\Keys\X509Certificate;

interface CertificateValidator
{
	public function validate(X509Certificate $certificate): bool;
}