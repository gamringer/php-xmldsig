<?php

namespace gamringer\xmldsig;

use gamringer\xmldsig\Exceptions\UnsupportedAlgorithmException;
use DOMElement;

class TransformFactory
{
	public function produceTransform(DOMElement $transformNode): Canonicalizer
	{
		$algorithm = $transformNode->getAttribute('Algorithm');

		$method = CanonicalizationMethod::tryFrom($algorithm);

		if ($method === null) {
			throw new UnsupportedAlgorithmException('Unsupported transform algorithm');
		}

		return new Canonicalizer($method);
	}
}