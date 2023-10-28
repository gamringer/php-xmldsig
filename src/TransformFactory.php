<?php

namespace gamringer\xmldsig;

use gamringer\xmldsig\Exceptions\UnsupportedAlgorithmException;

class TransformFactory
{
	public function produceTransform($transformNode)
	{
		$algorithm = $transformNode->getAttribute('Algorithm');

		if (in_array($algorithm, [
			Canonicalizer::METHOD_1_0,
			Canonicalizer::METHOD_1_0_WITH_COMMENTS,
			Canonicalizer::METHOD_1_1,
			Canonicalizer::METHOD_1_1_WITH_COMMENTS,
			Canonicalizer::METHOD_EXCLUSIVE_1_0,
			Canonicalizer::METHOD_EXCLUSIVE_1_0_WITH_COMMENTS,
		])) {
			return new Canonicalizer($algorithm);
		}

		throw new UnsupportedAlgorithmException('Unsupported transform algorithm');
	}
}