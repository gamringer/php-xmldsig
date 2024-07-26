<?php

namespace gamringer\xmldsig;

use gamringer\xmldsig\Exceptions\UnsupportedAlgorithmException;

class Canonicalizer
{
	public function __construct(
		protected CanonicalizationMethod $canonicalizationMethod = CanonicalizationMethod::METHOD_1_0,
	) {}

	public function getMethod(): CanonicalizationMethod
	{
		return $this->canonicalizationMethod;
	}

	public function getMethodId(): string
	{
		return $this->canonicalizationMethod->value;
	}

	public function setMethod(CanonicalizationMethod $canonicalizationMethod): void
	{
		if (!in_array($canonicalizationMethod, CanonicalizationMethod::cases())) {
			throw new UnsupportedAlgorithmException('Unsupported canonicalization method');
		}

		$this->canonicalizationMethod = $canonicalizationMethod;
	}

	public function canonicalize(\DOMNode $node): string
	{
		if ($this->canonicalizationMethod == CanonicalizationMethod::METHOD_1_0) {
			return $node->C14N(false, false);
		}
		if ($this->canonicalizationMethod == CanonicalizationMethod::METHOD_1_0_WITH_COMMENTS) {
			return $node->C14N(false, true);
		}
		if ($this->canonicalizationMethod == CanonicalizationMethod::METHOD_EXCLUSIVE_1_0) {
			return $node->C14N(true, false);
		}
		if ($this->canonicalizationMethod == CanonicalizationMethod::METHOD_EXCLUSIVE_1_0_WITH_COMMENTS) {
			return $node->C14N(true, true);
		}

		throw new UnsupportedAlgorithmException('Unsupported canonicalization method');
	}

	public function transform(\DOMNode $node): string
	{
		return $this->canonicalize($node);
	}
}