<?php

namespace gamringer\xmldsig;

class Canonicalizer
{
	protected $canonicalizationMethod = CanonicalizationMethod::METHOD_1_0;

	public function getMethod(): string
	{
		return $this->canonicalizationMethod;
	}

	public function setMethod(string $canonicalizationMethod): void
	{
		if (!in_array($canonicalizationMethod, [
			CanonicalizationMethod::METHOD_1_0,
			CanonicalizationMethod::METHOD_1_0_WITH_COMMENTS,
			CanonicalizationMethod::METHOD_EXCLUSIVE_1_0,
			CanonicalizationMethod::METHOD_EXCLUSIVE_1_0_WITH_COMMENTS,
		])) {
			throw new \Exception('Unsupported canonicalization method');
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

		throw new \Exception('Unsupported canonicalization method');
	}
}