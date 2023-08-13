<?php

namespace gamringer\xmldsig;

class Canonicalizer
{
	const METHOD_1_0 = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315';
	const METHOD_1_0_WITH_COMMENTS = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments';
	const METHOD_1_1 = 'http://www.w3.org/2006/12/xml-c14n11';
	const METHOD_1_1_WITH_COMMENTS = 'http://www.w3.org/2006/12/xml-c14n11#WithComments';
	const METHOD_EXCLUSIVE_1_0 = 'http://www.w3.org/2001/10/xml-exc-c14n#';
	const METHOD_EXCLUSIVE_1_0_WITH_COMMENTS = 'http://www.w3.org/2001/10/xml-exc-c14n#WithComments';

	protected $canonicalizationMethod = self::METHOD_1_0;

	public function __construct(?string $canonicalizationMethod = null)
	{
		if ($canonicalizationMethod !== null) {
			$this->setMethod($canonicalizationMethod);
		}
	}

	public function getMethod(): string
	{
		return $this->canonicalizationMethod;
	}

	public function setMethod(string $canonicalizationMethod): void
	{
		if (!in_array($canonicalizationMethod, [
			self::METHOD_1_0,
			self::METHOD_1_0_WITH_COMMENTS,
			self::METHOD_EXCLUSIVE_1_0,
			self::METHOD_EXCLUSIVE_1_0_WITH_COMMENTS,
		])) {
			throw new \Exception('Unsupported canonicalization method');
		}

		$this->canonicalizationMethod = $canonicalizationMethod;
	}

	public function canonicalize(\DOMNode $node): string
	{
		if ($this->canonicalizationMethod == self::METHOD_1_0) {
			return $node->C14N(false, false);
		}
		if ($this->canonicalizationMethod == self::METHOD_1_0_WITH_COMMENTS) {
			return $node->C14N(false, true);
		}
		if ($this->canonicalizationMethod == self::METHOD_EXCLUSIVE_1_0) {
			return $node->C14N(true, false);
		}
		if ($this->canonicalizationMethod == self::METHOD_EXCLUSIVE_1_0_WITH_COMMENTS) {
			return $node->C14N(true, true);
		}

		throw new \Exception('Unsupported canonicalization method');
	}

	public function transform(\DOMNode $node): string
	{
		return $this->canonicalize($node);
	}
}