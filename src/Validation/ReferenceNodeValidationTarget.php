<?php

namespace gamringer\xmldsig\Validation;

use gamringer\xmldsig\SignatureNode;
use gamringer\xmldsig\TransformFactory;

class ReferenceNodeValidationTarget
{
	protected $referenceNode;

	public function __construct($referenceNode)
	{
		$this->referenceNode = $referenceNode;
	}

	public function validate(): bool
	{
		$uri = $this->referenceNode->getAttribute('URI');

		$digestValueNodes = $this->referenceNode->getElementsByTagNameNS(SignatureNode::URI, 'DigestValue');
		if ($digestValueNodes->count() == 0) {
			// throw exception
		}
		if ($digestValueNodes->count() > 1) {
			// throw exception
		}

		if ($uri[0] == '#') {
			return $this->validateIdReferenceHash($uri, $digestValueNodes[0]->nodeValue);
		} elseif (preg_match('/^https?:\/\//', $uri)) {
			//$result = $result && $this->validateRemoteReferenceHash($uri, $digestValueNodes[0]->nodeValue);
		} elseif (!file_exists($uri)) {
			// throw exception
		}

		return $this->validateLocalReferenceHash($uri, $digestValueNodes[0]->nodeValue);
	}

	private function validateIdReferenceHash($uri, $expectedHash): bool
	{
		$hashTarget = $this->referenceNode->ownerDocument->getElementById(substr($uri, 1));
		$transformFactory = new TransformFactory();
		$transformNodeList = $this->referenceNode->getElementsByTagNameNS(SignatureNode::URI, 'Transform');
		foreach ($transformNodeList as $transformNode) {
			$transform = $transformFactory->produceTransform($transformNode);
			$hashTarget = $transform->transform($hashTarget);
		}

		return hash($this->gethashMethod(), $hashTarget, true) == base64_decode($expectedHash);
	}

	private function gethashMethod(): string
	{
		$digestMethodNodes = $this->referenceNode->getElementsByTagNameNS(SignatureNode::URI, 'DigestMethod');
		if ($digestMethodNodes->length != 0) {
			// throw exception
		}

		$digestMethodNode = $digestMethodNodes->item(0);

		$allowedAlgorithms = [
			'http://www.w3.org/2000/09/xmldsig#sha1' => 'sha1',

			'http://www.w3.org/2001/04/xmlenc#sha256' => 'sha256',
			'http://www.w3.org/2001/04/xmlenc#sha384' => 'sha384',
			'http://www.w3.org/2001/04/xmlenc#sha512' => 'sha512',
			'http://www.w3.org/2001/04/xmlenc#ripemd160' => 'ripemd160',

			'http://www.w3.org/2001/04/xmldsig-more#md5' => 'md5',
			'http://www.w3.org/2001/04/xmldsig-more#sha224' => 'sha224',
			'http://www.w3.org/2001/04/xmldsig-more#sha384' => 'sha384',

			'http://www.w3.org/2007/05/xmldsig-more#whirlpool' => 'whirlpool',

			'http://www.w3.org/2007/05/xmldsig-more#sha3-224' => 'sha3-224',
			'http://www.w3.org/2007/05/xmldsig-more#sha3-256' => 'sha3-256',
			'http://www.w3.org/2007/05/xmldsig-more#sha3-384' => 'sha3-384',
			'http://www.w3.org/2007/05/xmldsig-more#sha3-512' => 'sha3-512',
		];

		$requestedAlgorithm = $digestMethodNode->getAttribute('Algorithm');

		if (!isset($allowedAlgorithms[$requestedAlgorithm])) {
			// throw exception
		}

		return $allowedAlgorithms[$requestedAlgorithm];
	}

	private function validateLocalReferenceHash($uri, $expectedHash): bool
	{
		return hash_file($this->gethashMethod(), $uri, true) == base64_decode($expectedHash);
	}
}