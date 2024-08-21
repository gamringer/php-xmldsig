<?php

namespace gamringer\xmldsig;

class ReferenceNodeCollection
{
	protected array $idReferences = [];
	protected array $externalReferences = [];

	public function __construct(
		protected \DOMElement $parentNode,
		protected Canonicalizer $canonicalizer,
	) {}

	public function addIdReference(string $id): void
	{
		$this->idReferences[] = $id;
	}

	public function addExternalReference(string $uri, string $digestMethod, string $digestValue): void
	{
		$this->externalReferences[$uri] = [
			'method' => $digestMethod,
			'value' => $digestValue,
		];
	}

	private function getDigestAlgorithmIdentifier(string $digestMethod): string
	{
		return [
			'sha256' => 'http://www.w3.org/2001/04/xmlenc#sha256',
			'sha384' => 'http://www.w3.org/2001/04/xmldsig-more#sha384',
			'sha512' => 'http://www.w3.org/2001/04/xmlenc#sha512',
		][$digestMethod];
	}

	public function calculateReferences(string $digestMethod): void
	{
		if (empty($this->idReferences)) {
			$this->calculateEmptyReference($digestMethod);
			return;
		}

		foreach ($this->idReferences as $idReference) {
			$this->calculateIdReference($idReference, $digestMethod);
		}

		foreach ($this->externalReferences as $uri => $digestInfo) {
			$this->appendExternalReference($uri, $digestInfo);
		}
	}

	private function appendExternalReference(string $uri, array $digestInfo): void
	{
		$referenceNode = $this->parentNode->ownerDocument->createElement('Reference');
		$referenceNode->setAttribute('URI', $uri);
		$this->parentNode->appendChild($referenceNode);

		$digestAlgorithmIdentifier = $this->getDigestAlgorithmIdentifier($digestInfo['method']);
		$digestMethodNode = $this->parentNode->ownerDocument->createElement('DigestMethod');
		$digestMethodNode->setAttribute('Algorithm', $digestAlgorithmIdentifier);
		$referenceNode->appendChild($digestMethodNode);

		$digestValueNode = $this->parentNode->ownerDocument->createElement('DigestValue', base64_encode($digestInfo['value']));
		$referenceNode->appendChild($digestValueNode);
	}

	private function calculateIdReference($id, string $digestMethod): void
	{
		$node = $this->parentNode->ownerDocument->getElementById($id);
		$digestData = $this->canonicalizer->canonicalize($node);

		$referenceNode = $this->parentNode->ownerDocument->createElement('Reference');
		$referenceNode->setAttribute('URI', '#' . $id);
		$this->parentNode->appendChild($referenceNode);

		$transformsNode = $this->parentNode->ownerDocument->createElement('Transforms');
		$referenceNode->appendChild($transformsNode);

		$transformNode = $this->parentNode->ownerDocument->createElement('Transform');
		$transformNode->setAttribute('Algorithm', $this->canonicalizer->getMethodId());
		$transformsNode->appendChild($transformNode);

		$digestAlgorithmIdentifier = $this->getDigestAlgorithmIdentifier($digestMethod);
		$digestMethodNode = $this->parentNode->ownerDocument->createElement('DigestMethod');
		$digestMethodNode->setAttribute('Algorithm', $digestAlgorithmIdentifier);
		$referenceNode->appendChild($digestMethodNode);

		$digestValue = hash($digestMethod, $digestData, true);

		$digestValueNode = $this->parentNode->ownerDocument->createElement('DigestValue', base64_encode($digestValue));
		$referenceNode->appendChild($digestValueNode);
	}

	public function calculateNodeReference(\DOMElement $node, string $digestMethod): \DOMElement
	{
		$id = $node->getAttribute('Id');
		$digestData = $this->canonicalizer->canonicalize($node);

		$referenceNode = $this->parentNode->ownerDocument->createElement('Reference');
		$referenceNode->setAttribute('URI', '#' . $id);
		$this->parentNode->appendChild($referenceNode);

		$transformsNode = $this->parentNode->ownerDocument->createElement('Transforms');
		$referenceNode->appendChild($transformsNode);

		$transformNode = $this->parentNode->ownerDocument->createElement('Transform');
		$transformNode->setAttribute('Algorithm', $this->canonicalizer->getMethodId());
		$transformsNode->appendChild($transformNode);

		$digestAlgorithmIdentifier = $this->getDigestAlgorithmIdentifier($digestMethod);
		$digestMethodNode = $this->parentNode->ownerDocument->createElement('DigestMethod');
		$digestMethodNode->setAttribute('Algorithm', $digestAlgorithmIdentifier);
		$referenceNode->appendChild($digestMethodNode);

		$digestValue = hash($digestMethod, $digestData, true);

		$digestValueNode = $this->parentNode->ownerDocument->createElement('DigestValue', base64_encode($digestValue));
		$referenceNode->appendChild($digestValueNode);

		return $referenceNode;
	}

	private function calculateEmptyReference(string $digestMethod): void
	{
		$rootNodeName = $this->parentNode->ownerDocument->documentElement->nodeName;

		$digestData = $this->canonicalizer->canonicalize($this->parentNode->ownerDocument->documentElement);

		$referenceNode = $this->parentNode->ownerDocument->createElement('Reference');
		$referenceNode->setAttribute('URI', '');
		$this->parentNode->appendChild($referenceNode);

		$transformsNode = $this->parentNode->ownerDocument->createElement('Transforms');
		$referenceNode->appendChild($transformsNode);

		$transformNode = $this->parentNode->ownerDocument->createElement('Transform');
		$transformNode->setAttribute('Algorithm', 'http://www.w3.org/2000/09/xmldsig#enveloped-signature');
		$transformsNode->appendChild($transformNode);

		$transformNode = $this->parentNode->ownerDocument->createElement('Transform');
		$transformNode->setAttribute('Algorithm', $this->canonicalizer->getMethod());
		$transformsNode->appendChild($transformNode);

		$digestAlgorithmIdentifier = $this->getDigestAlgorithmIdentifier($digestMethod);
		$digestMethodNode = $this->parentNode->ownerDocument->createElement('DigestMethod');
		$digestMethodNode->setAttribute('Algorithm', $digestAlgorithmIdentifier);
		$referenceNode->appendChild($digestMethodNode);

		$digestValue = hash($digestMethod, $digestData, true);

		$digestValueNode = $this->parentNode->ownerDocument->createElement('DigestValue', base64_encode($digestValue));
		$referenceNode->appendChild($digestValueNode);
	}
}