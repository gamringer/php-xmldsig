<?php

namespace gamringer\xmldsig;

class SignatureNode
{
	protected $node;
	protected $signedInfoNode;
	protected $objectNode;
	protected $idReferences = [];
	protected $signaturePropertyNodes = [];
	protected $canonicalizationMethod = CanonicalizationMethod::METHOD_1_0;
	protected $preferredDigestMethod = null;

	public function __construct(\DOMElement $node)
	{
		$this->node = $node;
		$this->signedInfoNode = $node->ownerDocument->createElement('SignedInfo');
		$this->node->appendChild($this->signedInfoNode);
	}

	public function setCanonicalizationMethod(string $canonicalizationMethod): void
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

	public function addIdReference(string $id): void
	{
		$this->idReferences[] = $id;
	}

	public function setPreferredDigestMethod(string $digestMethod): void
	{
		if (!in_array($digestMethod, ['sha256', 'sha384', 'sha512'])) {
			throw new \Exception('Unsupported digest method');
		}

		$this->preferredDigestMethod = $digestMethod;
	}

	private function getDigestAlgorithmIdentifier(string $digestMethod): string
	{
		return [
			'sha256' => 'http://www.w3.org/2001/04/xmlenc#sha256',
			'sha384' => 'http://www.w3.org/2001/04/xmldsig-more#sha384',
			'sha512' => 'http://www.w3.org/2001/04/xmlenc#sha512',
		][$digestMethod];
	}

	private function calculateReferences(string $digestMethod): void
	{
		if (empty($this->idReferences)) {
			$this->calculateEmptyReference($digestMethod);
			return;
		}

		foreach ($this->idReferences as $idReference) {
			$this->calculateIdReference($idReference, $digestMethod);
		}
	}

	private function calculateIdReference($id, string $digestMethod): void
	{
		$node = $this->node->ownerDocument->getElementById($id);
		$digestData = $this->canonicalize($node);

		$referenceNode = $this->node->ownerDocument->createElement('Reference');
		$referenceNode->setAttribute('URI', '#' . $id);
		$this->signedInfoNode->appendChild($referenceNode);

		$transformsNode = $this->node->ownerDocument->createElement('Transforms');
		$referenceNode->appendChild($transformsNode);

		$transformNode = $this->node->ownerDocument->createElement('Transform');
		$transformNode->setAttribute('Algorithm', $this->canonicalizationMethod);
		$transformsNode->appendChild($transformNode);

		$digestAlgorithmIdentifier = $this->getDigestAlgorithmIdentifier($digestMethod);
		$digestMethodNode = $this->node->ownerDocument->createElement('DigestMethod');
		$digestMethodNode->setAttribute('Algorithm', $digestAlgorithmIdentifier);
		$referenceNode->appendChild($digestMethodNode);

		$digestValue = hash($digestMethod, $digestData, true);

		$digestValueNode = $this->node->ownerDocument->createElement('DigestValue', base64_encode($digestValue));
		$referenceNode->appendChild($digestValueNode);
	}

	private function calculateEmptyReference(string $digestMethod): void
	{
		$rootNodeName = $this->node->ownerDocument->documentElement->nodeName;

		$digestData = $this->canonicalize($this->node->ownerDocument->documentElement);

		$referenceNode = $this->node->ownerDocument->createElement('Reference');
		$referenceNode->setAttribute('URI', '');
		$this->signedInfoNode->appendChild($referenceNode);

		$transformsNode = $this->node->ownerDocument->createElement('Transforms');
		$referenceNode->appendChild($transformsNode);

		$transformNode = $this->node->ownerDocument->createElement('Transform');
		$transformNode->setAttribute('Algorithm', 'http://www.w3.org/2000/09/xmldsig#enveloped-signature');
		$transformsNode->appendChild($transformNode);

		$transformNode = $this->node->ownerDocument->createElement('Transform');
		$transformNode->setAttribute('Algorithm', $this->canonicalizationMethod);
		$transformsNode->appendChild($transformNode);

		$digestAlgorithmIdentifier = $this->getDigestAlgorithmIdentifier($digestMethod);
		$digestMethodNode = $this->node->ownerDocument->createElement('DigestMethod');
		$digestMethodNode->setAttribute('Algorithm', $digestAlgorithmIdentifier);
		$referenceNode->appendChild($digestMethodNode);

		$digestValue = hash('sha256', $digestData, true);

		$digestValueNode = $this->node->ownerDocument->createElement('DigestValue', base64_encode($digestValue));
		$referenceNode->appendChild($digestValueNode);

		$this->signedInfoNode->appendChild($referenceNode);
	}

	private function getDigestMethod(string $signatureMethod): string
	{
		if (isset($this->preferredDigestMethod)) {
			return $this->preferredDigestMethod;
		}

		return [
			'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256' => 'sha256',
			'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256' => 'sha256',
			'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384' => 'sha384',
			'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512' => 'sha512',
		][$signatureMethod];
	}

	public function getSignatureData(string $signatureMethod): string
	{
		$canonicalizationMethodNode = $this->node->ownerDocument->createElement('CanonicalizationMethod');
		$canonicalizationMethodNode->setAttribute('Algorithm', $this->canonicalizationMethod);
		$this->signedInfoNode->appendChild($canonicalizationMethodNode);

		$signatureMethodNode = $this->node->ownerDocument->createElement('SignatureMethod');
		$signatureMethodNode->setAttribute('Algorithm', $signatureMethod);
		$this->signedInfoNode->appendChild($signatureMethodNode);

		$digestMethod = $this->getDigestMethod($signatureMethod);

		$this->calculateReferences($digestMethod);
		$this->addObjectElements();

		$this->node->ownerDocument->documentElement->appendChild($this->node);

		return $this->canonicalize($this->signedInfoNode);
	}

	protected function canonicalize(\DOMNode $node): string
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

	public function setSignature(string $value, ?string $cert = null, array $chain = [])
	{
		if (isset($this->objectNode)) {
			$this->node->removeChild($this->objectNode);
		}

		$signatureValueNode = $this->node->ownerDocument->createElement('SignatureValue', $value);
		$this->node->appendChild($signatureValueNode);

		if ($cert !== null) {
			$keyInfoNode = $this->node->ownerDocument->createElement('KeyInfo');
			$this->node->appendChild($keyInfoNode);

			$x509DataNode = $this->node->ownerDocument->createElement('X509Data');
			$keyInfoNode->appendChild($x509DataNode);

			$x509CertificateNode = $this->node->ownerDocument->createElement('X509Certificate', $cert);
			$x509DataNode->appendChild($x509CertificateNode);

			foreach ($chain as $element) {
				$x509CertificateNode = $this->node->ownerDocument->createElement('X509Certificate', $element);
				$x509DataNode->appendChild($x509CertificateNode);
			}
		}

		if (isset($this->objectNode)) {
			$this->node->appendChild($this->objectNode);
		}
	}

	public function addSignatureProperty(string $id): \DOMElement
	{
		$node = $this->node->ownerDocument->createElement('SignatureProperty');
		$node->setAttribute('Id', $id);
		$node->setAttribute('Target', '#' . $this->node->getAttribute('Id'));

		$this->signaturePropertyNodes[] = $node;

		return $node;
	}

	private function addObjectElements(): void
	{
		$this->objectNode = $this->node->ownerDocument->createElement('Object');

		if (!empty($this->signaturePropertyNodes)) {
			$signaturePropertiesNode = $this->node->ownerDocument->createElement('SignatureProperties');
			$this->objectNode->appendChild($signaturePropertiesNode);
			foreach ($this->signaturePropertyNodes as $signaturePropertyNode) {
				$signaturePropertiesNode->appendChild($signaturePropertyNode);
			}
		}

		if ($this->objectNode->childNodes->count() > 0) {
			$this->node->appendChild($this->objectNode);
		}
	}
}