<?php

namespace gamringer\xmldsig;

class SignatureNode
{
	protected $node;
	protected $signedInfoNode;
	protected $referenceNodeCollection;
	protected $canonicalizer;
	protected $objectNode;
	protected $idReferences = [];
	protected $signaturePropertyNodes = [];
	protected $manifestNodes = [];
	protected $canonicalizationMethod = Canonicalizer::METHOD_1_0;
	protected $preferredDigestMethod = null;

	public function __construct(\DOMElement $node)
	{
		$this->node = $node;
		$this->signedInfoNode = $node->ownerDocument->createElement('SignedInfo');
		$this->node->appendChild($this->signedInfoNode);

		$this->canonicalizer = new Canonicalizer();
		$this->referenceNodeCollection = new ReferenceNodeCollection($this->signedInfoNode, $this->canonicalizer);
	}

	public function getReferenceNodeCollection(): ReferenceNodeCollection
	{
		return $this->referenceNodeCollection;
	}

	public function getCanonicalizer(): Canonicalizer
	{
		return $this->canonicalizer;
	}

	public function setCanonicalizer(Canonicalizer $canonicalizer): void
	{
		$this->canonicalizer = $canonicalizer;
	}

	public function setPreferredDigestMethod(string $digestMethod): void
	{
		if (!in_array($digestMethod, ['sha256', 'sha384', 'sha512'])) {
			throw new \Exception('Unsupported digest method');
		}

		$this->preferredDigestMethod = $digestMethod;
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

		$this->referenceNodeCollection->calculateReferences($digestMethod);

		$this->node->ownerDocument->documentElement->appendChild($this->node);

		$this->addObjectElements();
		$this->addObjectReferences($digestMethod);

		return $this->canonicalizer->canonicalize($this->signedInfoNode);
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

	public function addManifest(string $id): ManifestNode
	{
		$node = $this->node->ownerDocument->createElement('Manifest');
		$node->setAttribute('Id', $id);

		$manifestNode = new ManifestNode($node);

		$this->manifestNodes[] = $manifestNode;

		return $manifestNode;
	}

	public function addSignatureProperty(string $id): \DOMElement
	{
		$node = $this->node->ownerDocument->createElement('SignatureProperty');
		$node->setAttribute('Id', $id);
		$node->setAttribute('Target', '#' . $this->node->getAttribute('Id'));

		$this->signaturePropertyNodes[] = $node;

		return $node;
	}

	private function addObjectReferences(string $digestMethod): void
	{
		if (!empty($this->signaturePropertyNodes)) {
			foreach ($this->signaturePropertyNodes as $signaturePropertyNode) {
				$this->referenceNodeCollection->calculateNodeReference($signaturePropertyNode, $digestMethod);
			}
		}

		foreach ($this->manifestNodes as $manifestNode) {
			$manifestNode->getReferenceNodeCollection()->calculateReferences($digestMethod);
			$this->referenceNodeCollection->calculateNodeReference($manifestNode->getNode(), $digestMethod);
		}
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

		foreach ($this->manifestNodes as $manifestNode) {
			$this->objectNode->appendChild($manifestNode->getNode());
		}

		if ($this->objectNode->childNodes->count() == 0) {
			unset($this->objectNode);
			return;
		}

		$this->node->appendChild($this->objectNode);
	}
}