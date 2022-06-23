<?php

namespace gamringer\xmldsig;

class SignatureNode
{
	protected $node;
	protected $signedInfoNode;
	protected $references = [];

	public function __construct(\DOMElement $node)
	{
		$this->node = $node;
		$this->signedInfoNode = $node->ownerDocument->createElement('SignedInfo');
		$this->node->appendChild($this->signedInfoNode);

		$canonicalizationMethodNode = $node->ownerDocument->createElement('CanonicalizationMethod');
		$canonicalizationMethodNode->setAttribute('Algorithm', 'http://www.w3.org/2001/10/xml-exc-c14n#');
		$this->signedInfoNode->appendChild($canonicalizationMethodNode);
	}

	public function addIdReference(string $id, string $digestMethod = 'sha256'): void
	{
		$node = $this->node->ownerDocument->getElementById($id);
		$digestData = $node->C14N(true, false);

		$referenceNode = $this->node->ownerDocument->createElement('Reference');
		$referenceNode->setAttribute('URI', '#' . $id);

		$digestMethodNode = $this->node->ownerDocument->createElement('DigestMethod');
		$digestMethodNode->setAttribute('Algorithm', 'http://www.w3.org/2001/04/xmlenc#sha256');
		$referenceNode->appendChild($digestMethodNode);

		$digestValue = hash('sha256', $digestData, true);

		$digestValueNode = $this->node->ownerDocument->createElement('DigestValue', base64_encode($digestValue));
		$referenceNode->appendChild($digestValueNode);

		$this->references[] = $referenceNode;
	}

	private function addEmptyReference(string $digestMethod = 'sha256'): void
	{
		$rootNodeName = $this->node->ownerDocument->documentElement->nodeName;

		$digestData = $this->node->ownerDocument->documentElement->C14N(true, false);

		$referenceNode = $this->node->ownerDocument->createElement('Reference');
		$referenceNode->setAttribute('URI', '');
		$this->signedInfoNode->appendChild($referenceNode);

		$transformsNode = $this->node->ownerDocument->createElement('Transforms');
		$referenceNode->appendChild($transformsNode);

		$transformNode = $this->node->ownerDocument->createElement('Transform');
		$transformNode->setAttribute('Algorithm', 'http://www.w3.org/2000/09/xmldsig#enveloped-signature');
		$transformsNode->appendChild($transformNode);

		$digestMethodNode = $this->node->ownerDocument->createElement('DigestMethod');
		$digestMethodNode->setAttribute('Algorithm', 'http://www.w3.org/2001/04/xmlenc#sha256');
		$referenceNode->appendChild($digestMethodNode);

		$digestValue = hash('sha256', $digestData, true);

		$digestValueNode = $this->node->ownerDocument->createElement('DigestValue', base64_encode($digestValue));
		$referenceNode->appendChild($digestValueNode);
	}

	public function getSignatureData(string $method): string
	{
		$signatureMethodNode = $this->node->ownerDocument->createElement('SignatureMethod');
		$signatureMethodNode->setAttribute('Algorithm', $method);
		$this->signedInfoNode->appendChild($signatureMethodNode);

		if (empty($this->references)) {
			$this->addEmptyReference();
		}

		foreach ($this->references as $referenceNode) {
			$this->signedInfoNode->appendChild($referenceNode);
		}

		$this->node->ownerDocument->documentElement->appendChild($this->node);

		return $this->signedInfoNode->C14N(true, false);
	}

	public function setSignature(string $value, ?string $cert = null, array $chain = [])
	{
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
	}
}