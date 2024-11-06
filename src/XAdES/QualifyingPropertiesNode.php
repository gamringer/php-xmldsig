<?php

namespace gamringer\xmldsig\XAdES;

use gamringer\xmldsig\SignatureNode;
use gamringer\xmldsig\Util\Digest;
use gamringer\xmldsig\Util\CertificateCodec;
use DOMElement;

class QualifyingPropertiesNode
{
	public const URI = 'http://uri.etsi.org/01903/v1.1.1#';

	protected DOMElement $node;
	protected DOMElement $signedPropertiesNode;
	protected DOMElement $signedSignaturePropertiesNode;
	protected DOMElement $unsignedPropertiesNode;
	protected DOMElement $signingTimeNode;
	protected DOMElement $signingCertificateNode;
	protected DOMElement $signaturePolicyIdentifierNode;

	public function __construct(
		protected SignatureNode $signatureNode
	) {
		$this->node = $this->signatureNode->getNode()->ownerDocument->createElement('QualifyingProperties');
		$this->node->setAttributeNS('http://www.w3.org/2000/xmlns/' ,'xmlns', self::URI);
		$this->node->setAttributeNS('http://www.w3.org/2000/xmlns/' ,'xmlns:ds', SignatureNode::URI);
		$this->node->setAttribute('Target', '#' . $this->signatureNode->getNode()->getAttribute('Id'));

		$foo = $this->signatureNode->getNode()->ownerDocument->createElement('SignaturePolicyImplied');
		$this->getSignaturePolicyIdentifierNode()->appendChild($foo);

	}

	public function getNode(): DOMElement
	{
		return $this->node;
	}

	public function setSigningTime(\DateTimeInterface $datetime): void
	{
		$this->getSigningTimeNode()->textContent = $datetime->format('c');
	}

	public function setSigningCertificate(string $cert): void
	{

		//<SigningCertificate>
		//	<Cert>
		//		...
		//		<IssuerSerial> <!-- ds:X509IssuerSerialType -->
		//			<ds:X509IssuerName>CN=Let's Encrypt Authority X3, O=Let's Encrypt, C=US</ds:X509IssuerName>
		//			<ds:X509SerialNumber>307228618548093469617232206275864271231086</ds:X509SerialNumber>
		//		</IssuerSerial>
		//	</Cert>
		//</SigningCertificate>
		$hashid = 'http://www.w3.org/2001/04/xmldsig-more#sha384';
		$hash = Digest::hash($hashid, base64_decode($cert));
		$parsed = openssl_x509_parse(CertificateCodec::b642pem($cert));

		$certNode = $this->signatureNode->getNode()->ownerDocument->createElement('Cert');

		$certDigestNode = $this->signatureNode->getNode()->ownerDocument->createElement('CertDigest');
		$certNode->appendChild($certDigestNode);

		$digestMethodNode = $this->signatureNode->getNode()->ownerDocument->createElement('DigestMethod');
		$digestMethodNode->textContent = $hashid;
		$certDigestNode->appendChild($digestMethodNode);

		$digestValueNode = $this->signatureNode->getNode()->ownerDocument->createElement('DigestValue');
		$digestValueNode->textContent = base64_encode($hash);
		$certDigestNode->appendChild($digestValueNode);

		$issuerSerialNode = $this->signatureNode->getNode()->ownerDocument->createElement('IssuerSerial');
		$certNode->appendChild($issuerSerialNode);

		$issuerNameNode = $this->signatureNode->getNode()->ownerDocument->createElement('ds:X509IssuerName');
		$issuerNameNode->textContent = CertificateCodec::issuerString($parsed['issuer']);
		$certDigestNode->appendChild($issuerNameNode);

		$serialNumberNode = $this->signatureNode->getNode()->ownerDocument->createElement('ds:X509SerialNumber');
		$serialNumberNode->textContent = base64_encode($parsed['serialNumberHex']);
		$certDigestNode->appendChild($serialNumberNode);

		foreach ($this->getSigningCertificateNode()->childNodes as $child) {
			$child->remove();
		}

		$this->getSigningCertificateNode()->appendChild($certNode);
	}

	private function getSignaturePolicyIdentifierNode(): DOMElement
	{
		if (!isset($this->signaturePolicyIdentifierNode)) {
			$this->signaturePolicyIdentifierNode = $this->signatureNode->getNode()->ownerDocument->createElement('SignaturePolicyIdentifier');
			$this->getSignedSignaturePropertiesNode()->appendChild($this->signaturePolicyIdentifierNode);
		}

		return $this->signaturePolicyIdentifierNode;
	}

	private function getSigningCertificateNode(): DOMElement
	{
		if (!isset($this->signingCertificateNode)) {
			$this->signingCertificateNode = $this->signatureNode->getNode()->ownerDocument->createElement('SigningCertificate');
			$this->getSignedSignaturePropertiesNode()->appendChild($this->signingCertificateNode);
		}

		return $this->signingCertificateNode;
	}

	private function getSigningTimeNode(): DOMElement
	{
		if (!isset($this->signingTimeNode)) {
			$this->signingTimeNode = $this->signatureNode->getNode()->ownerDocument->createElement('SigningTime');
			$this->getSignedSignaturePropertiesNode()->appendChild($this->signingTimeNode);
		}

		return $this->signingTimeNode;
	}

	private function getSignedSignaturePropertiesNode(): DOMElement
	{
		if (!isset($this->signedSignaturePropertiesNode)) {
			$this->signedSignaturePropertiesNode = $this->signatureNode->getNode()->ownerDocument->createElement('SignedSignatureProperties');
			$this->getSignedPropertiesNode()->appendChild($this->signedSignaturePropertiesNode);
		}

		return $this->signedSignaturePropertiesNode;
	}

	private function getSignedPropertiesNode(): DOMElement
	{
		if (!isset($this->signedPropertiesNode)) {
			$this->signedPropertiesNode = $this->signatureNode->getNode()->ownerDocument->createElement('SignedProperties');
			$this->node->appendChild($this->signedPropertiesNode);
		}

		return $this->signedPropertiesNode;
	}
}