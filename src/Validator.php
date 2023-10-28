<?php

namespace gamringer\xmldsig;

use gamringer\xmldsig\Keys\X509Certificate;
use gamringer\xmldsig\Validation\ReferenceNodeValidationTarget;
use gamringer\xmldsig\Exceptions\NoSignatureException;
use gamringer\xmldsig\Exceptions\ValidationRuntimeError;
use gamringer\xmldsig\Exceptions\UnsupportedAlgorithmException;

class Validator
{
	protected $trustStore;

	public function setTrustStore(TrustStore $value): void
	{
		$this->trustStore = $value;
	}

	public function validateDocument(XMLDSigDocument $document): bool
	{
		$signatureNodes = $document->getAllSignatures();
		if (empty($signatureNodes)) {
			throw new NoSignatureException();
		}

		foreach ($document->getAllSignatures() as $signatureNode) {
			if (!$this->validateSignatureNode($signatureNode)) {
				return false;
			}
		}

		return true;
	}

	public function validateSignatureNode(SignatureNode $node): bool
	{
		if (!$this->validateReferences($node)) {
			return false;
		}

		if (!$this->validateSignatureValue($node)) {
			return false;
		}

		if (!$this->validateCertificate($node)) {
			return false;
		}

		return true;
	}

	private function validateReferences(SignatureNode $node): bool
	{
		$result = true;
		$referenceNodes = $node->getSignedInfoNode()->getElementsByTagNameNS(SignatureNode::URI, 'Reference');
		foreach ($referenceNodes as $referenceNode) {
			$referenceNodeTarget = new ReferenceNodeValidationTarget($referenceNode);
			$r = $referenceNodeTarget->validate();
			$result = $result && $r;
		}

		return $result;
	}

	private function validateSignatureValue(SignatureNode $node): bool
	{
		$signatureData = $node->getSignatureData();
		$signingCert = $this->getSigningCert($node);

		$sigAlg = $this->getSigningHashAlg($node);

		$r = openssl_verify($node->getSignatureData(), base64_decode($node->getSignatureValue()), $signingCert->getResource(), $sigAlg);
		if ($r === false || $r === -1) {
			throw new ValidationRuntimeError('Openssl unable to verify signature: ' . openssl_error_string());
		}

		return $r === 1;
	}

	private function getSigningHashAlg(SignatureNode $node): int
	{
		$sigMethodNodes = $node->getSignedInfoNode()->getElementsByTagNameNS(SignatureNode::URI, 'SignatureMethod');
		if ($sigMethodNodes->length != 1) {
			throw new ValidationRuntimeError('Unable to find signature algorithm');
		}

		$allowedAlgorithms = [
			'http://www.w3.org/2001/04/xmldsig-more#rsa-sha224' => \OPENSSL_ALGO_SHA224,
			'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256' => \OPENSSL_ALGO_SHA256,
			'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384' => \OPENSSL_ALGO_SHA384,
			'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512' => \OPENSSL_ALGO_SHA512,
			'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha224' => \OPENSSL_ALGO_SHA224,
			'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256' => \OPENSSL_ALGO_SHA256,
			'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384' => \OPENSSL_ALGO_SHA384,
			'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512' => \OPENSSL_ALGO_SHA512,
		];

		if (!isset($allowedAlgorithms[$sigMethodNodes->item(0)->getAttribute('Algorithm')])) {
			throw new UnsupportedAlgorithmException('Unsupported signature algorithm');
		}

		return $allowedAlgorithms[$sigMethodNodes->item(0)->getAttribute('Algorithm')];
	}

	private function validateCertificate(SignatureNode $node): bool
	{
		return true;
	}

	private function getSigningCert(SignatureNode $node): ?X509Certificate
	{
		$x509DataNodeList = $node->getNode()->getElementsByTagNameNS(SignatureNode::URI, 'X509Certificate');
		$certs = [];
		$eeCert = null;
		foreach ($x509DataNodeList as $x509DataNode) {
			$certificate = new X509Certificate("-----BEGIN CERTIFICATE-----\n" . $x509DataNode->nodeValue . "\n-----END CERTIFICATE-----");
			$parsed = $certificate->getParsed();
			if (strpos($parsed['extensions']['basicConstraints'], 'CA:FALSE') !== false) {
				$eeCert = $certificate;
				continue;
			}

			$certs[json_encode($parsed['subject'])] = $certificate;
		}

		if ($eeCert === null) {
			return null;
		}

		if (isset($certs[json_encode($eeCert->getParsed()['issuer'])])) {
			$possibleIssuer = $certs[json_encode($eeCert->getParsed()['issuer'])];
			if ($possibleIssuer->getParsed()['extensions']['subjectKeyIdentifier'] == $eeCert->getParsed()['extensions']['authorityKeyIdentifier']) {
				$eeCert->setIssuer($certs[json_encode($eeCert->getParsed()['issuer'])]);
			}
		}

		foreach ($certs as $cert) {
			if (isset($certs[json_encode($cert->getParsed()['issuer'])])) {
				$possibleIssuer = $certs[json_encode($cert->getParsed()['issuer'])];
				if ($possibleIssuer->getParsed()['extensions']['subjectKeyIdentifier'] == $cert->getParsed()['extensions']['authorityKeyIdentifier']) {
					$cert->setIssuer($certs[json_encode($cert->getParsed()['issuer'])]);
				}
			}
		}

		return $eeCert;
	}
}