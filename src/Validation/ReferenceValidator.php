<?php

namespace gamringer\xmldsig\Validation;

use gamringer\xmldsig\SignatureNode;
use gamringer\xmldsig\TransformFactory;
use gamringer\xmldsig\Exceptions\ValidationRuntimeError;
use gamringer\xmldsig\Exceptions\UnsupportedAlgorithmException;
use gamringer\xmldsig\ProtocolHandlers\FileProtocolHandler;
use gamringer\xmldsig\ProtocolHandlers\ProtocolHandler;

class ReferenceValidator
{
	public string $baseUri;
	protected array $protocolHandlers = [];

	public function __construct()
	{
		$this->baseUri = getcwd();
		$this->setProtocolHandler('file', new FileProtocolHandler());
	}

	public function setProtocolHandler(string $protocol, ProtocolHandler $handler): void
	{
		if (!preg_match('/^[a-z][a-z0-9+-.]*$/i', $protocol)) {
			// throw
		}

		$this->protocolHandlers[$protocol] = $handler;
	}

	public function validate(\DOMElement $element): bool
	{
		$uri = $element->getAttribute('URI');

		$digestValueNodes = $element->getElementsByTagNameNS(SignatureNode::URI, 'DigestValue');
		if ($digestValueNodes->count() == 0) {
			// throw exception
		}
		if ($digestValueNodes->count() > 1) {
			// throw exception
		}

		if ($uri[0] == '#') {
			return $this->validateIdReferenceHash($element, $uri, $digestValueNodes[0]->nodeValue);
		}

		$uri = $this->absolutizePath($uri);

		return $this->validateSchemeReferenceHash($element, $uri, $digestValueNodes[0]->nodeValue);
	}

	private function validateIdReferenceHash($element, $uri, $expectedHash): bool
	{
		$hashTarget = $element->ownerDocument->getElementById(substr($uri, 1));
		$transformFactory = new TransformFactory();
		$transformNodeList = $element->getElementsByTagNameNS(SignatureNode::URI, 'Transform');
		foreach ($transformNodeList as $transformNode) {
			$transform = $transformFactory->produceTransform($transformNode);
			$hashTarget = $transform->transform($hashTarget);
		}

		$hash = hash($this->gethashMethod($element), $hashTarget, true);

		return hash_equals($hash, base64_decode($expectedHash));
	}

	private function gethashMethod($element): string
	{
		$digestMethodNodes = $element->getElementsByTagNameNS(SignatureNode::URI, 'DigestMethod');
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

	private function validateSchemeReferenceHash($element, $uri, $expectedHash): bool
	{
		$uriReferenceParts = parse_url($uri);

		if (!isset($this->protocolHandlers[$uriReferenceParts['scheme']])) {
			// throw
		}

		$hash = $this->protocolHandlers[$uriReferenceParts['scheme']]->getHash($uri, $this->gethashMethod($element));

		return hash_equals($hash, base64_decode($expectedHash));
	}

	private function absolutizePath($uri): string
	{
		// Check if URI supplies a scheme
		if (preg_match('/^[a-z][a-z0-9+-.]*:/i', $uri)) {
			return $uri;
		}

		if ($this->baseUri === null) {
			throw new \Exception('Base URI is not defined');
		}

		// Check if the scheme-specific part of the reference URI is opaque
		if (preg_match('/^[a-z][a-z0-9+-.]*:[a-z0-9\-_.!~*\'();?:@&=+$,]/i', $this->baseUri)) {
			throw new \Exception('Base URI scheme does not allow relative URI references');
		}

		$authority = $this->getAuthority($this->baseUri);

		$uriReferenceParts = parse_url($this->baseUri);

		$referencePath = dirname($uriReferenceParts['path'] . '/.');

		if (substr($uri, 0, 2) == '//') {
			return $uriReferenceParts['scheme'] . '//' . $uri;
		}

		if (substr($uri, 0, 1) == '/') {
			return $uriReferenceParts['scheme'] . '://' . $authority . $uri;
		}

		return $uriReferenceParts['scheme'] . '://' . $authority . $referencePath . '/' . $uri;
	}

	private function getAuthority($reference): string
	{
		$uriReferenceParts = parse_url($reference);

		if (!isset($uriReferenceParts['host'])) {
			return '';
		}

		$userinfo = '';
		if (isset($uriReferenceParts['user'])) {
			$userinfo = $uriReferenceParts['user'];
			if (isset($uriReferenceParts['pass'])) {
				$userinfo .= ':' . $uriReferenceParts['pass'];
			}
			$userinfo .= '@';
		}

		$authority = $userinfo . $uriReferenceParts['host'];
		if (isset($uriReferenceParts['port'])) {
			$authority .= ':' . $uriReferenceParts['port'];
		}

		return $authority;
	}
}