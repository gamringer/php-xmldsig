<?php

namespace gamringer\xmldsig;

class XMLDSigDocument
{
	public function __construct(
		protected \DOMDocument $dom,
	) {}

	public function addSignature(?string $id = null): SignatureNode
	{
		$node = $this->dom->createElementNS(SignatureNode::URI, 'Signature');
		if ($id !== null) {
			$node->setAttribute('Id', $id);
		}

		$sn = SignatureNode::initialize($node);

		return $sn;
	}

	public function getDom(): \DOMDocument
	{
		return $this->dom;
	}

	public function getXml(): string
	{
		return $this->dom->saveXML();
	}

	public function getSignature(string $id): SignatureNode
	{
		$nodes = $this->dom->getElementsByTagNameNS(SignatureNode::URI, 'Signature');
		foreach ($nodes as $node) {
			if ($node->getAttribute('Id') == $id) {
				break;
			}
		}

		return SignatureNode::load($node);
	}

	public function getAllSignatures(): array
	{
		$output = [];

		$nodes = $this->dom->getElementsByTagNameNS(SignatureNode::URI, 'Signature');
		foreach ($nodes as $node) {
			$output[] = SignatureNode::load($node);
		}

		return $output;
	}
}