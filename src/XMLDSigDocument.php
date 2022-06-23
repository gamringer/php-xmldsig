<?php

namespace gamringer\xmldsig;

class XMLDSigDocument
{
	protected $dom;

	public function __construct(\DOMDocument $dom)
	{
		$this->dom = $dom;
	}

	public function addSignature(?string $id = null): SignatureNode
	{
		$node = $this->dom->createElementNS('http://www.w3.org/2000/09/xmldsig#', 'Signature');
		if ($id !== null) {
			$node->setAttribute('Id', $id);
		}

		return new SignatureNode($node);
	}

	public function getDom(): \DOMDocument
	{
		return $this->dom;
	}

	public function getXml(): string
	{
		return $this->dom->saveXML();
	}
}