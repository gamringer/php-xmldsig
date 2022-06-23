<?php

namespace gamringer\xmldsig;

class XMLDSigDocumentFactory
{
	public function loadFile(string $path): XMLDSigDocument
	{
		$xml = file_get_contents($path);
		return $this->loadXml($xml);
	}

	public function loadXml(string $xml): XMLDSigDocument
	{
		$dom = new \DOMDocument();
		$dom->loadXML($xml);

		return $this->loadDom($dom);
	}

	public function loadDom(\DOMDocument $dom): XMLDSigDocument
	{
		$dom->preserveWhiteSpace = true;
		return new XMLDSigDocument($dom);
	}
}