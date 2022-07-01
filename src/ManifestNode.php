<?php

namespace gamringer\xmldsig;

class ManifestNode
{
	protected $node;
	protected $canonicalizer;
	protected $referenceNodeCollection;

	public function __construct(\DOMElement $node)
	{
		$this->node = $node;

		$this->canonicalizer = new Canonicalizer();
		$this->referenceNodeCollection = new ReferenceNodeCollection($this->node, $this->canonicalizer);
	}

	public function getNode(): \DOMElement
	{
		return $this->node;
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

}