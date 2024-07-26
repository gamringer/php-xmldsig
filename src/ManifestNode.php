<?php

namespace gamringer\xmldsig;

class ManifestNode
{
	protected Canonicalizer $canonicalizer;
	protected ReferenceNodeCollection $referenceNodeCollection;

	public function __construct(
		protected \DOMElement $node,
	) {
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