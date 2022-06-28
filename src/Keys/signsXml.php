<?php

namespace gamringer\xmldsig\Keys;

use gamringer\xmldsig\SignatureNode;

interface signsXml
{
	public function sign(SignatureNode $dsigNode): void;
}