<?php

namespace gamringer\xmldsig\ProtocolHandlers;

interface ProtocolHandler
{
	public function getHash(string $uri, string $algorithm): string;
}