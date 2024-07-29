<?php

namespace gamringer\xmldsig\ProtocolHandlers;

use gamringer\xmldsig\Exceptions\ProtocolHandlerException;
use gamringer\xmldsig\Exceptions\ResourceRetrievalException;

class FileProtocolHandler implements ProtocolHandler
{
	public function getHash(string $uri, string $algorithm): string
	{
		if (substr($uri, 0, 7) != 'file://') {
			throw new ProtocolHandlerException('Unhandled protocol');
		}

		$path = substr($uri, 7);

		if (!file_exists($path)) {
			throw new ResourceRetrievalException('File not found');
		}

		return hash_file($algorithm, $path, true);
	}
}