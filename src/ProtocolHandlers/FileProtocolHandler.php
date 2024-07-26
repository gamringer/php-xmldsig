<?php

namespace gamringer\xmldsig\ProtocolHandlers;

class FileProtocolHandler implements ProtocolHandler
{
	public function getHash(string $uri, string $algorithm): string
	{
		if (substr($uri, 0, 7) != 'file://') {
			throw new \Exception('Unhandled protocol');
		}

		$path = substr($uri, 7);

		if (!file_exists($path)) {
			throw new \Exception('File not found');
		}

		return hash_file($algorithm, $path, true);
	}
}