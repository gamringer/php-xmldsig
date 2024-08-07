<?php

require __DIR__ . '/../vendor/autoload.php';
require __DIR__ . '/example-common.php';

use gamringer\xmldsig\XMLDSigDocumentFactory;
use gamringer\xmldsig\Canonicalizer;
use gamringer\xmldsig\Validation\OpenSSLCertificateValidator;
use gamringer\xmldsig\Validation\TrustStore;
use gamringer\xmldsig\Validation\Validator;

// Prepare document
$documentFactory = new XMLDSigDocumentFactory();
$dsigDocument = $documentFactory->loadFile(getenv('XMLFILE'));

// Configure validator
$validator = new Validator();
$validator->referenceValidator->baseUri = 'file://' . dirname(realpath(getenv('XMLFILE')));

echo $validator->validateDocument($dsigDocument) ? 'valid' : 'invalid', PHP_EOL;