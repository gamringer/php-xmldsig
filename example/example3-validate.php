<?php

require __DIR__ . '/../vendor/autoload.php';
require __DIR__ . '/example-common.php';

use gamringer\xmldsig\XMLDSigDocumentFactory;
use gamringer\xmldsig\Canonicalizer;
use gamringer\xmldsig\Validator;

// Prepare document
$documentFactory = new XMLDSigDocumentFactory();
$dsigDocument = $documentFactory->loadFile(getenv('XMLFILE'));

// Prepare Key
$trustStore = new gamringer\xmldsig\TrustStore();
$trustStore->addCertificateFile('example/credential/trust/g1rca1.cer');

// Configure validator
$validator = new Validator();
$validator->trustStore = $trustStore;
$validator->referenceValidator->baseUri = 'file://' . dirname(realpath(getenv('XMLFILE')));

echo $validator->validateDocument($dsigDocument) ? 'valid' : 'invalid', PHP_EOL;