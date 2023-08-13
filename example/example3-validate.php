<?php

require __DIR__ . '/../vendor/autoload.php';

use gamringer\xmldsig\XMLDSigDocumentFactory;
use gamringer\xmldsig\Canonicalizer;
use gamringer\xmldsig\Validator;

// Prepare document
$xml = file_get_contents(getenv('XMLFILE'));

// Prepare Key
$trustStore = new gamringer\xmldsig\TrustStore();
$trustStore->addCertificateFile('example/credential/trust/g1rca1.cer');

// Load document
$documentFactory = new XMLDSigDocumentFactory();
$dsigDocument = $documentFactory->loadXml($xml);

// Configure signature
$signatureNode = $dsigDocument->getSignature('signature1');

// Configure validator
$validator = new Validator();
$validator->setTrustStore($trustStore);

echo $validator->validateDocument($dsigDocument) ? 'valid' : 'invalid', PHP_EOL;