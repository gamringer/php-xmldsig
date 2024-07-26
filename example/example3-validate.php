<?php

require __DIR__ . '/../vendor/autoload.php';
require __DIR__ . '/example-common.php';

use gamringer\xmldsig\XMLDSigDocumentFactory;
use gamringer\xmldsig\Canonicalizer;
use gamringer\xmldsig\Validator;

// Prepare document
$xml = file_get_contents(getenv('XMLFILE'));
$documentFactory = new XMLDSigDocumentFactory();
$dsigDocument = $documentFactory->loadXml($xml);

// Prepare Key
$trustStore = new gamringer\xmldsig\TrustStore();
$trustStore->addCertificateFile('example/credential/trust/g1rca1.cer');

// Configure signature
//$signatureNode = $dsigDocument->getSignature('signature1');

// Configure validator
$validator = new Validator();
$validator->setTrustStore($trustStore);

echo $validator->validateDocument($dsigDocument) ? 'valid' : 'invalid', PHP_EOL;