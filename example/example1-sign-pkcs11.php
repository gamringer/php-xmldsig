<?php

require __DIR__ . '/../vendor/autoload.php';
require __DIR__ . '/example-common.php';

use gamringer\xmldsig\XMLDSigDocumentFactory;
use gamringer\xmldsig\Canonicalizer;
use gamringer\xmldsig\CanonicalizationMethod;

// Prepare document
$xml = file_get_contents(getenv('XMLFILE'));

// Prepare Key
$key = getHardwareKey();
$key->setCertificate(
    file_get_contents(getenv('CERTFILE')),
    [
        file_get_contents(getenv('CAFILE')),
    ]
);

// Load document
$signer = new XMLDSigDocumentFactory();
$dsigDocument = $signer->loadXml($xml);

// Configure signature
$signatureNode = $dsigDocument->addSignature('signature1');
$signatureNode->getReferenceNodeCollection()->addIdReference('foo');
$signatureNode->getReferenceNodeCollection()->addIdReference('bar');
$signatureNode->getReferenceNodeCollection()->addExternalReference(
    __FILE__,
    'sha256',
    hash('sha256', file_get_contents(__FILE__), true)
);
$signatureNode->getCanonicalizer()->setMethod(CanonicalizationMethod::METHOD_1_0);
$signatureNode->setPreferredDigestMethod('sha384');

$manifestNode = $signatureNode->addManifest('some-manifest-id');
$manifestNode->getReferenceNodeCollection()->addIdReference('foo');
$manifestNode->getReferenceNodeCollection()->addExternalReference(
    __FILE__,
    'sha256',
    hash('sha256', file_get_contents(__FILE__), true)
);

$signaturePropertyNode = $signatureNode->addSignatureProperty('some-signature-property-id');
$signaturePropertyNode->appendChild($dsigDocument->getDom()->createElement('SignatureTime', date('c')));

// Sign
$key->sign($signatureNode);

$dsigDocument->getDom()->formatOutput = true;
echo $dsigDocument->getXml();

