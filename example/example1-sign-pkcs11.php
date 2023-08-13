<?php

require __DIR__ . '/../vendor/autoload.php';

use gamringer\xmldsig\XMLDSigDocumentFactory;
use gamringer\xmldsig\Canonicalizer;

// Prepare document
$xml = file_get_contents(getenv('XMLFILE'));

// Prepare Key
$p11Module = new \Pkcs11\Module(getenv('MODULEPATH'));
$p11Session = $p11Module->openSession(getenv('SLOTID'), \Pkcs11\CKF_RW_SESSION);

$p11Session->login(Pkcs11\CKU_USER, getenv('PIN'));
$key = gamringer\xmldsig\Keys\Pkcs11Key::fromUri($p11Session, 'pkcs11:object='.getenv('KEYLABEL').';type=private');

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
$signatureNode->getReferenceNodeCollection()->addExternalReference(__FILE__, 'sha256', hash('sha256', file_get_contents(__FILE__), true));
$signatureNode->getCanonicalizer()->setMethod(Canonicalizer::METHOD_1_0);
$signatureNode->setPreferredDigestMethod('sha384');

$manifestNode = $signatureNode->addManifest('some-manifest-id');
$manifestNode->getReferenceNodeCollection()->addIdReference('foo');
$manifestNode->getReferenceNodeCollection()->addExternalReference(__FILE__, 'sha256', hash('sha256', file_get_contents(__FILE__), true));

$signaturePropertyNode = $signatureNode->addSignatureProperty('some-signature-property-id');
$signaturePropertyNode->appendChild($dsigDocument->getDom()->createElement('SignatureTime', date('c')));

// Sign
$key->sign($signatureNode);

echo $dsigDocument->getXml();
