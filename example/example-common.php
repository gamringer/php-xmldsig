<?php

function getSoftwareKey()
{
    return gamringer\xmldsig\Keys\Pkcs8Key::fromFile(getenv('KEYFILE'));
}

function getHardwareKey()
{
    $p11Module = new \Pkcs11\Module(getenv('MODULEPATH'));
    $p11Session = $p11Module->openSession(getenv('SLOTID'), \Pkcs11\CKF_RW_SESSION);

    $p11Session->login(Pkcs11\CKU_USER, getenv('PIN'));

    return gamringer\xmldsig\Keys\Pkcs11Key::fromUri($p11Session, 'pkcs11:object='.getenv('KEYLABEL').';type=private');
}