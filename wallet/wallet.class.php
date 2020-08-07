<?php
require_once __DIR__ . "/secp256k1.class.php";
require_once __DIR__ . "/common/rc4.php";

class Wallet
{
    // seed of private key
    private $PrivateSeed;

    function __construct()
    {
        // do nothing here now.
        $this->PrivateSeed = NULL;
    }

    public function CreateWallet()
    {
        if ($this->PrivateSeed) {
            return FALSE;
        }
        $secp256k1 = new Secp256k1();
        if ($secp256k1->GeneratePrivateKey()) {
            $this->PrivateSeed = $secp256k1->PrivateKey;
            return TRUE;
        }
        return FALSE;
    }

    private function EncryptData($data, $password)
    {
        return rc4($data, $password);
    }

    public function LoadWallet($filename, $password)
    {
        $secp256k1 = new Secp256k1();
        $data = file_get_contents($filename);
        
        $KeyString = $this->EncryptData($data, $password);

        if ($secp256k1->LoadPrivateKey($KeyString)) {
            $this->PrivateSeed = $secp256k1->PrivateKey;
            return TRUE;
        }
        return FALSE;
    }

    public function ExportWallet($filename, $password)
    {
        $data = $this->EncryptData($this->PrivateSeed, $password);
        $fp = fopen($filename, $data);
        fwrite($fp, $data);
        fclose($fp);
    }

    public function ImportWallet($KeyString)
    {
        if ($this->PrivateSeed) {
            return FALSE;
        }
        $secp256k1 = new Secp256k1();
        if ($secp256k1->LoadPrivateKey($KeyString)) {
            $this->PrivateSeed = $secp256k1->PrivateKey;
            return TRUE;
        }
        return FALSE;
    }

    public function GetCard($Index)
    {
        if (NULL == $this->PrivateSeed || 0 == $Index) {
            return FALSE;
        }
        $secp256k1 = new Secp256k1();
        return $secp256k1->PrivateKeyTweak($Index);
    }
}
