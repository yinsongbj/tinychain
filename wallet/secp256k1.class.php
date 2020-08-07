<?php

class Secp256k1
{
    public $Context = NULL;
    public $PrivateKey;
    public $PublicKey;

    function __construct()
    {
        $this->Context = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    }

    // generate a private key
    public function GeneratePrivateKey()
    {
        while (1) {
            $privateKey = pack("H*", $this->str_rand());
            if (secp256k1_ec_seckey_verify($this->Context, $privateKey) == 1) {
                break;
            }
        }
        $this->PrivateKey = $privateKey;
        return bin2hex($this->PrivateKey);
    }

    // Load a private key from data string
    public function LoadPrivateKey($KeyString)
    {
        $privateKey = pack("H*", $KeyString);
        if (secp256k1_ec_seckey_verify($this->Context, $privateKey) == 1) {
            return NULL;
        }
        $this->PrivateKey = $privateKey;
        return bin2hex($this->PrivateKey);
    }

    // create a public key from a private key
    public function CreatePublicKey($privateKey = NULL)
    {
        $publicKey = null;
        if (NULL == $privateKey) {
            $privateKey = $this->PrivateKey;
        }
        $result = secp256k1_ec_pubkey_create($this->Context, $publicKey, $privateKey);
        if ($result === 1) {
            $serializeFlags = SECP256K1_EC_COMPRESSED;
            $serialized = '';
            if (1 !== secp256k1_ec_pubkey_serialize($this->Context, $serialized, $publicKey, $serializeFlags)) {
                return NULL;
            }
            $this->PublicKey = unpack("H*", $serialized)[1];
            return $this->PublicKey;
        } else {
            return NULL;
        }
    }

    public function Sign($message)
    {
        $msg32 = hash('sha256', $message, true);

        /** @var resource $signature */
        $signature = null;
        if (1 !== secp256k1_ecdsa_sign($this->Context, $signature, $msg32, $this->PrivateKey)) {
            throw new \Exception("Failed to create signature");
        }

        $serialized = '';
        secp256k1_ecdsa_signature_serialize_der($this->Context, $serialized, $signature);
        return $this->mergePublicKey($serialized);
        //return bin2hex($serialized);
    }

    private function mergePublicKey($serialized, $publicKey = NULL)
    {
        if (NULL == $publicKey) {
            $publicKey = $this->PublicKey;
        }
        return $publicKey . bin2hex($serialized);
    }

    static private function recoveryPublicKey($signatureString)
    {
        $publicKey = substr($signatureString, 0, 66);
        $signatureRaw = substr($signatureString, 66);
        return array($publicKey, $signatureRaw);
    }

    static public function Verify($message, $signatureString, $publicKeyString = NULL)
    {
        $Context = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
        // recovery public key from signature data.
        if (NULL == $publicKeyString) {
            $raw = secp256k1::recoveryPublicKey($signatureString);
            $publicKeyString = $raw[0];
            $signatureString = $raw[1];
        }
        $msg32 = hash('sha256', $message, true);
        // Load up the public key from its bytes (into $publicKey):
        /** @var resource $publicKey */
        $publicKeyRaw = pack("H*", $publicKeyString);
        $publicKey = null;
        if (1 !== secp256k1_ec_pubkey_parse($Context, $publicKey, $publicKeyRaw)) {
            throw new \Exception("Failed to parse public key");
        }

        // Load up the signature from its bytes (into $signature):
        /** @var resource $signature */
        $signatureRaw = pack("H*", $signatureString);
        $signature = null;
        if (1 !== secp256k1_ecdsa_signature_parse_der($Context, $signature, $signatureRaw)) {
            throw new \Exception("Failed to parse DER signature");
        }

        // Verify:
        $result = secp256k1_ecdsa_verify($Context, $signature, $msg32, $publicKey);
        return $result;
    }
    /*
     * generate a random string
     * @param int $length the length of generation string
     * @param string $char random string charactor
     * @return string $string random string
     */
    private function str_rand($length = 64, $char = '0123456789abcdef')
    {
        if (!is_int($length) || $length < 0) {
            return false;
        }

        $string = '';
        for ($i = $length; $i > 0; $i--) {
            $string .= $char[mt_rand(0, strlen($char) - 1)];
        }

        return $string;
    }

    public function PrivateKeyTweak($index)
    {
        $tweak = pack("H*", "0000000000000000000000000000000000000000000000000000000000000001");
        $privateKey = $this->PrivateKey;
        for ($i=0; $i < $index; $i++) { 
            $result = secp256k1_ec_privkey_tweak_add($this->Context, $this->PrivateKey, $tweak);
            if ($result != 1) {
                throw new \Exception("Invalid private key or augend value");
                return NULL;
            }
        }
        return bin2hex($privateKey);
    }
}

// // for test only
// $secp = new Secp256k1();
// echo "GeneratePrivateKey: " . $secp->GeneratePrivateKey() . PHP_EOL;
// echo "CreatePublicKey: " . $secp->CreatePublicKey() . PHP_EOL;
// $signature = $secp->Sign("hello world.");
// echo "Sign: " . $signature . PHP_EOL;
// echo "Verify: " . $secp->Verify("hello world.", $signature) . PHP_EOL;
