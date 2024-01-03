<?php

require __DIR__ . '/../../vendor/autoload.php';

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A256CBCHS512;
use Jose\Component\Encryption\Algorithm\KeyEncryption\RSAOAEP256;
use Jose\Component\Encryption\Compression\CompressionMethodManager;
use Jose\Component\Encryption\Compression\Deflate;
use Jose\Component\Encryption\JWEBuilder;
use Jose\Component\Encryption\Serializer\JSONGeneralSerializer;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Encryption\JWEDecrypter;

class Multiplereceipient extends CI_Controller {

    private $keyEncryptionAlgorithmManager; 
    private $contentEncryptionAlgorithmManager;
    private $compressionMethodManager;
    private $serializer;

    public function __construct() {
        // The key encryption algorithm manager with the RSA-OAEP-256 algorithm.
        $this->keyEncryptionAlgorithmManager = new AlgorithmManager([
            new RSAOAEP256()
        ]);
        // The Content Encryption algorithm manager with the A256CBC-HS512 algorithm.
        $this->contentEncryptionAlgorithmManager = new AlgorithmManager([
            new A256CBCHS512(),
        ]);
        // The compression method manager with the DEF (Deflate) method
        $this->compressionMethodManager = new CompressionMethodManager([
            new Deflate(),
        ]);
        //JWS JSON General serialization mode
        $this->serializer = new JSONGeneralSerializer();
    }


    public function index() {

        // Create/instantiate the JWE builder
        $jweBuilder = new JWEBuilder(
            $this->keyEncryptionAlgorithmManager,
            $this->contentEncryptionAlgorithmManager,
            $this->compressionMethodManager                
        );

        // Create the recipients' public keys
        $private_key1 = JWKFactory::createRSAKey(
            2048,
            [
                'alg' => 'RSA-OAEP-256',
                'use' => 'enc'
            ]);        
        $public_key1 = $private_key1->toPublic();
        
        $private_key2 = JWKFactory::createRSAKey(
            2048,
            [
                'alg' => 'RSA-OAEP-256',
                'use' => 'enc'
            ]);
        $public_key2 = $private_key2->toPublic();
        
        $payload = json_encode([
            'iat' => time(),
            'nbf' => time(),
            'exp' => time() + 3600,
            'iss' => 'My service',
            'aud' => 'Your application',
        ]);
        // Build the JWE for multiple recipients
        $jwe = $jweBuilder
                ->create()
                ->withPayload($payload)
                ->withSharedProtectedHeader([
                    //'alg' => 'RSA-OAEP-256',
                    'alg' => 'RSA-OAEP-256',
                    'enc' => 'A256CBC-HS512',
                    'zip' => 'DEF'
                ])
                //->addRecipient($public_key1,['alg' => 'RSA-OAEP-256'])
                //->addRecipient($public_key2, ['alg' => 'RSA-OAEP-256'])
                
                ->addRecipient($public_key1)
                ->addRecipient($public_key2)
                ->build();
            
        // Serialize the JWE to a JSON Genral format (multi-recipient)
        $serializedJwe = $this->serializer->serialize($jwe);

        echo "<pre>";
        //echo $serializedJwe;
		//$manage= json_decode($serializedJwe, true);
		//echo json_decode($serializedJwe, true);
		echo "---multiple jwe---";
		echo "<br/>";
		echo json_encode(json_decode($serializedJwe, true), JSON_PRETTY_PRINT);
        $this->decrypt($serializedJwe,$private_key1, 0);
        $this->decrypt($serializedJwe,$private_key2, 1);
    }

    public function decrypt($serializedJwe,$privateKey,$recipient) {
        // Load the JWE from its serialized for
        $jwe = $this->serializer->unserialize($serializedJwe);
               
        // decrypt the JWE
        $decryptedPayload = null;
        $decrypter = new JWEDecrypter(
            $this->keyEncryptionAlgorithmManager,
            $this->contentEncryptionAlgorithmManager,
            $this->compressionMethodManager
        );

        if ($decrypter->decryptUsingKey($jwe, $privateKey, $recipient)) {
			echo "<br>";
			echo "<br>";
			echo "<br>";
            $decryptedPayload = $jwe->getPayload();
            echo "<pre>";
            echo $decryptedPayload;
        }   
    }
}
