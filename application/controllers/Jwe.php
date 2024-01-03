<?php
defined('BASEPATH') OR exit('No direct script access allowed');
require __DIR__.'/../../vendor/autoload.php';


use Jose\Component\Core\JWKSet;
use Jose\Component\Core\Converter\StandardConverter;



//use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Signature\Algorithm\PS256;
use Jose\Component\Signature\Algorithm\ES512;
use Jose\Component\Signature\Algorithm\RS256;

use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Core\AlgorithmManagerFactory;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A128CBCHS256;
use Jose\Component\Encryption\Algorithm\KeyEncryption\PBES2HS512A256KW;
use Jose\Component\KeyManagement\JWKFactory;

use Jose\Component\Core\JWK;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Encryption\Serializer\JWESerializerManager;
//use Jose\Component\Signature\Serializer\CompactSerializer;

use Jose\Component\Signature\Serializer\JWSSerializerManager;


use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A256KW;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A256CBCHS512;
use Jose\Component\Encryption\Compression\CompressionMethodManager;
use Jose\Component\Encryption\Compression\Deflate;
use Jose\Component\Encryption\JWEBuilder;

use Jose\Component\Encryption\JWEDecrypter;
use Jose\Component\Encryption\Serializer\CompactSerializer;
use Jose\Component\Encryption\JWELoaderFactory;

class Jwe extends CI_Controller {
	private $algorithmManager;
	public function __construct() {
		$this->algorithmManager = new AlgorithmManager([
			new A256KW(),
			new A256CBCHS512(),
		]);
	}
	public function index()
	{	
		// $jweLoaderFactory = new JWELoaderFactory(
			// $jweSerializerManagerFactory,
			// $jweDecrypterFactory,
			// $headerCheckerManagerFactory
		// );
		
		// The key encryption algorithm manager with the A256KW algorithm.
		// $keyEncryptionAlgorithmManager = new AlgorithmManager([
			// new A256KW(),
		// ]);
		// echo '<pre>';	
		// print_r($keyEncryptionAlgorithmManager);die();
		// The content encryption algorithm manager with the A256CBC-HS256 algorithm.
		// $contentEncryptionAlgorithmManager = new AlgorithmManager([
			// new A256CBCHS512(),
		// ]);
		
		
		
		// The key encryption algorithm manager with the A256KW algorithm.
		$keyEncryptionAlgorithmManager = $this->algorithmManager;
		// The content encryption algorithm manager with the A256CBC-HS256 algorithm.
		$contentEncryptionAlgorithmManager = $this->algorithmManager;


		// The compression method manager with the DEF (Deflate) method.
		$compressionMethodManager = new CompressionMethodManager([
			new Deflate(),
		]);

		// We instantiate our JWE Builder.
		$jweBuilder = new JWEBuilder(
			$keyEncryptionAlgorithmManager,
			$contentEncryptionAlgorithmManager,
			$compressionMethodManager
		);
			
		// We instantiate our JWE Decrypter.
		$jweDecrypter = new JWEDecrypter(
			$keyEncryptionAlgorithmManager,
			$contentEncryptionAlgorithmManager,
			$compressionMethodManager
		);
		
		
		// Our key.
		$jwk = JWKFactory::createOctKey(
			1024, // Size in bits of the key. Should be at least of the same size as the hashing algorithm.
		);
				
		// The payload we want to encrypt. It MUST be a string.
		$payload = json_encode([
			'iat' => time(),
			'nbf' => time(),
			'exp' => time() + 3600,
			'iss' => 'My service',
			'aud' => 'Your application',
		]);
		
		//jwe object
		$jwe = $jweBuilder
			->create()              // We want to create a new JWE
			->withPayload($payload) // We set the payload
			->withSharedProtectedHeader([
				'alg' => 'A256KW',        // Key Encryption Algorithm
				'enc' => 'A256CBC-HS512', // Content Encryption Algorithm
				'zip' => 'DEF'            // We enable the compression (irrelevant as the payload is small, just for the example).
			])
			->addRecipient($jwk)    // We add a recipient (a shared key or public key).
			->build();              // We build it
		
		
		// echo 'jwe- ';	
		// echo '<pre>';	
		// print_r($jwe);
		
		$serializer = new CompactSerializer(); // The serializer
		$token = $serializer->serialize($jwe, 0); // We serialize the recipient at index 0 (we only have one recipient).
		echo 'token OctKey- ';	
		echo '<pre>';	
		print_r($token);
		
				
		// The serializer manager. We only use the JWE Compact Serialization Mode.
		// $serializerManager = new JWESerializerManager([
			// new CompactSerializer(),
		// ]);
				// We try to load the token.
		//$jwe = $serializerManager->unserialize($token);
	
	
	
		// We decrypt the token. This method does NOT check the header.
		$success = $jweDecrypter->decryptUsingKey($jwe, $jwk, 0);
				
		echo '</br>';	
		echo '</br>';	
		echo 'success- ';
		print_r($success);
		//print_r($jwk->all());
		
		
	}
}
