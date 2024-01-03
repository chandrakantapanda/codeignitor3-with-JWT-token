<?php
defined('BASEPATH') OR exit('No direct script access allowed');
require __DIR__.'/../../vendor/autoload.php';

use Jose\Component\Core\AlgorithmManager;
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
use Jose\Component\Signature\Serializer\CompactSerializer;

use Jose\Component\Signature\Serializer\JWSSerializerManager;


class Welcome extends CI_Controller {
	private $algorithmManager;
	public function __construct() {
		$this->algorithmManager = new AlgorithmManager([
			new HS256(),
			new RS256()
		]);
	}
	public function index()
	{die('welcome');
		$jwk = JWKFactory::createOctKey(
			1024, // Size in bits of the key. Should be at least of the same size as the hashing algorithm.
			[
				'alg' => 'HS256', // This key must only be used with the HS256 algorithm
				'use' => 'sig'    // This key is used for signature/verification operations only
			]
		);
		echo 'jwk- ';	
		echo '<pre>';	
		print_r($jwk);
		
		// We instantiate our JWS Builder.
		$jwsBuilder = new JWSBuilder($this->algorithmManager);

		$payload = json_encode([
			'iat' => time(),
			'nbf' => time(),
			'exp' => time() + 3600,
			'iss' => 'My service',
			'aud' => 'Your application',
		]);
		$jws = $jwsBuilder
		->create()                               // We want to create a new JWS
		->withPayload($payload)                  // We set the payload
		->addSignature($jwk, ['alg' => 'HS256']) // We add a signature with a simple protected header
		->build();
		$serializer = new CompactSerializer(); // The serializer

		$token = $serializer->serialize($jws, 0); // We serialize the signature at index 0 (we only have one signature).
		
		echo 'token- ';	
		echo '<pre>';	
		print_r($token);		
	
	}
	
	public function verifytoken()
	{
		// We instantiate our JWS Verifier.
		$jwsVerifier = new JWSVerifier(
			$this->algorithmManager
		);
		// Our key.
		$jwk = new JWK([
			'kty' => 'oct',
			'k' => 'CSsvaC0eiPZMkoOjnynIxG-7jZAtZe3HyB5Z1108X7OOXEOCAslGhHMgiu4mvK0QV4SMg2S44pX46oA3LogEETIjSiHOhVqlI173uOuAPTyJUCRCpJ1CMuC6bV782KnOx-HiCHOi1A9I9-T4s7GVRGYPbz1zsXDse4ExxQg5edM',
		]);

		// The serializer manager. We only use the JWS Compact Serialization Mode.
		$serializerManager = new JWSSerializerManager([
			new CompactSerializer(),
		]);

		// The input we want to check
		$token = 'eyJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2NzQ2NDE0OTksIm5iZiI6MTY3NDY0MTQ5OSwiZXhwIjoxNjc0NjQ1MDk5LCJpc3MiOiJNeSBzZXJ2aWNlIiwiYXVkIjoiWW91ciBhcHBsaWNhdGlvbiJ9.YEPx2KOOeXAPV4Hf424gaFOC6XHyCHPEh3kjgcLjHBQ';

		// We try to load the token.
		$jws = $serializerManager->unserialize($token);

		// We verify the signature. This method does NOT check the header.
		// The arguments are:
		// - The JWS object,
		// - The key,
		// - The index of the signature to check. See 
		$isVerified = $jwsVerifier->verifyWithKey($jws, $jwk, 0);

		echo 'isVerified- ';	
		echo '<pre>';	
		print_r($isVerified);	
	}
	public function abc()
	{
	
	
	
	
	
	}
}
