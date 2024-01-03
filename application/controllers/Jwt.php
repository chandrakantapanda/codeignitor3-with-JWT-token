<?php
defined('BASEPATH') OR exit('No direct script access allowed');
require __DIR__.'/../../vendor/autoload.php';


use Jose\Component\Core\JWKSet;
use Jose\Component\Core\Converter\StandardConverter;



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


class Jwt extends CI_Controller {
	private $algorithmManager;
	public function __construct() {
		$this->algorithmManager = new AlgorithmManager([
			new HS256(),
			new RS256()
		]);
	}
	
	public function index(){
		$jwk = JWKFactory::createOctKey(
			1024, // Size in bits of the key. Should be at least of the same size as the hashing algorithm.
			[
				'alg' => 'HS256', // This key must only be used with the HS256 algorithm
				'use' => 'sig'    // This key is used for signature/verification operations only
			]
		);
		$k_jwk=$jwk->all('kty');
		
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
		
		echo 'token createOctKey- ';	
		echo '<pre>';	
		print_r($token);
		
		// We instantiate our JWS Verifier.
		$jwsVerifier = new JWSVerifier(
			$this->algorithmManager
		);
		// Our key.
		
		$jwk = new JWK([
			'kty' => 'oct',
			'k' => $k_jwk['k'],
		]);

		// The serializer manager. We only use the JWS Compact Serialization Mode.
		$serializerManager = new JWSSerializerManager([
			new CompactSerializer(),
		]);


		// We try to load the token.
		$jws = $serializerManager->unserialize($token);
		
		// We verify the signature. This method does NOT check the header.
		// The arguments are:
		// - The JWS object,
		// - The key,
		// - The index of the signature to check. See 
		$isVerified = $jwsVerifier->verifyWithKey($jws, $jwk, 0);
		
		echo '<br/>';
		echo '<br/>';
		echo 'isVerified- ';
		print_r($isVerified);	
		
				
	}
	public function rsa(){
		
		$jwk = JWKFactory::createRSAKey(
			1024, // Size in bits of the key. Should be at least of the same size as the hashing algorithm.
			[
				'alg' => 'RS256', // This key must only be used with the HS256 algorithm
				'use' => 'sig'    // This key is used for signature/verification operations only
			]
		);
		echo 'RSAKey- ';	
		echo '<pre>';	
		print_r($jwk);
		
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
		->addSignature($jwk, ['alg' => 'RS256']) // We add a signature with a simple protected header
		->build();
		$serializer = new CompactSerializer(); // The serializer

		$token = $serializer->serialize($jws, 0); // We serialize the signature at index 0 (we only have one signature).
		
		echo 'token- ';	
		echo '<pre>';	
		print_r($token);
	
		// We instantiate our JWS Verifier.
		$jwsVerifier = new JWSVerifier(
			$this->algorithmManager
		);
		// The serializer manager. We only use the JWS Compact Serialization Mode.
		$serializerManager = new JWSSerializerManager([
			new CompactSerializer(),
		]);
		$jws = $serializerManager->unserialize($token);
		$isVerified = $jwsVerifier->verifyWithKey($jws, $jwk, 0);

		echo '<pre>';
		echo 'isVerified - ';
		var_dump($isVerified);	
	
	}
	public function octetkey()
	{
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
		echo 'jws- ';	
		echo '<pre>';	
		print_r($jws);
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
			'k' => 'PyCDG77Nxmm5_u2vmIRj34pBpT9yV4qMKAwKJRgCiLM3u1hVAtDZdt8RJkHiKye-eZ11nYMHXY3r5iwPuGxTrYUp3SrBtOxCC5OUdTHpfKud2x23HVMVMGIChqxHzu_L312HDQuIYhq1Qi8dDj7W8A2MtIGAqI7HTshvA1k7v2g',
		]);

		// The serializer manager. We only use the JWS Compact Serialization Mode.
		$serializerManager = new JWSSerializerManager([
			new CompactSerializer(),
		]);

		// The input we want to check
		$token = 'eyJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2NzQ3OTEzNDQsIm5iZiI6MTY3NDc5MTM0NCwiZXhwIjoxNjc0Nzk0OTQ0LCJpc3MiOiJNeSBzZXJ2aWNlIiwiYXVkIjoiWW91ciBhcHBsaWNhdGlvbiJ9.AtdOwwlt1ptRnvKzesIPHphpKx7rMYFTDJdFBwEz_5w';

		// We try to load the token.
		$jws = $serializerManager->unserialize($token);
		echo 'jws- ';	
		echo '<pre>';	
		print_r($jws);	
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
		// $jwk = JWKFactory::createFromValues([
			// 'kid' => '71ee230371d19630bc17fb90ccf20ae632ad8cf8',
			// 'kty' => 'RSA',
			// 'alg' => 'RS256',
			// 'use' => 'sig',
			// 'n' => 'vnMTRCMvsS04M1yaKR112aB8RxOkWHFixZO68wCRlVLxK4ugckXVD_Ebcq-kms1T2XpoWntVfBuX40r2GvcD9UsTFt_MZlgd1xyGwGV6U_tfQUll5mKxCPjr60h83LXKJ_zmLXIqkV8tAoIg78a5VRWoms_0Bn09DKT3-RBWFjk=',
			// 'e' => 'AQAB',
		// ]);
		$jwk = JWKFactory::createRSAKey(
			1024, // Size in bits of the key. Should be at least of the same size as the hashing algorithm.
			[
				'alg' => 'RS256', // This key must only be used with the HS256 algorithm
				'use' => 'sig'    // This key is used for signature/verification operations only
			]
		);
		echo 'RSAKey- ';	
		echo '<pre>';	
		print_r($jwk);
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
		->addSignature($jwk, ['alg' => 'RS256']) // We add a signature with a simple protected header
		->build();
		$serializer = new CompactSerializer(); // The serializer

		$token = $serializer->serialize($jws, 0); // We serialize the signature at index 0 (we only have one signature).
		
		echo 'token- ';	
		echo '<pre>';	
		print_r($token);
	
	
	
	}
	public function abcv()
	{	
		// We instantiate our JWS Verifier.
		$jwsVerifier = new JWSVerifier(
			$this->algorithmManager
		);
		// Our key.
		$jwk = new JWK([
			'kty' => 'RSA',
			'k' => 'vnD0jj64lNbk9GIgDI7TAZlXqrt0o1aAPG9tESmBXTFofAjFRiK__P90rr4JdKB-RqGUzn76llbJNIxNrubfqyP5QaCnEJtAR-YkwoqvWwwtOAzdCWYGO0uudHT4zNQUdmueeV1qi2ZXxb1c1p1fo3XShmXOzryjsBmzUZAACbM',
		]);

		// The serializer manager. We only use the JWS Compact Serialization Mode.
		$serializerManager = new JWSSerializerManager([
			new CompactSerializer(),
		]);
		// The input we want to check
		$token = 'eyJhbGciOiJSUzI1NiJ9.eyJpYXQiOjE2NzQ2NDUzMTQsIm5iZiI6MTY3NDY0NTMxNCwiZXhwIjoxNjc0NjQ4OTE0LCJpc3MiOiJNeSBzZXJ2aWNlIiwiYXVkIjoiWW91ciBhcHBsaWNhdGlvbiJ9.uNc43TBYnDRNhqU__F3mCXr0KKoL6UzXCuGcSshUEGeU4i3odoKvrvwmUsfL8YKagpNw_0vWHT1G8NHxkcBL-TXX88HayH5zhSbUDXRzj9abtRXx58HPUrZ_ouKkJDCcxwd1VUB5sIceq6q8scNo8KDouwAW0rxpl-l5wkElpnA';

		// We try to load the token.
		$jws = $serializerManager->unserialize($token);
		print_r($jws);
		// We verify the signature. This method does NOT check the header.
		// The arguments are:
		// - The JWS object,
		// - The key,
		// - The index of the signature to check. See 
		$isVerified = $jwsVerifier->verifyWithKey($jws, $jwk, 0);

		echo '<pre>';
		var_dump($isVerified);
	
	
	}
	public function testRsa(){
		// Create using direct values
		$keyset = JWKSet::createFromKeyData(['keys' => [
			'71ee230371d19630bc17fb90ccf20ae632ad8cf8' => [
			'kid' => '71ee230371d19630bc17fb90ccf20ae632ad8cf8',
			'kty' => 'RSA',
			'alg' => 'RS256',
			'use' => 'sig',
			'n' => 'vnMTRCMvsS04M1yaKR112aB8RxOkWHFixZO68wCRlVLxK4ugckXVD_Ebcq-kms1T2XpoWntVfBuX40r2GvcD9UsTFt_MZlgd1xyGwGV6U_tfQUll5mKxCPjr60h83LXKJ_zmLXIqkV8tAoIg78a5VRWoms_0Bn09DKT3-RBWFjk=',
			'e' => 'AQAB',
		]]]);
		$jsonConverter = new StandardConverter();
		$serializer = new CompactSerializer($jsonConverter);
		$jws = $serializer->unserialize($input);
		
		$headerChecker = HeaderCheckerManager::create(
			[new AlgorithmChecker(['RS256'])], // A list of header checkers
			[new JWSTokenSupport()]            // A list of token support services (we only use the JWS token type here)
		);
		
		$jwsVerifier = new JWSVerifier($this->algorithmManager);
		
		
		$claimChecker = ClaimCheckerManager::create(
			[new ExpirationTimeChecker()] // A list of claim checkers
		);

		// We check all signatures
		$isVerified = false;
		for ($i = 0; $i < $jws->count(); $i++) {
			try {
				$headerChecker->check($jws, 0); // We check the header of the first (index=0) signature.        
				if ($jwsVerifier->verifyWithKey($jws, $keyset, 0)) { // We verify the signature
					$isVerified = true;
					break;
				}
			} catch (\Exception $e) {
				continue;
			}
		}

		if (!$isVerified) {
			//Unable to check the token. The header or the signature verification failed.
		} else {
			// We check the claims.
			// If everything is ok, claims can be used.
			$claims = $jsonConverter->decode($jws->getPayload());
			$claimChecker->check($claims); // We check the claims.
		}
		
		
		
		
		
		
		
	}
}
