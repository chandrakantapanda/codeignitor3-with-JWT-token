Readme 
## Requirements
PHP8.1 NGINX
composer
Jwt framework 

## Core Code
    1. `JwekeyEncryption`
    2. `ContentEncryption`
    3. `Jwecompression`
    4. `Serialization`

**JwekeyEncryption**
	```
    $keyEncryptionAlgorithmManager = new AlgorithmManager([
        new RSAOAEP256(),
    ]);
	```
	
**ContentEncryption**
	```
    $contentEncryptionAlgorithmManager = new AlgorithmManager([
        new A256CBCHS512(),
    ]);
	```
	
**Jwecompression** 
	```
    $compressionMethodManager = new CompressionMethodManager([
        new Deflate(),
    ]);
	```

**Serialization**
	```
    $serializerManager = new JWESerializerManager([
        new CompactSerializer()
    ]);
	```

## Implementation Details 
  - *We have already install composer and required package . No need to install again
	
  -steps to achieve 
  
	install composer in localsystem

  - Run command to add package in our library.
  - This library is use for algorithm list depends on the cypher operation to be performed (signature or encryption)
  - Core component of the JWT Framework
    ```
    composer require web-token/jwt-core
    ```
  - This package is use for Generate A New Key
    ```
    composer require web-token/jwt-key-mgmt
    ```

  - This package is use JWS serializers
    ```
    composer require web-token/jwt-signature
    ```

  - This package is use for Header Checker JWT (JWS or JWE)
    ```
    composer require web-token/jwt-checker
    ```

  - This package is use for Content encryption algorithm manager with the aescbc algorithm
    ```    
    web-token/jwt-encryption-algorithm-aescbc
    ```
  - This package is use for key encryption algorithm manager with the RSA-OAEP-256 algorithm
    ```    
    composer require web-token/jwt-encryption-algorithm-rsa 
    ```
For reference https://web-token.spomky-labs.com/
