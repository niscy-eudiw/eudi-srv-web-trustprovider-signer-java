/*
 * Copyright 2012-2015 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package eu.europa.ec.eudi.signer.rssp.unit;

import org.junit.BeforeClass;
import org.junit.runner.RunWith;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import eu.europa.ec.eudi.signer.rssp.common.config.CryptoConfig;

@RunWith(SpringJUnit4ClassRunner.class)
// @SpringBootTest
public class CryptoTests {

	private static CryptoConfig config = null;

	@BeforeClass
	public static void prep() {
		config = new CryptoConfig();
		config.setKeyAlgorithm("RSA");
		config.setKeySize(2048);
		config.setSignatureAlgorithm("SHA256WithRSA");
	}

	/*
	 * @Test
	 * public void testPrivateKeyRoundTrip() throws Exception {
	 * CertificateGenerator generator = new CertificateGenerator(config);
	 * final KeyPair keyPair = generator.generateKeyPair();
	 * final PrivateKey originalKey = keyPair.getPrivate();
	 * 
	 * final PemConverter converter = new PemConverter(config);
	 * String keyString = converter.privateKeyToString(originalKey);
	 * System.out.println(keyString);
	 * System.out.printf("\nPrivate plain key is this %d chars long\n",
	 * keyString.length());
	 * // convert back
	 * final PrivateKey restoredKey = converter.stringToPrivateKey(keyString);
	 * Assert.
	 * assertEquals("Expected the private key to be the same after round-trip through string"
	 * ,
	 * originalKey, restoredKey);
	 * }
	 * 
	 * @Test
	 * public void testEncryptedPrivateKeyRoundTrip() throws Exception {
	 * CertificateGenerator generator = new CertificateGenerator(config);
	 * final KeyPair keyPair = generator.generateKeyPair();
	 * final PrivateKey originalKey = keyPair.getPrivate();
	 * 
	 * final PemConverter converter = new PemConverter(config);
	 * String keyString = converter.privateKeyToString(originalKey);
	 * System.out.println(keyString);
	 * System.out.printf("\nPrivate encrypted key is this %d chars long\n",
	 * keyString.length());
	 * // convert back
	 * final PrivateKey restoredKey = converter.stringToPrivateKey(keyString);
	 * Assert.
	 * assertEquals("Expected the private key to be the same after round-trip through string"
	 * ,
	 * originalKey, restoredKey);
	 * }
	 * 
	 * @Test
	 * public void testPublicKeyRoundTrip() throws Exception {
	 * CertificateGenerator generator = new CertificateGenerator(config);
	 * final KeyPair keyPair = generator.generateKeyPair();
	 * final PublicKey originalKey = keyPair.getPublic();
	 * 
	 * // password should be ignored
	 * final PemConverter converter = new PemConverter(config);
	 * 
	 * String keyString = converter.publicKeyToString(originalKey);
	 * System.out.println("String form:");
	 * System.out.println(keyString);
	 * System.out.printf("\nPublic plain key is %d chars long\n",
	 * keyString.length());
	 * final PublicKey restoredKey = converter.stringToPublicKey(keyString);
	 * Assert.
	 * assertEquals("Expected the public key to be the same after round-trip through string"
	 * ,
	 * originalKey, restoredKey);
	 * }
	 */
}
