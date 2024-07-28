package com.jszsoft.jwktest;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTClaimsSet.Builder;
import com.nimbusds.jwt.SignedJWT;

@SpringBootApplication
public class JwktestApplication implements CommandLineRunner {

	@Value("${app.key_type}")
	private String keyType;

	@Value("${app.jks.content}")
	private String jks;

	@Value("${app.jks.pass}")
	private String jksPass;

	@Value("${app.jks.alias}")
	private String jksAlias;

	@Value("${app.pem.private}")
	private String pemPrivateKey;

	@Value("${app.pem.public}")
	private String pemPublicKey;

	private static Logger LOG = LoggerFactory
			.getLogger(JwktestApplication.class);

	public static void main(String[] args) {
		LOG.info("STARTING THE APPLICATION");
		SpringApplication.run(JwktestApplication.class, args);
		LOG.info("APPLICATION FINISHED");
	}

	@Override
	public void run(String... args) {
		LOG.info("EXECUTING : command line runner");

		LOG.info("Key Type: {}", keyType);

		String jwt = createJWT();

		LOG.info("!!! Verifying generated JWT !!!\n");

		verifyJWT(jwt);

		String[] jwtArray = jwt.split("\\.");
		String payload = new String(Base64.getDecoder().decode(jwtArray[1]));
		payload = payload.replace("98765", "12345");
		String alteredPayload = Base64.getEncoder().encodeToString(payload.getBytes());
		String alteredJWT = jwtArray[0] + "." + alteredPayload + "." + jwtArray[2];

		LOG.info("!!! Verifying altered JWT !!!\n");
		verifyJWT(alteredJWT);
	}

	private JWTClaimsSet buildClaimsSet() {
		String issuer = "ERP System";
		Instant issuedAt = Instant.now();
		Instant expirationTime = issuedAt.plus(300L, ChronoUnit.SECONDS);

		Builder builder = new JWTClaimsSet.Builder()
				.issuer(issuer)
				.issueTime(Date.from(issuedAt))
				.claim("customer_id", "123")
				.claim("user_id", "98765")
				.expirationTime(Date.from(expirationTime));

		return builder.build();
	}

	private PrivateKey getPrivateKeyFromJKS() {
		PrivateKey privateKey = null;

		try {
			KeyStore keyStore = null;
			char[] pass = jksPass.toCharArray();

			keyStore = KeyStore.getInstance("JKS");
			try (InputStream inputStream = new ByteArrayInputStream(Base64.getDecoder().decode(jks))) {
				keyStore.load(inputStream, pass);
			}

			privateKey = (PrivateKey) keyStore.getKey(jksAlias, pass);
		} catch (Exception ex) {
			LOG.error("Error when retrieving private key from JKS, {}", ex);
		}

		return privateKey;
	}

	private PublicKey getPublicKeyFromJKS() {
		PublicKey publicKey = null;

		try {
			KeyStore keyStore = null;
			char[] pass = jksPass.toCharArray();

			keyStore = KeyStore.getInstance("JKS");
			try (InputStream inputStream = new ByteArrayInputStream(Base64.getDecoder().decode(jks))) {
				keyStore.load(inputStream, pass);
			}

			Certificate cert = keyStore.getCertificate(jksAlias);
			if (cert != null) {
				// Get the public key from the certificate
				publicKey = cert.getPublicKey();
			}
		} catch (Exception ex) {
			LOG.error("Error when retrieving public key from JKS, {}", ex);
		}

		return publicKey;
	}

	private PrivateKey getPrivateKeyFromPEM() {
		PrivateKey privateKey = null;

		try (InputStream inputStream = new ByteArrayInputStream(Base64.getDecoder().decode(pemPrivateKey))) {
			String pemContent = new String(inputStream.readAllBytes(), StandardCharsets.UTF_8);
			pemContent = pemContent.replace("-----BEGIN PRIVATE KEY-----", "");
			pemContent = pemContent.replace("-----END PRIVATE KEY-----", "");
			pemContent = pemContent.replaceAll("\\s", "");

			// Decode Base64 to get the binary data
			byte[] keyBytes = Base64.getDecoder().decode(pemContent);

			// Generate private key
			PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");

			privateKey = keyFactory.generatePrivate(keySpec);
		} catch (Exception ex) {
			LOG.error("Error when retrieving private key from PEM, {}", ex);
		}

		return privateKey;
	}

	private PublicKey getPublicKeyFromPEM() {
		PublicKey publicKey = null;

		try (InputStream inputStream = new ByteArrayInputStream(Base64.getDecoder().decode(pemPublicKey))) {
			String pemContent = new String(inputStream.readAllBytes(), StandardCharsets.UTF_8);
			pemContent = pemContent.replace("-----BEGIN PUBLIC KEY-----", "");
			pemContent = pemContent.replace("-----END PUBLIC KEY-----", "");
			pemContent = pemContent.replaceAll("\\s", "");

			// Decode Base64 to get the binary data
			byte[] keyBytes = Base64.getDecoder().decode(pemContent);

			// Generate private key
			X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");

			publicKey = keyFactory.generatePublic(keySpec);
		} catch (Exception ex) {
			LOG.error("Error when retrieving public key from PEM, {}", ex);
		}

		return publicKey;
	}

	private String createJWT() {
		String jwt = null;
		try {
			PrivateKey privateKey = keyType.equalsIgnoreCase("jks") ? getPrivateKeyFromJKS() : getPrivateKeyFromPEM();

			// Create RSA signer
			JWSSigner signer = new RSASSASigner(privateKey);

			// Create JWS object
			JWSObject jwsObject = new JWSObject(
					new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("testJWT").build(),
					new Payload(buildClaimsSet().toJSONObject()));

			// Sign the JWS
			jwsObject.sign(signer);

			// Serialize the JWS to compact form
			jwt = jwsObject.serialize();

			LOG.info("JWT: " + jwt);
		} catch (Exception ex) {
			LOG.error("Error when creating JWT, {}", ex);
		}

		return jwt;
	}

	private void verifyJWT(String jwt) {
		try {
			PublicKey publicKey = keyType.equalsIgnoreCase("jks") ? getPublicKeyFromJKS() : getPublicKeyFromPEM();

			// Create RSA verifier
			JWSVerifier verifier = new RSASSAVerifier((RSAPublicKey) publicKey);

			// Parse the JWS and verify it
			SignedJWT signedJWT = SignedJWT.parse(jwt);

			if (signedJWT.verify(verifier)) {
				// If verified, print the claims
				JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
				System.out.println("JWT verified!");
				System.out.println("Issuer: " + claims.getIssuer());
				System.out.println("Expiration Time: " + claims.getExpirationTime());
				System.out.println("Customer id: " + claims.getStringClaim("customer_id"));
				System.out.println("User id: " + claims.getStringClaim("user_id"));

				Instant now = Instant.now();
				if (claims.getExpirationTime().before(Date.from(now))) {
					System.out.println("JWT expired!!!");
				} else {
					System.out.println("JWT not expired.");
				}
			} else {
				System.out.println("JWT verification failed, signature not matched!!!");
			}
		} catch (Exception ex) {
			LOG.error("Error when verifying JWT, {}", ex);
		}
	}

}