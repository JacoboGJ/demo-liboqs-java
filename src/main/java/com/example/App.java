package com.example;

import org.openquantumsafe.*;
/*import org.restlet.engine.header.HeaderReader;

import com.codahale.metrics.MetricRegistryListener.Base;

import org.forgerock.json.jose.jwt.Jwt;
import org.forgerock.json.jose.jwt.JwtClaimsSet;*/
import org.json.JSONObject;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Base64;

/**
 * App fos testing liboqs java wrapper to sign and verify post quantum safe signatures
 *
 */
public class App 
{
    public static void main( String[] args ) throws IOException
    {
        // Creation of JWS, header, payload and signature

        // -----------Signing Algorithm---------------
        String sig_name = "Dilithium2";

        // -----------------Create JWT---------------
        JSONObject payloadJWT = new JSONObject();
        payloadJWT.put("sub", "jacobo");
        payloadJWT.put("aud", "miapp");
        JSONObject headerJWT = new JSONObject();
        headerJWT.put("alg", sig_name);
        headerJWT.put("type", "JWT");


        // ------------Encode payload and header----------
        String encodedPayload = Base64.getEncoder().encodeToString(payloadJWT.toString().getBytes());
        String encodedHeader = Base64.getEncoder().encodeToString(headerJWT.toString().getBytes());

        String jwsToSign = encodedHeader + "." + encodedPayload;

        // -------------Sign header and payload-----------

        // Check if key pair file has been created
        String rootPath = "/home/jacobo/tfm/demo-maven-project/demo/security/keys/" + sig_name + "/";
        Path privateKeyPath = Paths.get(rootPath + "privateKey");
        Path publicKeyPath = Paths.get(rootPath + "publicKey");

        Signature signer = null;
        byte[] publicKey = null;

        if (Files.exists(privateKeyPath) && Files.isRegularFile(privateKeyPath)) {
            byte[] privateKey = Files.readAllBytes(privateKeyPath);
            signer = new Signature(sig_name, privateKey);
            publicKey = Files.readAllBytes(publicKeyPath);
        } else {
            signer = new Signature(sig_name);
            publicKey = signer.generate_keypair();

            Files.createFile(publicKeyPath);
            Files.write(publicKeyPath, publicKey);
            Files.createFile(privateKeyPath);
            Files.write(privateKeyPath, signer.export_secret_key());
        }

        byte[] signature = signer.sign(jwsToSign.getBytes());
        String jwsSignature = Base64.getEncoder().encodeToString(signature);

        // -------------Generate token---------------------
        String jws = jwsToSign + "." + jwsSignature;

        System.out.println("JWS with dilithium signature: " + jws);


        // --------------verification process---------------
        Signature verifier = new Signature(sig_name);
        String[] headerPayloadSignatureArray = jws.split("\\.");
        System.out.println(headerPayloadSignatureArray.length);

        String headerPayload = headerPayloadSignatureArray[0] + "." +  headerPayloadSignatureArray[1];
        String signatureFromJWS = headerPayloadSignatureArray[2];
        byte[] headerPayloadBytes = headerPayload.getBytes();
        byte[] signatureBytes = Base64.getDecoder().decode(signatureFromJWS);
        boolean is_valid = verifier.verify(headerPayloadBytes, signatureBytes, publicKey);
        System.out.println("Is the signature valid? " + is_valid);

        signer.dispose_sig();
        verifier.dispose_sig();
    }
}
