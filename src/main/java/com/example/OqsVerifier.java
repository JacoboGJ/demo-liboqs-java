package com.example;

import org.openquantumsafe.*;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.forgerock.util.encode.Base64url;

/**
 * App fos testing liboqs java wrapper to sign and verify post quantum safe signatures
 *
 */
public class OqsVerifier 
{
    public static void main( String[] args ) throws IOException
    {
        // -----------Signing Algorithm---------------
        String sig_name = "Dilithium2";
        // -----------------idToken-------------------
        String idToken = "<id_token:REPLACE THIS STRING>";

        System.out.println("id_token length: " + idToken.length());
        System.out.println("Signature: " + sig_name);

        String [] id_token_splitted = idToken.split("\\.");

        String encodedHeader = id_token_splitted[0];
        String encodedPayload = id_token_splitted[1];
        String encodedSignature = id_token_splitted[2];

        // -------------Sign header and payload-----------

        // Check if key pair file has been created
        String rootPath = "/home/jacobo/tfm/demo-maven-project/demo/security/keys/" + sig_name + "/";
        Path publicKeyPath = Paths.get(rootPath + "publicKey");
        byte[] publicKey = Files.readAllBytes(publicKeyPath);;

        // --------------verification process---------------
        Signature verifier = new org.openquantumsafe.Signature(sig_name);;

        String headerPayload = encodedHeader + "." +  encodedPayload;

        byte[] headerPayloadBytes = headerPayload.getBytes();
        byte[] signatureBytes = Base64url.decode(encodedSignature);
        System.out.println("signature lenght: " + signatureBytes.length);
        System.out.println("signinput lenght: " + headerPayloadBytes.length);
        System.out.println("publicKey lenght: " + publicKey.length);
        boolean is_valid = verifier.verify(headerPayloadBytes, signatureBytes, publicKey);
        System.out.println("Is the signature valid? " + is_valid);

        verifier.dispose_sig();
    }
}
