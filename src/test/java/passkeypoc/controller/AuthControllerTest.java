package passkeypoc.controller;

import com.webauthn4j.data.*;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientInputs;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.util.Base64UrlUtil;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

class AuthControllerTest {

    @Test
    void getChallenge() {

        // Server properties
        Origin origin = new Origin("localhost:8080");

        byte[] userBase64UrlEncoded = Base64UrlUtil.encode("test-user".getBytes());

        PublicKeyCredentialRpEntity rp = new PublicKeyCredentialRpEntity("spring-test", "Spring Test");
        PublicKeyCredentialUserEntity user = new PublicKeyCredentialUserEntity(userBase64UrlEncoded, "test", "test");
        Challenge challenge = new DefaultChallenge() /* set challenge */;
        List<PublicKeyCredentialParameters> pubKeyCredParams = List.of(
                new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256),
                new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.RS256)
        );

        Long timeout = 60000L;
        AttestationConveyancePreference attestation = AttestationConveyancePreference.DIRECT;
        AuthenticatorSelectionCriteria authenticatorSelection = new AuthenticatorSelectionCriteria(AuthenticatorAttachment.PLATFORM, false, UserVerificationRequirement.PREFERRED);
        AuthenticationExtensionsClientInputs extension = new AuthenticationExtensionsClientInputs.BuilderForRegistration().setUvm(true).setCredProps(true).build();

        PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions = new PublicKeyCredentialCreationOptions(rp, user, challenge, pubKeyCredParams, timeout, null, authenticatorSelection, attestation, extension);

        System.out.println(publicKeyCredentialCreationOptions.toString());



    }



}