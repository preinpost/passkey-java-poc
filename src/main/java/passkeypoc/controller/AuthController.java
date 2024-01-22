package passkeypoc.controller;

import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.authenticator.Authenticator;
import com.webauthn4j.authenticator.AuthenticatorImpl;
import com.webauthn4j.data.*;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientInputs;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.util.Base64UrlUtil;
import jakarta.servlet.http.HttpSession;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.io.Serializable;
import java.util.List;

@Slf4j
@RestController
@RequiredArgsConstructor
public class AuthController {

    private final WebAuthnManager webAuthnManager;
    private final HttpSession session;

    @GetMapping("get_challenge")
    public PublicKey getChallenge() {

        byte[] userBase64UrlEncoded = Base64UrlUtil.encode("test-user".getBytes());

        PublicKeyCredentialRpEntity rp = new PublicKeyCredentialRpEntity("localhost", "Spring Test");
        PublicKeyCredentialUserEntity user = new PublicKeyCredentialUserEntity(userBase64UrlEncoded, "test", "test");
        DefaultChallenge challenge = new DefaultChallenge();

        List<PublicKeyCredentialParameters> pubKeyCredParams = List.of(
                new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256),
                new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.RS256)
        );


        Long timeout = 60000L;
        AttestationConveyancePreference attestation = AttestationConveyancePreference.DIRECT;
        AuthenticatorSelectionCriteria authenticatorSelection = new AuthenticatorSelectionCriteria(AuthenticatorAttachment.PLATFORM, false, UserVerificationRequirement.PREFERRED);
        AuthenticationExtensionsClientInputs extension = new AuthenticationExtensionsClientInputs.BuilderForRegistration().setUvm(true).setCredProps(true).build();

        PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions = new PublicKeyCredentialCreationOptions(rp, user, challenge, pubKeyCredParams, timeout, null, authenticatorSelection, attestation, extension);

        session.setAttribute("ServerProperty", new ServerProperty(
                new Origin("http://localhost:8081"),
                "localhost",
                challenge,
                null)
        );

        return new PublicKey(publicKeyCredentialCreationOptions);
    }


    public static class PublicKey implements Serializable {
        final public PublicKeyCredentialCreationOptions publicKey;

        public PublicKey(PublicKeyCredentialCreationOptions publicKey) {
            this.publicKey = publicKey;
        }
    }

    @PostMapping("register")
    public String register(@RequestBody RegistrationResponseJSON request) {

        log.info("register: " + request.toString());

        RegistrationRequest webAuthnRegistrationRequest =
                createRegistrationRequest(request.getClientDataJSON(), request.getAttestationObject(), request.getClientExtensions());

        RegistrationParameters webAuthnRegistrationParameters =
                createRegistrationParameters((ServerProperty) session.getAttribute("ServerProperty"));

        RegistrationData response = webAuthnManager.validate(webAuthnRegistrationRequest, webAuthnRegistrationParameters);

        Authenticator authenticator = new AuthenticatorImpl(
                response.getAttestationObject().getAuthenticatorData().getAttestedCredentialData(),
                response.getAttestationObject().getAttestationStatement(),
                response.getAttestationObject().getAuthenticatorData().getSignCount()
        );

        session.setAttribute("Authenticator", authenticator);

        return "register";
    }

    RegistrationRequest createRegistrationRequest(String clientDataBase64,
                                                  String attestationObjectBase64,
                                                  String clientExtensionsJSON) {

        byte[] clientDataBytes = Base64UrlUtil.decode(clientDataBase64);
        byte[] attestationObjectBytes = Base64UrlUtil.decode(attestationObjectBase64);

        return new RegistrationRequest(
                attestationObjectBytes,
                clientDataBytes,
                clientExtensionsJSON,
                null
        );
    }

    RegistrationParameters createRegistrationParameters(ServerProperty serverProperty) {
        return new RegistrationParameters(
                serverProperty,
                null,
                false,
                false
        );
    }


    @Getter
    public static class RegistrationResponseJSON implements Serializable {

        final public String clientDataJSON;
        final public String attestationObject;
        final public String clientExtensions;

        public RegistrationResponseJSON(String clientDataJSON, String attestationObject, String clientExtensions) {
            this.clientDataJSON = clientDataJSON;
            this.attestationObject = attestationObject;
            this.clientExtensions = clientExtensions;
        }

        @Override
        public String toString() {
            return "RegistrationResponseJSON{" +
                    "clientDataJSON='" + clientDataJSON + '\'' +
                    ", attestationObject='" + attestationObject + '\'' +
                    ", clientExtensions='" + clientExtensions + '\'' +
                    '}';
        }
    }

    @GetMapping("/get_login_challenge")
    public PublicKeyCredentialRequestOptions getLoginChallenge() {

        byte[] userBase64UrlEncoded = Base64UrlUtil.encode("test-user".getBytes());

        PublicKeyCredentialRpEntity rp = new PublicKeyCredentialRpEntity("localhost", "Spring Test");
        PublicKeyCredentialUserEntity user = new PublicKeyCredentialUserEntity(userBase64UrlEncoded, "test", "test");
        DefaultChallenge challenge = new DefaultChallenge();

        Authenticator authenticator = (Authenticator) session.getAttribute("Authenticator");
        PublicKeyCredentialDescriptor publicKeyCredentialDescriptor = new PublicKeyCredentialDescriptor(PublicKeyCredentialType.PUBLIC_KEY, authenticator.getAttestedCredentialData().getCredentialId(), authenticator.getTransports());
        UserVerificationRequirement userVerificationRequirement = UserVerificationRequirement.PREFERRED;

        session.setAttribute("ServerProperty", new ServerProperty(
                new Origin("http://localhost:8081"),
                "localhost",
                challenge,
                null)
        );

        return new PublicKeyCredentialRequestOptions(challenge, 60000L, rp.getId(), List.of(publicKeyCredentialDescriptor), userVerificationRequirement, null);
    }

    @Getter
    @RequiredArgsConstructor
    public static class AuthenticationResponseJson implements Serializable {

        final public String credentialId;
        final public String clientDataJSON;
        final public String authenticatorData;
        final public String signature;
        final public String userHandle;
    }

    @PostMapping("/login")
    public String login(@RequestBody AuthenticationResponseJson request) {

        log.info("login: " + request.toString());

        AuthenticationRequest authenticationRequest = createAuthenticationRequest(
                request.getCredentialId(),
                request.getUserHandle(),
                request.getAuthenticatorData(),
                request.getClientDataJSON(),
                null,
                request.getSignature()
        );

        AuthenticationParameters authenticationParameters = createAuthenticationParameters(
                (ServerProperty) session.getAttribute("ServerProperty"),
                (Authenticator) session.getAttribute("Authenticator")
        );


        AuthenticationData response = webAuthnManager.validate(authenticationRequest, authenticationParameters);


        return "login";
    }

    AuthenticationRequest createAuthenticationRequest(
            String credentialId,
            String userHandle,
            String authenticatorData,
            String clientDataJSON,
            String clientExtensionsJSON,
            String signature
    ) {

        byte[] credentialIdBytes = Base64UrlUtil.decode(credentialId);
        byte[] userHandleBytes = Base64UrlUtil.decode(userHandle);
        byte[] clientDataBytes = Base64UrlUtil.decode(clientDataJSON);
        byte[] authenticatorDataBytes = Base64UrlUtil.decode(authenticatorData);
        byte[] signatureBytes = Base64UrlUtil.decode(signature);

        return new AuthenticationRequest(
                credentialIdBytes,
                userHandleBytes,
                authenticatorDataBytes,
                clientDataBytes,
                clientExtensionsJSON,
                signatureBytes
        );
    }

    AuthenticationParameters createAuthenticationParameters(
            ServerProperty serverProperty,
            Authenticator authenticator
    ) {
        return new AuthenticationParameters(
                serverProperty,
                authenticator,
                null,
                true,
                true
        );
    }
}

