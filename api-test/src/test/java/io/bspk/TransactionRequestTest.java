package io.bspk;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.JWK;
import io.bspk.httpsig.HttpSigAlgorithm;
import io.bspk.httpsig.HttpSign;
import io.bspk.httpsig.SignatureParameters;
import io.bspk.oauth.xyz.crypto.*;
import io.bspk.oauth.xyz.data.Interact;
import io.bspk.oauth.xyz.data.InteractFinish;
import io.bspk.oauth.xyz.data.Key;
import io.bspk.oauth.xyz.data.api.*;
import io.restassured.RestAssured;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;
import org.apache.commons.lang3.RandomStringUtils;
import org.greenbytes.http.sfv.ByteSequenceItem;
import org.greenbytes.http.sfv.Dictionary;
import org.greenbytes.http.sfv.StringItem;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;
import org.apache.commons.codec.digest.DigestUtils;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class TransactionRequestTest {

    public static final String CONTENT_TYPE = "application/json";

    public JWK clientKey() {
        try {
            return JWK.parse(
                    "{\n" +
                            "  \"kty\": \"RSA\",\n" +
                            "  \"d\": \"m1M7uj1uZMgQqd2qwqBk07rgFzbzdCAbsfu5kvqoALv3oRdyi_UVHXDhos3DZVQ3M6mKgb30XXESykY8tpWcQOU-qx6MwtSFbo-3SNx9fBtylyQosHECGyleVP79YTE4mC0odRoUIDS90J9AcFsdVtC6M2oJ3CCL577a-lJg6eYyQoRmbjdzqMnBFJ99TCfR6wBQQbzXi1K_sN6gcqhxMmQXHWlqfT7-AJIxX9QUF0rrXMMX9fPh-HboGKs2Dqoo3ofJ2XuePpmpVDvtGy_jenXmUdpsRleqnMrEI2qkBonJQSKL4HPNpsylbQyXt2UtYrzcopCp7jL-j56kRPpQAQ\",\n" +
                            "  \"e\": \"AQAB\",\n" +
                            "  \"kid\": \"xyz-client\",\n" +
                            "  \"alg\": \"RS256\",\n" +
                            "  \"n\": \"zwCT_3bx-glbbHrheYpYpRWiY9I-nEaMRpZnRrIjCs6b_emyTkBkDDEjSysi38OC73hj1-WgxcPdKNGZyIoH3QZen1MKyyhQpLJG1-oLNLqm7pXXtdYzSdC9O3-oiyy8ykO4YUyNZrRRfPcihdQCbO_OC8Qugmg9rgNDOSqppdaNeas1ov9PxYvxqrz1-8Ha7gkD00YECXHaB05uMaUadHq-O_WIvYXicg6I5j6S44VNU65VBwu-AlynTxQdMAWP3bYxVVy6p3-7eTJokvjYTFqgDVDZ8lUXbr5yCTnRhnhJgvf3VjD_malNe8-tOqK5OSDlHTy6gD9NqdGCm-Pm3Q\"\n" +
                            "}"
            );
        } catch (ParseException e) {
            return null;
        }
    }

    public JWK privateKey() {
        try {
            return JWK.parse(
                    "{\n" +
                            "        \"p\": \"zA_NmnceZ4UEPwJvTfrGcRn4ZB855TVOgULtVRzbMcRXWnyDi9KDlKShIoXWxvCiwniP0fevRLQ-3L7iNfA7cLy7oIrJeGUmbpCSwhqzjZupcDVHxM8QdhFDTbjhv7s3zj3EC3iPih_lal7loUbzdyYA7mvu5THfWmfBJ9DBAuM\",\n" +
                            "        \"kty\": \"RSA\",\n" +
                            "        \"q\": \"o7-udAWbLhqKHGxWym6JWuxFc0Kyap2av5gb_sm2out17vN8gROnRhSKybodzWtwAIdb2s5hXyggyrPGPMsPncrvXJGgH3U14045aJ5-c1p5TqcQHmh604DCRbTwuhqJFkDhWtLR8u7WO4ZVXINZvoOtYaSaYHyVWjOCk6Mxd90\",\n" +
                            "        \"d\": \"gA-lFERDsbm3pX6QTc7eSzu7KGPkE_AyJ9waVp1cwMbYPWabrOgXv9WDpQl1IaW1k1HUr5G4wOynTYHO0E-ZCDNNJFuqXn10Sw3g7di_6hjIMCRtd5JWnnWMFLghF8HlJY908JT5wxgNgG103zHOvR5jTfHnUqCaTDghx8YbDGghLdCmIVvtm72V7EWsh0_OUHaCLfH8TZdlQxunYszLMwab4X8Lctp1Eqo5RsdctUm5XTmj9E8-dD2APCn89peL_anskrG7UrNXVcOODCT_Skw7YgGt4eoAwpfPSoKtQF8fyfmEbpDGuSRN9CzPdW7OH3-Kl-rkagqBk-oY2DnJaQ\",\n" +
                            "        \"e\": \"AQAB\",\n" +
                            "        \"kid\": \"gnap-public-client\",\n" +
                            "        \"qi\": \"fTyhRigvfKGGb4ok52bT2jVf5kPPuDkGoI40FfmDNxgF0qr0i5gVgHQJyxZUfemp15n331Iow5TTc4utBT4S19qm1_0nRVLI0fqgKEW67dxwDBxPAXbpyyPSQDSYIwwnlQKoZtDxuDXjEUoRaGwMl7jfLF0_WVNq5ur6RV0Un4U\",\n" +
                            "        \"dp\": \"x_bQdoY2ACFD2O7s3VBZ92kIlCxZUnebN2W7JkWBslIBe8U6LuEaWaW91ROsNQSHqeP0oz-Au-WZGD3hdBO2W7JGdnqqFNWiBISdm6IIw0J_llpPutdh_SDLgDUk2vp-JBc4rjj1B9hbupHFmfXqDJ7sGLchwezOP0we5oJVMRs\",\n" +
                            "        \"alg\": \"PS512\",\n" +
                            "        \"dq\": \"czgS5qxzLpOaDrnkr_frSkDp9Vo-9GoFUz8So8sHacfIaeSF_MT5dIRLy_nbsokgfB7CcUm6lhxERp0MpgYz7NG4byhAxSHSUyjdmFG9pClLJh7DZsIZeu0kxau1nx3AzBnG-ANTm16W-7dgJQJ_iWBaBVSvE6lV5exMutmfmzk\",\n" +
                            "        \"n\": \"gobawvl3Y-MRkyIp4LoPJUkxDih1-eTEgZRkOwj1qS4Urix16UPp0LraW6oGva1d7-_Jqt0GUjCM0p7V0Uq3X96T2Au_fnXiZ4BK5aFB9pUxL5eVD0KKuRyh5ImCQk1cuHwJ26xiTxoJZ-4nD2QMXrK19ZDJ5BL8q7xCrhssHrT24RXu-HF0DQBlIX5FJnoveQxqMcbU99hrXfTadjorGSo2XO_cnsfRGMcxdmVGZP5LwrPfUDlttzodiOxBggXVoO33_1JUdifKE77nctH-eWmZ6xMh4OuapmWZTIF1HPx3hS1DMdxiLcWoW5vDBZLg3Dcpaj00dCTcagmKBWoC9w\"\n" +
                            "    }"
            );
        } catch (ParseException e) {
            return null;
        }
    }

    public AccessTokenRequest createAccessTokenRequest(RequestedResource rr, String... references) {
        List<HandleAwareField<RequestedResource>> l = Arrays.stream(references)
                .map(r -> HandleAwareField.<RequestedResource>of(r))
                .collect(Collectors.toList());
        l.add(HandleAwareField.of(rr));
        return new AccessTokenRequest().setAccess(l);
    }
    private String callbackBaseUrl = "http://foo.bar.com/client/callback";
    private String nonce = RandomStringUtils.randomAlphanumeric(20);
    private RequestedResource rr = new RequestedResource()
                            .setType("photo-api")
        .setActions(Arrays.asList("read", "write", "delete"))
        .setLocations(Arrays.asList("https://server.example.net/", "https://resource.local/other"))
        .setDatatypes(Arrays.asList("metadata", "images"));

    private AccessTokenRequest atr = createAccessTokenRequest(rr, "foo", "bar", "baz");

    private KeyRequest key = new KeyRequest()
			.setJwk(privateKey().toPublicJWK())
            .setProof(Key.Proof.HTTPSIG);

    ClientRequest client = new ClientRequest().setKey(key);

    private TransactionRequest request = null;
    private Response response = null;

    private ObjectMapper objectMapper = new ObjectMapper();

    private final String BASE_URL = "http://localhost:9834/api/as/transaction";

    @Test
    public void auth_server_and_client() throws IOException, URISyntaxException {
        RestAssured.baseURI = BASE_URL;
        request = new TransactionRequest()
                .setInteract(new InteractRequest()
                        .setFinish(InteractFinish.redirect()
                                .setUri(URI.create(callbackBaseUrl))
                                .setNonce(nonce))
                        .setStart(Interact.InteractStart.REDIRECT))
                .setAccessToken(atr)
                .setClient(client);

        String req = objectMapper.writeValueAsString(request);
        RequestSpecification request = RestAssured.given();

        request.header("Content-Type", CONTENT_TYPE);
        String contentDigest = contentDigest(req);
        request.header("Content-Digest", contentDigest);

        Map<String, String> ctx = new HashMap<>();
        ctx.put("@target-uri", BASE_URL);
        ctx.put("@method", "POST");
        ctx.put("content-length", String.valueOf(req.length()));
        ctx.put("content-type", CONTENT_TYPE);
        ctx.put("content-digest", contentDigest);

        // now we sign the request which ends up in headers
        sign(request, ctx);

        response = request.body(req).post();
        System.out.println(response.asString());
        TransactionResponse txnResponse = objectMapper.readValue(response.asString(), TransactionResponse.class);

        //@todo need more assertions here
        assertEquals(txnResponse.getCont().getUri().toString(), "http://host.docker.internal:9834/api/as/transaction/continue");

    }

    private void sign(RequestSpecification request, Map<String, String> ctx) {
        SignatureParameters sigParams = new SignatureParameters()
                .setCreated(Instant.now())
                .setKeyid("gnap-public-client")
                .setNonce(RandomStringUtils.randomAlphanumeric(13))
                .setAlg(HttpSigAlgorithm.JOSE)
                .addComponentIdentifier("@target-uri")
                .addComponentIdentifier("@method")
                .addComponentIdentifier("Content-Length")
                .addComponentIdentifier("Content-Type")
                .addComponentIdentifier("Content-Digest");

        byte[] baseBytes = createSignatureBase(sigParams, ctx);

        HttpSign httpSign = new HttpSign(HttpSigAlgorithm.JOSE, privateKey());

        byte[] s = httpSign.sign(baseBytes);

        if (s == null) {
            throw new RuntimeException("Could not sign message.");
        }

        String sigId = RandomStringUtils.randomAlphabetic(5).toLowerCase();

        Dictionary sigHeader = Dictionary.valueOf(Map.of(sigId, ByteSequenceItem.valueOf(s)));
        Dictionary sigInputHeader = Dictionary.valueOf(Map.of(sigId, sigParams.toComponentValue()));

        request.header("Signature", sigHeader.serialize());
        request.header("Signature-Input", sigInputHeader.serialize());
    }

    /**
     * This implements the Httpsig spec
     * @// TODO: 19/05/2022 needs to be refactored to be more generic it is stolen from the ClientApi.java
     * @param sigParams
     * @param ctx
     * @return
     */
    public byte[] createSignatureBase(SignatureParameters sigParams, Map<String, String> ctx) {
        StringBuilder base = new StringBuilder();

        for (StringItem componentIdentifier : sigParams.getComponentIdentifiers()) {

            String componentValue = ctx.get(componentIdentifier.get());

            if (componentValue != null) {
                // write out the line to the base
                componentIdentifier.serializeTo(base)
                        .append(": ")
                        .append(componentValue)
                        .append('\n');
            } else {
                throw new RuntimeException("Couldn't find a value for required parameter: " + componentIdentifier.serialize());
            }
        }

        // add the signature parameters line
        sigParams.toComponentIdentifier().serializeTo(base)
                .append(": ");
        sigParams.toComponentValue().serializeTo(base);

        return base.toString().getBytes();
    }

    private String contentDigest(String req) {
        byte[] cdHash = DigestUtils.sha512(req.getBytes(StandardCharsets.UTF_8));
        String content_digest = Base64.getEncoder().encodeToString(cdHash);
        return "sha-512=:" + content_digest + ":";

    }
}