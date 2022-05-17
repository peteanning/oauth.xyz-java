package io.bspk;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sailpoint.ietf.subjectidentifiers.model.SubjectIdentifierFormats;
import io.bspk.oauth.xyz.data.AccessToken;
import io.bspk.oauth.xyz.data.Interact;
import io.bspk.oauth.xyz.data.InteractFinish;
import io.bspk.oauth.xyz.data.api.*;
import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import org.apache.commons.lang3.RandomStringUtils;

import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class StepDefinitions {

    public AccessTokenRequest createAccessTokenRequest(RequestedResource rr, String... references) {
        List<HandleAwareField<RequestedResource>> l = Arrays.stream(references)
                .map(r -> HandleAwareField.<RequestedResource>of(r))
                .collect(Collectors.toList());
        l.add(HandleAwareField.of(rr));
        return new AccessTokenRequest().setAccess(l);
    }
    private String callbackBaseUrl = "http://foo.bar.com/client/callback";
    private String nonce = RandomStringUtils.randomAlphanumeric(20);
    RequestedResource rr = new RequestedResource()
                            .setType("photo-api")
        .setActions(Arrays.asList("read", "write", "delete"))
        .setLocations(Arrays.asList("https://server.example.net/", "https://resource.local/other"))
        .setDatatypes(Arrays.asList("metadata", "images"));

    AccessTokenRequest atr = createAccessTokenRequest(rr, "foo", "bar", "baz");

    TransactionRequest request = new TransactionRequest()
            .setInteract(new InteractRequest()
                    .setFinish(InteractFinish.redirect()
                            .setUri(URI.create(callbackBaseUrl))
                            .setNonce(nonce))
                    .setStart(Interact.InteractStart.REDIRECT))
            .setAccessToken(atr);


    @Given("An Authorisation Server and a Registered Client")
    public void foo() throws IOException {
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.writeValue(System.out, request);
    }

    @When("A request for access is sent and the interaction start method is redirect")
    public void when_i_wait () {
        System.out.println("Implement me");
    }

    @Then("A response should be received indicating where to send the User.")
    public void my_belly_should_growl () {

        System.out.println("Implement me");
    }
}