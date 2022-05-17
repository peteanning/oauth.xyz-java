Feature: Requesting Access

  Scenario: Successful Client Request
    Given An Authorisation Server and a Registered Client
    When A request for access is sent and the interaction start method is redirect
    Then A response should be received indicating where to send the User.
