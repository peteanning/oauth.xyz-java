package io.bspk;
import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;

public class StepDefinitions {

    @Given("I have {int} cukes in my belly")
    public void i_have_n_cukes_in_my_belly(int cukes) {
        System.out.format("Cukes: %n\n", cukes);
    }

    @When("I wait 1 hour")
    public void when_i_wait () {
        System.out.println("I have waited one hour");
    }

    @Then("my belly should growl")
    public void my_belly_should_growl () {
        System.out.println("my belly should growl");
    }
}