package rewards;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.SpringApplication;
import org.springframework.context.ApplicationContext;

import common.money.MonetaryAmount;
import rewards.internal.RewardNetworkImpl;
import rewards.internal.StubAccountRepository;
import rewards.internal.StubRestaurantRepository;
import rewards.internal.StubRewardRepository;
import rewards.internal.account.AccountRepository;
import rewards.internal.restaurant.RestaurantRepository;
import rewards.internal.reward.RewardRepository;

class RewardNetworkTests {

    private RewardNetwork rewardNetwork;

    @BeforeEach
    public void setUp() {
        ApplicationContext applicationContext = SpringApplication.run(TestInfrastructureConfig.class);
        AccountRepository accountRepo = new StubAccountRepository();
        RestaurantRepository restaurantRepo = new StubRestaurantRepository();
        RewardRepository rewardRepo = new StubRewardRepository();

        // setup the object being tested by handing what it needs to work
        rewardNetwork = new RewardNetworkImpl(accountRepo, restaurantRepo, rewardRepo);
    }

    @Test
    public void testRewardForDining() {
        Dining dining = Dining.createDining("100.00", "1234123412341234", "1234567890");

        // call the 'rewardNetwork' to test its rewardAccountFor(Dining) method
        RewardConfirmation confirmation = rewardNetwork.rewardAccountFor(dining);

        // assert the expected reward confirmation results
        assertNotNull(confirmation);
        assertNotNull(confirmation.getConfirmationNumber());

        // assert an account contribution was made
        AccountContribution contribution = confirmation.getAccountContribution();
        assertNotNull(contribution);

        // the account number should be '123456789'
        assertEquals("123456789", contribution.getAccountNumber());

        // the total contribution amount should be 8.00 (8% of 100.00)
        assertEquals(MonetaryAmount.valueOf("8.00"), contribution.getAmount());

        // the total contribution amount should have been split into 2
        // distributions
        assertEquals(2, contribution.getDistributions().size());

        // each distribution should be 4.00 (as both have a 50% allocation)
        assertEquals(MonetaryAmount.valueOf("4.00"), contribution.getDistribution("Annabelle").getAmount());
        assertEquals(MonetaryAmount.valueOf("4.00"), contribution.getDistribution("Corgan").getAmount());
    }

}
