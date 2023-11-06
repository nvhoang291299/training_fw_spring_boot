package accounts.web;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import accounts.AccountManager;
import rewards.internal.account.Account;

/**
 * A Spring MVC REST Controller handling requests to retrieve Account
 * information.
 *
 * Note that some of the Account related classes are imported from the
 * rewards-db project:
 *
 * -Domain objects: Account and Beneficiary -Service layer: AccountManager
 * interface -Repository layer: AccountRepository interface
 *
 */
// TODO-03: Add an appropriate annotation to make this class a REST controller -
// done
@RestController
public class AccountController {

    private final AccountManager accountManager;

    /**
     * Creates a new AccountController with a given account manager.
     */
    @Autowired
    public AccountController(AccountManager accountManager) {
        this.accountManager = accountManager;
    }

    /**
     * Return a list of all accounts
     */
    // TODO-04: Add an appropriate annotation to make this method handle - done
    // "/accounts"
    @GetMapping("/accounts")
    public List<Account> accountList() {

        // TODO-05: Implement the logic to find and return all accounts - done
        // - Use "accountManger" object to get all accounts
        // - Recompile this class if necessary, and wait for the application to
        // restart (via devtools)
        // - From the home page, click the link - this should now work
        // - If you prefer, access http://localhost:8080/accounts using curl or
        // Postman
        List<Account> list = accountManager.getAllAccounts();
        return list; // REPLACE THIS LINE to return a list accounts

        // TODO-06: (If you are using STS) We are about to make lots of
        // changes, so stop the application otherwise Devtools
        // will keep restarting it.
    }

    // TODO-08: Implement the /accounts/{entityId} request handling method. -
    // done
    // - Call the method accountDetails().
    // - Annotate to define URL mapping /accounts/{entityId}
    // this method will respond to.
    // - Use a method parameter to obtain the URI template parameter
    // needed to retrieve an account.
    // - Use the accountManager to obtain an account. This is the value to
    // return
    // - Save all work.
    @GetMapping("/accounts/{entityId}")
    public Account accountDetails(@PathVariable long entityId) {
        Account account = accountManager.getAccount(entityId);
        return account;
    }

    // TODO-10b: If AccountControllerTests.testHandleDetailsRequest()
    // fails, fix errors before moving on

    // TODO-11: Run the application
    // - You should now be able to invoke http://localhost:8080/accounts/N
    // where N is 0-20 and get a response. You can use curl, Postman or
    // your browser to do this.

}
