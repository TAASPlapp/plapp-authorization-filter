import com.plapp.authorization.JWTAuthorizationRegexFilter;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

@SpringBootTest(classes = ReadKeyTests.class)
public class ReadKeyTests {

    @Test
    public void testRead() throws Exception {
        new JWTAuthorizationRegexFilter(new AuthenticationManager() {
            @Override
            public Authentication authenticate(Authentication authentication) throws AuthenticationException {
                return null;
            }
        });
    }
}
