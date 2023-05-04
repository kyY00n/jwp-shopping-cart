package cart.dto;

public class AuthPayload {
    private final String email;
    private final String password;

    public AuthPayload(String email, String password) {
        this.email = email;
        this.password = password;
    }

    public String getEmail() {
        return email;
    }

    public String getPassword() {
        return password;
    }
}