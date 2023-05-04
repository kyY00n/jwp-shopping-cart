package cart.controller;

import static cart.factory.ProductFactory.createOtherProduct;
import static cart.factory.ProductFactory.createProduct;
import static cart.factory.UserFactory.createUser;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import cart.domain.Cart;
import cart.domain.CartItem;
import cart.domain.Product;
import cart.domain.User;
import cart.dto.CartItemCreateRequest;
import cart.dto.ProductDto;
import cart.repository.CartRepository;
import cart.repository.ProductRepository;
import cart.repository.UserRepository;
import io.restassured.RestAssured;
import io.restassured.http.ContentType;
import io.restassured.response.ExtractableResponse;
import io.restassured.response.Response;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;

@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
public class CartIntegrationTest {
    private static final String VALID_EMAIL = "rosie@wooteco.com";
    private static final String VALID_PASSWORD = "1234";


    @LocalServerPort
    private int port;

    @Autowired
    private CartRepository cartRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private ProductRepository productRepository;


    @BeforeEach
    void setUp() {
        RestAssured.port = port;
    }

    @Test
    @DisplayName("회원의 장바구니를 읽어올 수 있다.")
    void read_cart_items() {
        //given
        addCartItems();

        //when
        ExtractableResponse<Response> response = RestAssured
                .given().log().all()
                .auth().preemptive().basic(VALID_EMAIL, VALID_PASSWORD)
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .when().get("/user/cartItems")
                .then().log().all().extract();

        //then
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body().jsonPath().getBoolean("success")).isTrue();
        List<ProductDto> productResponses = response.body().jsonPath()
                .getList("data.product", ProductDto.class);
        assertThat(productResponses).hasSize(3);
    }

    private void addCartItems() {
        productRepository.add(createProduct());
        productRepository.add(createOtherProduct());

        User user = createUser("rosie@wooteco.com");
        Cart cart = cartRepository.findByUser(user);

        for (CartItem cartItem : cart.getCartItems()) {
            cartRepository.removeCartItem(cartItem.getId());
        }
        List<Product> products = productRepository.findAll();

        cartRepository.addCartItem(cart, new CartItem(products.get(0)));
        cartRepository.addCartItem(cart, new CartItem(products.get(1)));
        cartRepository.addCartItem(cart, new CartItem(products.get(1)));
    }

    @Test
    @DisplayName("존재하지 않는 유저일 경우 에러 응답을 반환한다.")
    void response_error_when_user_not_found() {
        //given
        //when
        String absentEmail = "notfound@a.com";
        ExtractableResponse<Response> response = RestAssured
                .given().log().all()
                .auth().preemptive().basic(absentEmail, "xxx")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .when().get("/user/cartItems")
                .then().log().all().extract();
        //then
        assertAll(
                () -> assertThat(response.statusCode()).isEqualTo(400),
                () -> assertThat(response.body().jsonPath().getBoolean("success")).isFalse(),
                () -> assertThat(response.body().jsonPath().getString("errorMessage")).isEqualTo("회원을 찾을 수가 없습니다.")
        );
    }

    @Test
    @DisplayName("비밀번호가 일치하지 않는 경우 에러 응답을 반환한다.")
    void response_error_when_password_is_invalid() {
        //given
        //when
        ExtractableResponse<Response> response = RestAssured
                .given().log().all()
                .auth().preemptive().basic("rosie@wooteco.com", "invalidPassword")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .when().get("/user/cartItems")
                .then().log().all().extract();
        //then
        assertAll(
                () -> assertThat(response.statusCode()).isEqualTo(401),
                () -> assertThat(response.body().jsonPath().getBoolean("success")).isFalse(),
                () -> assertThat(response.body().jsonPath().getString("errorMessage")).isEqualTo("올바르지 않은 비밀번호 입니다.")
        );
    }

    @Test
    @DisplayName("장바구니에 상품을 추가할 수 있다.")
    void create_cart_item_success() {
        //given
        CartItemCreateRequest cartItemCreateRequest = createCartItemRequestWithProduct();
        //when
        ExtractableResponse<Response> response = RestAssured
                .given().log().all()
                .auth().preemptive().basic(VALID_EMAIL, VALID_PASSWORD)
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .contentType(ContentType.JSON)
                .body(cartItemCreateRequest)
                .when().post("/user/cartItems")
                .then().log().all().extract();

        //then
        assertAll(
                () -> assertThat(response.statusCode()).isEqualTo(201),
                () -> assertThat(response.body().jsonPath().getBoolean("success")).isTrue()
        );
    }

    private CartItemCreateRequest createCartItemRequestWithProduct() {
        Product product = createProduct();
        productRepository.add(product);
        CartItemCreateRequest cartItemCreateRequest = new CartItemCreateRequest(product.getId());
        return cartItemCreateRequest;
    }

    @Test
    @DisplayName("장바구니에서 상품을 삭제할 수 있다.")
    void delete_cart_item_success() {
        //given
        addCartItem();

        User user = userRepository.findByEmail(VALID_EMAIL).get();
        Cart cart = cartRepository.findByUser(user);
        //when
        ExtractableResponse<Response> response = RestAssured
                .given().log().all()
                .auth().preemptive().basic(VALID_EMAIL, VALID_PASSWORD)
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .contentType(ContentType.JSON)
                .when().delete("/user/cartItems/" + cart.getCartItems().get(0).getId())
                .then().log().all().extract();
        //then
        assertAll(
                () -> assertThat(response.statusCode()).isEqualTo(200),
                () -> assertThat(response.body().jsonPath().getBoolean("success")).isTrue()
        );
    }

    private void addCartItem() {
        CartItemCreateRequest cartItemCreateRequest = createCartItemRequestWithProduct();
        RestAssured.with()
                .auth().preemptive().basic(VALID_EMAIL, VALID_PASSWORD)
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .body(cartItemCreateRequest).post("/user/cartItems");
    }
}