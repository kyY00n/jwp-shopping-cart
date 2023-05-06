package cart.dto.api.response;

import cart.domain.cart.CartProduct;
import cart.dto.ProductDto;

public class CartItemResponse {
    private final Long id;

    private final ProductDto product;

    public CartItemResponse(Long id, ProductDto product) {
        this.id = id;
        this.product = product;
    }

    public static CartItemResponse from(CartProduct cartProduct) {
        ProductDto productDto = ProductDto.from(cartProduct.getProduct());
        return new CartItemResponse(cartProduct.getId(), productDto);
    }

    public Long getId() {
        return id;
    }

    public ProductDto getProduct() {
        return product;
    }
}