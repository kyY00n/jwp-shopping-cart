package cart.dto;

import cart.domain.Product;

import java.util.List;
import java.util.stream.Collectors;

public class ProductsResponseDto {

    private List<ProductResponseDto> products;

    private ProductsResponseDto(List<ProductResponseDto> products) {
        this.products = products;
    }

    public static ProductsResponseDto from(final List<Product> products) {
        List<ProductResponseDto> productsResponseDto = products.stream()
                .map(ProductResponseDto::from)
                .collect(Collectors.toList());

        return new ProductsResponseDto(productsResponseDto);
    }

    public List<ProductResponseDto> getProducts() {
        return products;
    }
}
