package cart.dto.api.request;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.PositiveOrZero;

public class ProductEditRequest {

    @NotBlank(message = "상품명은 공백일 수 없습니다.")
    private final String name;

    @NotNull(message = "가격은 공백일 수 없습니다.")
    @PositiveOrZero(message = "가격은 0원 이상이어야 합니다.")
    private final int price;

    @NotNull(message = "상품 이미지 url을 넣어주세요.")
    private final String imgUrl;

    public ProductEditRequest(String name, int price, String imgUrl) {
        this.name = name;
        this.price = price;
        this.imgUrl = imgUrl;
    }

    public String getName() {
        return name;
    }

    public int getPrice() {
        return price;
    }

    public String getImgUrl() {
        return imgUrl;
    }
}
