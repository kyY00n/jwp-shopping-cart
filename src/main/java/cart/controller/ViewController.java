package cart.controller;

import cart.dto.UserEmailPasswordDto;
import cart.service.ProductService;
import cart.service.UserService;
import java.util.List;
import java.util.stream.Collectors;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class ViewController {

    private final ProductService productService;
    private final UserService userService;

    public ViewController(ProductService productService, UserService userService) {
        this.productService = productService;
        this.userService = userService;
    }

    @GetMapping("/")
    public String getHome(final Model model) {
        model.addAttribute("productsDto", productService.findAll());
        return "index";
    }

    @GetMapping("/admin")
    public String getAdmin(final Model model) {
        model.addAttribute("productsDto", productService.findAll());
        return "admin";
    }

    @GetMapping("/settings")
    public String getSettings(final Model model) {
        List<UserEmailPasswordDto> userEmailPasswordDtos = userService.findAllUser().stream().map(UserEmailPasswordDto::from)
                .collect(Collectors.toList());
        model.addAttribute("users", userEmailPasswordDtos);
        return "settings";
    }

    @GetMapping("/cart")
    public String getCart() {
        return "cart";
    }
}
