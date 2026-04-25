package com.duong.salesmanagement.config;

import com.duong.salesmanagement.model.Role;
import com.duong.salesmanagement.model.User;
import com.duong.salesmanagement.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * Khởi tạo dữ liệu mẫu khi DB trống.
 * Các tài khoản seed đã được kích hoạt sẵn (enabled = true)
 * vì không cần xác minh email.
 */
@Component
public class DataInitializer implements CommandLineRunner {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public DataInitializer(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(String... args) {
        if (userRepository.count() == 0) {
            System.out.println("No users found. Initializing default accounts...");

            userRepository.save(buildUser("admin",      "admin123",      "System Administrator",   "admin@food.dev",      Role.ADMIN));
            userRepository.save(buildUser("customer",   "customer123",   "John Doe – Customer",    "customer@food.dev",   Role.CUSTOMER));
            userRepository.save(buildUser("restaurant", "restaurant123", "Tasty Food Restaurant",  "restaurant@food.dev", Role.RESTAURANT));
            userRepository.save(buildUser("driver",     "driver123",     "Mike – Driver",           "driver@food.dev",     Role.DRIVER));

            System.out.println("Default accounts created successfully!");
        } else {
            System.out.println("Database already has users, skipping seed.");
        }
    }

    /** Tạo User với password đã mã hóa và enabled = true (tài khoản seed). */
    private User buildUser(String username, String rawPassword,
                           String fullName, String email, Role role) {
        User u = new User(username, passwordEncoder.encode(rawPassword), fullName, email, role);
        u.setEnabled(true); // Bỏ qua bước xác minh email cho tài khoản seed
        return u;
    }
}
