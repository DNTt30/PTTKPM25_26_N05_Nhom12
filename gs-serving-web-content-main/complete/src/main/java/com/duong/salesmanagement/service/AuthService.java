package com.duong.salesmanagement.service;

import com.duong.salesmanagement.model.Role;
import com.duong.salesmanagement.model.User;
import com.duong.salesmanagement.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Random;

/**
 * Xử lý nghiệp vụ đăng ký và xác minh OTP.
 */
@Service
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;

    public AuthService(UserRepository userRepository,
                       PasswordEncoder passwordEncoder,
                       EmailService emailService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.emailService = emailService;
    }

    /**
     * Đăng ký tài khoản mới:
     *  1. Validate trùng username / email
     *  2. Mã hóa password
     *  3. Tạo OTP 6 chữ số, lưu DB với thời hạn 15 phút
     *  4. Gửi OTP qua email
     *
     * @return User đã lưu (chưa enabled)
     */
    @org.springframework.transaction.annotation.Transactional
    public User register(String username, String rawPassword, String fullName,
                         String email, String roleName) {

        // Check xem username hoặc email đã tồn tại chưa
        User existingUsername = userRepository.findByUsername(username).orElse(null);
        User existingEmail = userRepository.findByEmail(email).orElse(null);

        User userToSave = null;

        // Nếu email đã tồn tại
        if (existingEmail != null) {
            if (existingEmail.isEnabled()) {
                throw new IllegalArgumentException("Email đã được sử dụng và đã xác minh!");
            } else {
                // Tái sử dụng user cũ chưa xác minh
                userToSave = existingEmail;
                // Nếu đổi username khác nhưng email cũ, ta báo lỗi hoặc cập nhật luôn (đơn giản nhất là báo hãy đăng ký lại đúng username)
            }
        }

        // Nếu username đã tồn tại (mà không trùng email ở trên)
        if (userToSave == null && existingUsername != null) {
            if (existingUsername.isEnabled()) {
                throw new IllegalArgumentException("Tên đăng nhập đã tồn tại!");
            } else {
                userToSave = existingUsername;
            }
        }

        Role role;
        try {
            role = Role.valueOf(roleName.toUpperCase());
        } catch (IllegalArgumentException ex) {
            role = Role.CUSTOMER;
        }

        String otp = String.format("%06d", new java.util.Random().nextInt(1_000_000));

        if (userToSave == null) {
            // Tạo mới hoàn toàn
            userToSave = new User(
                    username,
                    passwordEncoder.encode(rawPassword),
                    fullName,
                    email,
                    role
            );
        } else {
            // Cập nhật lại thông tin mới nhất vào record chưa xác minh
            userToSave.setUsername(username);
            userToSave.setPassword(passwordEncoder.encode(rawPassword));
            userToSave.setFullName(fullName);
            userToSave.setEmail(email);
            userToSave.setRole(role);
        }

        userToSave.setVerificationCode(otp);
        userToSave.setCodeExpiry(LocalDateTime.now().plusMinutes(15));
        userToSave.setEnabled(false);

        userRepository.save(userToSave);

        // Gửi OTP qua Gmail (nếu lỗi, Transactional sẽ rollback CSDL)
        emailService.sendVerificationCode(email, otp);

        return userToSave;
    }

    /**
     * Xác minh OTP:
     *  1. Tìm user theo email
     *  2. Kiểm tra code khớp và chưa hết hạn
     *  3. Kích hoạt tài khoản (enabled = true), xóa code
     */
    public void verifyCode(String email, String code) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("Email không tồn tại!"));

        if (user.isEnabled()) {
            throw new IllegalStateException("Tài khoản đã được xác minh trước đó!");
        }

        if (user.getCodeExpiry() == null || LocalDateTime.now().isAfter(user.getCodeExpiry())) {
            throw new IllegalStateException("Mã xác minh đã hết hạn! Vui lòng đăng ký lại.");
        }

        if (!code.equals(user.getVerificationCode())) {
            throw new IllegalArgumentException("Mã xác minh không chính xác!");
        }

        // Kích hoạt tài khoản
        user.setEnabled(true);
        user.setVerificationCode(null);
        user.setCodeExpiry(null);
        userRepository.save(user);
    }

    /**
     * Gửi lại OTP mới cho email (nếu hết hạn hoặc thất lạc).
     */
    public void resendCode(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("Email không tồn tại!"));

        if (user.isEnabled()) {
            throw new IllegalStateException("Tài khoản đã được xác minh rồi!");
        }

        String newOtp = String.format("%06d", new Random().nextInt(1_000_000));
        user.setVerificationCode(newOtp);
        user.setCodeExpiry(LocalDateTime.now().plusMinutes(15));
        userRepository.save(user);

        emailService.sendVerificationCode(email, newOtp);
    }

    /**
     * Quên mật khẩu: Gửi OTP xác nhận
     */
    public void forgotPassword(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("Email không tồn tại trong hệ thống!"));

        if (!user.isEnabled()) {
            throw new IllegalStateException("Tài khoản chưa được xác minh. Không thể đặt lại mật khẩu.");
        }

        String otp = String.format("%06d", new Random().nextInt(1_000_000));
        user.setVerificationCode(otp);
        user.setCodeExpiry(LocalDateTime.now().plusMinutes(15));
        userRepository.save(user);

        emailService.sendPasswordResetCode(email, otp);
    }

    /**
     * Xác nhận đổi mật khẩu mới bằng OTP
     */
    public void resetPassword(String email, String code, String newPassword) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("Email không tồn tại!"));

        if (user.getCodeExpiry() == null || LocalDateTime.now().isAfter(user.getCodeExpiry())) {
            throw new IllegalStateException("Mã xác nhận đã hết hạn! Vui lòng gửi yêu cầu mới.");
        }

        if (!code.equals(user.getVerificationCode())) {
            throw new IllegalArgumentException("Mã xác nhận không chính xác!");
        }

        // Cập nhật mật khẩu mới
        user.setPassword(passwordEncoder.encode(newPassword));
        user.setVerificationCode(null);
        user.setCodeExpiry(null);
        userRepository.save(user);
    }
}
