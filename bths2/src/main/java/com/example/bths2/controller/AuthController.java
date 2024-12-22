package com.example.bths2.controller;

import com.example.bths2.model.User;
import com.example.bths2.repositories.UserRepository;
import com.example.bths2.utils.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private UserRepository userRepository;

    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    /**
     * API Login - Đăng nhập người dùng.
     * @param loginRequest - Đối tượng chứa username và password từ client.
     * @return ResponseEntity<?> - Trả về token JWT nếu thành công, hoặc thông báo lỗi nếu thất bại.
     */
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody User loginRequest) {
        // Tìm người dùng theo username
        User user = userRepository.findByUserName(loginRequest.getUserName());

        // Kiểm tra username và mật khẩu
        if (user == null || !passwordEncoder.matches(loginRequest.getPassword(), user.getPassword())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "Invalid credentials"));
        }

        // Sinh token
        String token = JwtUtil.generateToken(user.getUserName());
        user.setToken(token);
        userRepository.save(user);

        // Trả về token và thông tin người dùng (nếu cần)
        Map<String, Object> response = new HashMap<>();
        response.put("token", token);
        response.put("username", user.getUserName());
        return ResponseEntity.ok(response);
    }

    /**
     * API Verify Token - Xác thực token từ client.
     * @param token - Token JWT gửi qua query parameter.
     * @return ResponseEntity<?> - Trả về thông báo nếu token hợp lệ hoặc lỗi nếu không hợp lệ.
     */
    @GetMapping("/verify")
    public ResponseEntity<?> verifyToken(@RequestParam String token) {
        try {
            // Xác thực token
            JwtUtil.validateToken(token);
            return ResponseEntity.ok(Map.of("message", "Token is valid"));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", e.getMessage()));
        }
    }
}
