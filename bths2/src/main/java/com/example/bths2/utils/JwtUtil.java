package com.example.bths2.utils;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import java.util.Date;

public class JwtUtil {
    private static final Logger logger = LoggerFactory.getLogger(JwtUtil.class);

    // Khóa bí mật mạnh hơn
    private static final SecretKey SECRET_KEY = Keys.hmacShaKeyFor("12345678901234567890123456789012".getBytes());

    // Thời gian hết hạn token (1 giờ)
    private static final long EXPIRATION_TIME = 3600000;

    /**
     * Phương thức tạo JWT.
     * @param username - Tên người dùng cần mã hóa trong token.
     * @return String - Token đã mã hóa.
     */
    public static String generateToken(String username) {
        return Jwts.builder()
                .setSubject(username) // Đặt giá trị chính (username)
                .setIssuedAt(new Date()) // Thời gian tạo token
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME)) // Thời gian hết hạn
                .signWith(SECRET_KEY, SignatureAlgorithm.HS256) // Mã hóa với thuật toán HS256
                .compact(); // Hoàn thiện token
    }

    /**
     * Phương thức xác thực và giải mã JWT.
     * @param token - Token được gửi từ client.
     * @return Claims - Dữ liệu chứa trong token (username, thời gian, ...)
     * @throws Exception - Ném lỗi nếu token không hợp lệ hoặc hết hạn.
     */
    public static Claims validateToken(String token) throws Exception {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(SECRET_KEY)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (ExpiredJwtException e) {
            logger.error("Token đã hết hạn!", e);
            throw new Exception("Token đã hết hạn!");
        } catch (UnsupportedJwtException e) {
            logger.error("Token không được hỗ trợ!", e);
            throw new Exception("Token không được hỗ trợ!");
        } catch (MalformedJwtException e) {
            logger.error("Token không hợp lệ!", e);
            throw new Exception("Token không hợp lệ!");
        } catch (SignatureException e) {
            logger.error("Chữ ký token không hợp lệ!", e);
            throw new Exception("Chữ ký token không hợp lệ!");
        } catch (IllegalArgumentException e) {
            logger.error("Token rỗng!", e);
            throw new Exception("Token rỗng!");
        }
    }
}
