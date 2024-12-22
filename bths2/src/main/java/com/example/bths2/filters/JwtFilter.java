package com.example.bths2.filters;

import com.example.bths2.utils.JwtUtil;
import io.jsonwebtoken.Claims;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JwtFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(JwtFilter.class);

    /**
     * Phương thức xử lý mỗi yêu cầu HTTP để kiểm tra token.
     * @param request - Yêu cầu HTTP từ client.
     * @param response - Phản hồi HTTP cho client.
     * @param filterChain - Chuỗi filter tiếp theo.
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        // Lấy token từ header Authorization
        String authHeader = request.getHeader("Authorization");

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            logger.warn("Authorization header is missing or invalid.");
            sendErrorResponse(response, "Token is required!", HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        String token = authHeader.substring(7); // Loại bỏ "Bearer " để lấy token thật sự

        try {
            // Xác thực token
            Claims claims = JwtUtil.validateToken(token);
            request.setAttribute("username", claims.getSubject()); // Lưu username từ token vào request
            filterChain.doFilter(request, response); // Tiếp tục xử lý request
        } catch (Exception e) {
            logger.error("Token validation failed: {}", e.getMessage());
            sendErrorResponse(response, e.getMessage(), HttpServletResponse.SC_UNAUTHORIZED);
        }
    }

    /**
     * Phương thức gửi phản hồi lỗi dưới dạng JSON.
     * @param response - Đối tượng phản hồi HTTP.
     * @param message - Thông báo lỗi.
     * @param status - Mã trạng thái HTTP.
     * @throws IOException - Nếu có lỗi khi ghi phản hồi.
     */
    private void sendErrorResponse(HttpServletResponse response, String message, int status) throws IOException {
        response.setStatus(status);
        response.setContentType("application/json");
        response.getWriter().write(String.format("{\"error\": \"%s\"}", message));
    }
}
