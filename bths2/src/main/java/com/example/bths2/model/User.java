package com.example.bths2.model;


import jakarta.persistence.*;

@Entity // Annotation để đánh dấu lớp này là một entity JPA
@Table(name = "User") // Tên bảng trong cơ sở dữ liệu
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY) // Tự động tăng giá trị ID
    private Long id;

    @Column(unique = true, nullable = false) // Không cho phép giá trị null và đảm bảo duy nhất
    private String userName;

    @Column(nullable = false) // Không cho phép giá trị null
    private String password;

    @Column // Có thể để null nếu token chưa được tạo
    private String token;

    // Constructors
    public User() {
    }

    public User(String userName, String password, String token) {
        this.userName = userName;
        this.password = password;
        this.token = token;
    }

    // Getters và Setters
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    // Phương thức toString() để kiểm tra
    @Override
    public String toString() {
        return "User{" +
                "id=" + id +
                ", userName='" + userName + '\'' +
                ", password='" + password + '\'' +
                ", token='" + token + '\'' +
                '}';
    }
}
