# SecureShare

## https://secshare.fly.dev/

SecureShare is a secure file sharing backend service built with **Spring Boot**, **JWT authentication**, and **PostgreSQL**.
The application focuses on providing a secure infrastructure for user authentication and protected resource access.

## Features

* User registration and authentication
* JWT based authentication system
* Secure password hashing
* Role based authorization
* RESTful API design
* PostgreSQL database integration
* Deployable to cloud platforms (Render)

## Tech Stack

* Java
* Spring Boot
* Spring Security
* JWT (JSON Web Tokens)
* PostgreSQL
* Maven

## Project Structure

```
src
 ├── auth
 │    ├── AuthController
 │    ├── AuthService
 │
 ├── user
 │    ├── User
 │    ├── UserRepository
 │
 ├── security
 │    ├── JwtService
 │    ├── JwtFilter
 │
 └── config
      ├── SecurityConfig
```

## Authentication Flow

1. User registers with email and password
2. Password is hashed using `PasswordEncoder`
3. User logs in with credentials
4. Server generates a **JWT token**
5. Client sends token in requests

```
Authorization: Bearer <JWT_TOKEN>
```

6. `JwtFilter` validates the token
7. If valid, the user is authenticated in the security context

## API Endpoints

### Authentication

```
POST /auth/register
POST /auth/login
```

### Example Request

```
POST /auth/login
```

Body:

```json
{
  "email": "user@example.com",
  "password": "password123"
}
```

Response:

```json
{
  "token": "JWT_TOKEN"
}
```

## Environment Variables

Example configuration:

```
SPRING_DATASOURCE_URL=jdbc:postgresql://HOST:PORT/DATABASE
SPRING_DATASOURCE_USERNAME=USERNAME
SPRING_DATASOURCE_PASSWORD=PASSWORD

JWT_SECRET=your_base64_secret_key
```

## Running the Project

Clone the repository:

```
git clone https://github.com/yourusername/secureshare.git
```

Navigate to the project:

```
cd secureshare
```

Run the project:

```
./mvnw spring-boot:run
```

## Deployment

The project can be deployed using **Render** with a PostgreSQL database service.

Steps:

1. Create PostgreSQL service
2. Copy the internal database URL
3. Configure environment variables
4. Deploy the Spring Boot application

## Security Notes

* Passwords are stored using hashing.
* JWT tokens are signed using a secret key.
* All protected routes require authentication.

## Future Improvements

* File upload system
* Encrypted file storage
* File sharing with expiring links
* Access logging
* User roles and permissions

## License

This project is for educational purposes.

