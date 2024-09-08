# Python API with Flask, JWT, and Swagger

This project is a simple Python API using Flask, with JWT authentication and Swagger documentation.

## Features

- User registration and login
- JWT authentication
- Admin-only item creation
- Swagger UI for API documentation and testing
- Environment variable configuration

## Prerequisites

- Python 3.7+
- pip

## Installation

1. Clone the repository:
   ```
   git clone <repository-url>
   cd <project-directory>
   ```

2. Create a virtual environment and activate it:
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```

3. Install the required packages:
   ```
   pip install -r requirements.txt
   ```

4. Create a `.env` file in the project root and add the following:
   ```
   DATABASE_URI=sqlite:///site.db
   JWT_SECRET_KEY=your-secret-key
   ```
   Replace `your-secret-key` with a secure secret key.

## Running the Application

Run the following command in the project root:

```
python app.py
```

The API will be available at `http://localhost:5000`. You can access the Swagger UI documentation at the same URL.

## API Endpoints

- POST `/auth/register`: Register a new user
- POST `/auth/login`: Login and receive a JWT token
- GET `/items`: Get all items (requires authentication)
- POST `/items`: Create a new item (requires admin authentication)

For more details on the API endpoints and how to use them, please refer to the Swagger documentation available when running the application.

## Using JWT Authentication

1. First, use the `/auth/login` endpoint to obtain a JWT token.
2. For endpoints that require authentication, use the Authorization header in your requests.
3. In the Swagger UI:
   - Click the "Authorize" button.
   - In the value field, enter: `Bearer <your_jwt_token>` (replace `<your_jwt_token>` with the actual token you received from the login endpoint).
   - Click "Authorize" to save.
4. For requests outside of Swagger UI, include the header:
   ```
   Authorization: Bearer <your_jwt_token>
   ```

## Contributing

Please read CONTRIBUTING.md for details on our code of conduct, and the process for submitting pull requests.

## License

This project is licensed under the MIT License - see the LICENSE.md file for details.