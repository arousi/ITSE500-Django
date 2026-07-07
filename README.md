 # Prompeteer Server Backend

[![CI](https://github.com/arousi/ITSE500-Django/actions/workflows/ci.yml/badge.svg)](https://github.com/arousi/ITSE500-Django/actions/workflows/ci.yml)

Welcome to the Prompeteer backend server! This guide will help you set up, run, and explore the server, even if you're new to Django or backend development.

See [TESTING.md](./TESTING.md) for how to run the test suite locally and how the OpenAPI contract (consumed by the Flutter and React clients) is generated and kept in sync.

---

## 📁 Project Structure

```
codebase/
  deploy/
    back-end/
      prompeteer_server/
        ├── auth_api/           # Authentication and registration logic
        ├── chat_api/           # Chat and messaging endpoints
        ├── user_mang/          # User management (profiles, permissions, etc.)
        ├── prompeteer_server/  # Main Django project config (settings, urls, wsgi/asgi)
        │   ├── static/templates/   # HTML templates (landing page, etc.)
        ├── staticfiles/        # Collected static files for production
        ├── db.sqlite3          # SQLite database (default)
        ├── README.md           # This file
        └── ...
```

---

## 🚀 Getting Started

### 1. Install Python

- Make sure you have **Python 3.10+** installed. You can check with:

  ```sh
  python --version
  ```

### 2. Create and Activate a Virtual Environment

use VS-Code Terminal which will run the `server_venv` right away and run the server from there

- On Windows:

  ```sh
  python -m venv server_venv
  server_venv\Scripts\activate
  ```

- On Mac/Linux:

  ```sh
  python3 -m venv server_venv
  source server_venv/bin/activate
  ```

### 3. Install Dependencies

From the `prompeteer_server` directory, run:

```sh
pip install -r requirements.txt
```

**Note:**

- The `requirements.txt` file is located in your project directory, *not* inside the `server_venv` folder.
- The `server_venv` directory is your local virtual environment and should **never** be uploaded to GitHub (it's in `.gitignore`).
- If `requirements.txt` is missing, ask your team or run `pip freeze > requirements.txt` after installing dependencies.

### 4. Run Database Migrations

```sh
python manage.py migrate
```

### 5. Create a Superuser (for admin access)

```sh
python manage.py createsuperuser
```

### 6. Start the Development Server

```sh
python manage.py runserver
```

- Visit [http://127.0.0.1:8000/](http://127.0.0.1:8000/) to see the landing page.
- Admin panel: [http://127.0.0.1:8000/admin/](http://127.0.0.1:8000/admin/)

---

## 🗂 Navigating the Directories

- `auth_api/` — All authentication, registration, and login endpoints.
- `user_mang/` — User profiles, permissions, and related logic.
- `chat_api/` — Chat and messaging endpoints.
- `prompeteer_server/` — Django project settings, URLs, and ASGI/WSGI config.
- `static/templates/` — HTML templates (landing page, etc.).
- `staticfiles/` — Static files for production (after running `collectstatic`).

---

## 📬 Making API Requests

You can use [Postman](https://www.postman.com/) or `curl` to interact with the API. For a quick start, you can import the provided Postman collection into the Postman VS Code extension:

### 📨 Importing the Postman Collection in VS Code

1. **Install the Postman VS Code extension** if you haven't already.
2. In VS Code, open the Command Palette (`Ctrl+Shift+P`), search for `Postman: Open` and launch the extension.
3. Click the **Import** button in the Postman panel.
4. Select the file `postman-prompeteer-api.postman_collection.json` from the project root.
5. The collection with all main API endpoints will appear in your Postman workspace—ready to use!

You can also use the standalone Postman app to import the same file.

Here are some example requests:

### Visitor Login (Guest Session)

```sh
curl -X POST http://127.0.0.1:8000/api/v1/auth_api/visitor-login/ \
     -H "Content-Type: application/json" \
     -d '{"device_id": "abc123xyz"}'
```

### User Registration

```sh
curl -X POST http://127.0.0.1:8000/api/v1/auth_api/reg/ \
     -H "Content-Type: application/json" \
     -d '{"username": "john_doe", "email": "john@example.com", "password": "hashedpassword123"}'
```

### User Login

```sh
curl -X POST http://127.0.0.1:8000/api/v1/auth_api/login/ \
     -H "Content-Type: application/json" \
     -d '{"email": "john@example.com", "password": "hashedpassword123"}'
```

---

## 🛠 Troubleshooting

- If you get `ModuleNotFoundError`, check that your virtual environment is activated and dependencies are installed.
- For database issues, try deleting `db.sqlite3` and running `python manage.py migrate` again (only for development/testing).
- For errors or debugging check the `.log` files, utilize the `Postman`

---

## 📚 More

- For more endpoints, see the landing page at [http://127.0.0.1:8000/](http://127.0.0.1:8000/).
- For real-time features, make sure Redis is running (for Channels support).

---

Happy hacking! 🚀
