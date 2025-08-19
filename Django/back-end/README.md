# Prompeteer_Back

Back end of my grad project application

* Server Files: l-ozma-kapa-project\codebase\deploy\back-end\prompeteer_server
* Virtuale Environement Files: l-ozma-kapa-project\codebase\deploy\back-end\server_venv
* Server Settngs and Configurations: l-ozma-kapa-project\codebase\deploy\back-end\prompeteer_server\prompeteer_server

<!--
![GitHub Created At](https://img.shields.io/github/created-at/arousi/Prompeteer_Back)
![GitHub repo size](https://img.shields.io/github/repo-size/arousi/Prompeteer_Back)
![GitHub commit activity](https://img.shields.io/github/commit-activity/t/arousi/Prompeteer_Back)
-->

![Twitch Status](https://img.shields.io/twitch/status/libyachampion?label=LibyaChampion&link=http%3A%2F%2Fdiscordapp.com%2Fusers%2Flibyachampion_85734)

![PyPI - Python Version](https://img.shields.io/pypi/pyversions/3)
![Django - Version](https://img.shields.io/pypi/v/django?label=Django)
![Bcrypt - Version](https://img.shields.io/pypi/v/bcrypt?label=BCrypt&link=https://pypi.org/project/bcrypt/)
![DRF - Version](https://img.shields.io/pypi/v/djangorestframework?label=DRF&link=https://pypi.org/project/djangorestframework/)
<!--
![PyPI - Version](https://img.shields.io/pypi/v/websocket-client?label=WebSocket)
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/dspy?label=DSPy&link=https%3A%2F%2Fpypi.org%2Fproject%2Fdspy%2F)
-->
![PyPI - Version](https://img.shields.io/pypi/v/LangChain?label=LangChain&link=https://pypi.org/project/langchain/)

## Description

Back end of my grad project application. This Django-based backend provides the API and business logic for the Prompeteer application.

## Technologies Used

* Django
* Django REST Framework
* Channels (for WebSocket support)
* SQLite (Development) -> PostGre SQL (Deployment)
* Langchain: Orchestrates different components, such as LLMs, databases, and APIs, into a single pipeline.
* OpenRouter: Provides a unified interface to access multiple LLMs, enabling dynamic selection and failover.
* LM-Studio-SDK: provides necessary tools to communicate with locally hosted LLMs.

## Project Structure

The backend is structured into several Django apps:

* `auth_api`: Handles user authentication and authorization.
* `langchain_logic`: Contains the logic for interacting with Langchain.
* `open_router`: Manages connections to different LLMs through OpenRouter.
* `pipeline`: Orchestrates the data flow between the different components, from the front end, to OpenRouter and back.

## Running the Server

1. install dependencies via requirements.txt

    ``` bash
    python -m venv env
    .\env\Scripts\activate
    pip install -r requirements.txt
    ```

2. **Start the Django development server:**

    ```bash
    python manage.py runserver
    ```

The backend will be accessible at `http://localhost:8000/`.

## API Endpoints

The API endpoints are documented using Swagger or a similar tool (if integrated). Key endpoints include:

* `http://localhost:8000/auth/reg/`: User registration
* `http://localhost:8000/auth/login/`: User login
* `http://localhost:8000/auth/logout/`: User logout
