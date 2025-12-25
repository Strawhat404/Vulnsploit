# 🛡️ VulnSploit
### Advanced Modular Vulnerability Scanning Engine

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Django](https://img.shields.io/badge/backend-Django-092E20.svg)
![Celery](https://img.shields.io/badge/async-Celery-37814A.svg)
![Docker](https://img.shields.io/badge/deploy-Docker-2496ED.svg)

**VulnSploit** is a high-performance, containerized penetration testing backend designed for automated reconnaissance and vulnerability assessment. Built on a robust **Django** architecture with **Celery** for asynchronous task orchestration, it provides a unified REST API to control and aggregate data from industry-standard security tools.

---

##   Key Features

### 🔧 Multi-Tool Integration
VulnSploit wraps and orchestrates a comprehensive suite of offensive security tools:

###   Performance & Architecture
*   **Asynchronous Execution**: Long-running scans are offloaded to **Celery** workers backed by **Redis**, ensuring a non-blocking, responsive API.
*   **Dockerized Deployment**: Fully containerized services (Backend, Worker, Broker) for consistent deployment across environments.
*   **Scalable**: Easily scale worker nodes to handle multiple concurrent scans.

###  Security
*   **JWT Authentication**: Secure API access using JSON Web Tokens (SimpleJWT).
*   **Input Validation**: Strict validation of targets and parameters to prevent command injection.

---

##   Technology Stack

*   **Backend Framework**: Django 5 + Django REST Framework (DRF)
*   **Task Queue**: Celery 5
*   **Message Broker**: Redis 7
*   **Database**: SQLite (Dev) / PostgreSQL (Prod ready)
*   **Containerization**: Docker & Docker Compose

---

##   Getting Started

### Prerequisites
*   Docker & Docker Compose installed on your machine.

### Installation

1.  **Clone the Repository**
    ```bash
    git clone https://github.com/yourusername/vulnsploit.git
    cd vulnsploit
    ```

2.  **Build & Start Services**
    ```bash
    docker-compose up --build
    ```
    *This will start the Django API, Celery Worker, and Redis Broker.*

3.  **Create Admin User**
    ```bash
    docker-compose exec backend python manage.py createsuperuser
    ```

---

##   API Usage

### 1. Authentication
Obtain your access token to interact with the API.

*   **Endpoint**: `POST /api/token/`
*   **Body**:
    ```json
    {
      "username": "admin",
      "password": "yourpassword"
    }
    ```
*   **Response**: Returns `access` and `refresh` tokens.

### 2. Launch a Scan
Trigger an asynchronous scan task.

*   **Endpoint**: `POST /api/scans/`
*   **Headers**: `Authorization: Bearer <your_access_token>`
*   **Body**:
    ```json
    {
      "target": "example.com",
      "scan_type": "nmap_full" 
      // Options: nmap_quick, nikto, sqlmap, gobuster, nuclei, etc.
    }
    ```
*   **Response**:
    ```json
    {
      "id": 123,
      "status": "Scan queued... check back shortly."
    }
    ```

### 3. Retrieve Results
Get the output of a completed scan.

*   **Endpoint**: `GET /api/scans/123/`
*   **Response**:
    ```json
    {
      "id": 123,
      "target": "example.com",
      "result": "Starting Nmap 7.93...\nOpen ports: 80, 443...",
      "created_at": "2023-10-27T10:00:00Z"
    }
    ```

---


##   Contributing

Contributions are welcome! Please fork the repository and submit a Pull Request.

##   License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
