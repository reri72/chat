# Simple C Chat Program

This is a simple chat program developed in C.

---
## Features

### Server
* Connects to **MySQL** to create and manage the necessary database and tables.
* Handles **client connections** for user registration (sign-up), login, and chat functionalities.
* **SSL/TLS encryption** is used for initial client-server communication (e.g., login, registration) to secure sensitive data. Please note that **chat messages themselves are not encrypted via SSL/TLS after the initial secure connection.**

### Client
* Connects to the server to utilize **registration, login, and chat services.**

---
## Prerequisites

Before running the program, ensure you have the following installed:
* **C Compiler** (e.g., GCC)
* **Make**
* **MySQL Server**

---
## Usage

Follow these steps to build, set up, and run the chat program:

1.  **Build and Package:**
    * Compile the source code: `make`
    * Package the executables: `make pkg`

2.  **Generate Certificates:**
    * Create **self-signed SSL/TLS certificates** for secure server-client communication. (Instructions for generating certificates, e.g., using OpenSSL, should be provided here or in a separate document if complex).

3.  **Prepare MySQL Database:**
    * Set up a **MySQL database** that the server can access. Ensure the server's MySQL credentials are correct.

4.  **Configure Settings:**
    * Adjust the **configuration files** for both the server and client with appropriate values (e.g., server IP, port, database credentials).

5.  **Run the Program:**
    * **Start the server first.**
    * Then, **run the client** and connect to the server to begin using the chat service.
