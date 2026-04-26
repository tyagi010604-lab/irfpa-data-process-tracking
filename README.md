# IRFPA/DDCA Management System — C++ Edition

A full-stack IRFPA runsheet management system with a C++ HTTP server backend and pure HTML/CSS/JavaScript frontend.

## Project Structure

```
irfpa_cpp/
├── server.cpp      ← C++ HTTP server + REST API + SQLite logic (all-in-one)
├── index.html      ← Complete frontend (HTML + CSS + JS, no frameworks)
├── Makefile        ← Build helper
└── README.md       ← This file
```

> `irfpa_management.db` is created automatically on first run.

---

## Prerequisites

### Ubuntu / Debian
```bash
sudo apt-get update
sudo apt-get install g++ libsqlite3-dev libssl-dev
```

### macOS (Homebrew)
```bash
brew install openssl sqlite
```

### Fedora / RHEL / CentOS
```bash
sudo dnf install gcc-c++ sqlite-devel openssl-devel
```

---

## Compile & Run

### Option 1 — Using Make
```bash
make
./server
```

### Option 2 — Direct g++ (Linux)
```bash
g++ -std=c++17 -O2 -o server server.cpp -lsqlite3 -lssl -lcrypto -lpthread
./server
```

### Option 3 — Direct g++ (macOS with Homebrew OpenSSL)
```bash
OPENSSL=$(brew --prefix openssl)
g++ -std=c++17 -O2 -o server server.cpp \
    -I$OPENSSL/include -L$OPENSSL/lib \
    -lsqlite3 -lssl -lcrypto -lpthread
./server
```

Then open **http://localhost:8080** in your browser.

---

## Default Credentials

| Username         | Password  | Role      | Stage              |
|------------------|-----------|-----------|--------------------|
| `admin`          | `admin123`| Admin     | All stages         |
| `substrate_op`   | `pass123` | Operator  | CZT Substrate      |
| `epilayer_op`    | `pass123` | Operator  | Epilayer           |
| `fab_op`         | `pass123` | Operator  | Fabrication        |
| `measurement_op` | `pass123` | Operator  | Measurement        |
| `hybrid_op`      | `pass123` | Operator  | Hybridization      |
| `assembly_op`    | `pass123` | Operator  | Assembly           |
| `test_op`        | `pass123` | Operator  | Testing & Demo     |
| `archive_op`     | `pass123` | Operator  | Archive            |

---

## Features

### Dashboard
- Stage overview cards with entry counts
- Device processing status with progress bars
- Auto-archival when all 7 processing stages complete
- Recent activity feed

### Data Entry
- Add parameter values per stage and device
- Upload sample images (stored as base64 in SQLite)
- Image thumbnail viewer

### Parameter Comparison
- Select parameters across multiple stages
- Compare values for the same parameter across different devices
- View associated images

### Administration (Admin only)
- User management (activate/deactivate accounts)
- Archive management with statistics
- Full audit log viewer
- Export audit log as CSV

---

## REST API Reference

| Method | Endpoint                        | Description              |
|--------|---------------------------------|--------------------------|
| POST   | `/api/auth/login`               | Login, returns JWT token |
| GET    | `/api/users/me`                 | Current user info        |
| GET    | `/api/stages`                   | List all stages          |
| GET    | `/api/data-entries`             | List data entries        |
| POST   | `/api/data-entries`             | Create data entry        |
| GET    | `/api/data-entries/:id/image`   | Get entry image (data URL)|
| GET    | `/api/audit-logs`               | List audit logs (admin)  |
| GET    | `/api/audit-logs/export`        | Export audit log as CSV  |
| GET    | `/api/users`                    | List users (admin)       |
| POST   | `/api/users/:id/toggle`         | Toggle user active status|
| GET    | `/api/devices`                  | Device completion status |

Authentication: `Authorization: Bearer <token>` header.

---

## Architecture

- **Backend**: Single C++ file — custom HTTP/1.1 server (POSIX sockets), JWT auth (HMAC-SHA256), SQLite3 via C API
- **Frontend**: Single HTML file — vanilla JS, no dependencies, communicates via fetch() to the REST API
- **Database**: SQLite3 file (`irfpa_management.db`) — tables: `users`, `stages`, `data_entries`, `audit_logs`
- **Security**: SHA-256 password hashing (OpenSSL), JWT with HMAC-SHA256 signatures, role-based access control
