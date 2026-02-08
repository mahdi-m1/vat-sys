# VAT Tax System v3.0.0

## Bahrain NBR Compliance System

A complete VAT management system for Bahrain National Bureau for Revenue (NBR) compliance with AI-powered invoice processing.

---

## Features

### Core Features
- **Client Management**: Add, edit, and manage multiple clients
- **Invoice Upload**: Drag & drop with automatic folder organization
- **AI-Powered OCR**: Extract invoice data using Ollama AI
- **Human Review**: Approve/reject invoices before database entry
- **NBR Reports**: Generate Excel reports in NBR format

### Administration
- **User Management**: Role-based access control (Admin, Reviewer, User)
- **Activity Logging**: Track all user actions
- **System Monitoring**: CPU, memory, disk usage, service status
- **User Performance**: Track productivity metrics

### Settings
- **Ollama AI Configuration**: URL, model, timeout settings
- **Tax Types**: Pre-configured VAT and Excise tax rates

---

## Quick Start

### Prerequisites
- Docker & Docker Compose
- Ollama server (optional, for AI features)

### Installation

```bash
# 1. Extract the files
unzip vat-system-v3.zip
cd vat-system-v3

# 2. Configure environment (optional)
nano .env

# 3. Start the system
docker compose up -d

# 4. Wait for initialization (30 seconds)
sleep 30

# 5. Check status
docker compose ps
```

### Access
- **URL**: http://localhost
- **Username**: admin
- **Password**: admin123

---

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DB_PASSWORD` | VatSecure2026! | Database password |
| `SECRET_KEY` | vat-secret-key... | Application secret |
| `OLLAMA_URL` | http://192.168.1.225:11434 | Ollama server URL |
| `OLLAMA_MODEL` | llama3.2:latest | AI model to use |
| `OLLAMA_TIMEOUT` | 60 | AI request timeout |

### Ollama AI Setup

1. Install Ollama on your server (192.168.1.225)
2. Pull the model: `ollama pull llama3.2:latest`
3. Ensure Ollama is accessible from Docker network

---

## User Roles

| Role | Permissions |
|------|-------------|
| **Admin** | Full access to all features |
| **Reviewer** | Review and approve invoices |
| **User** | Upload invoices, view reports |

---

## File Organization

Invoices are automatically organized:

```
/storage/
├── uploads/
│   └── {client_name}/
│       └── {year}/
│           └── {month}/
│               └── {invoice_type}/
│                   └── invoice_file.pdf
└── reports/
    └── {client_name}/
        └── {year}/
            └── Company_Q1_2026.xlsx
```

---

## NBR Report Format

Generated Excel reports follow NBR format:

### Sheet 1: VP information (Sales)
| Column | Description |
|--------|-------------|
| VAT return field number | NBR field code |
| Invoice number | Invoice reference |
| Invoice date | Date of invoice |
| VAT Account Number | Customer VAT number |
| Entity Name | Customer name |
| Good/Service description | Description |
| Total BHD (exclusive) | Amount before VAT |
| VAT amount | VAT amount |
| Total BHD (inclusive) | Amount with VAT |

### Sheet 2: VAT payer information (Purchases)
Same structure as Sales sheet.

---

## Tax Types

| Code | Name | Rate | NBR Field |
|------|------|------|-----------|
| VAT10 | VAT 10% | 10% | L1C1 |
| VAT0 | VAT 0% | 0% | L2C1 |
| EXEMPT | Exempt | 0% | L3C1 |
| EXCISE | Excise Tax | 50-100% | - |

---

## API Endpoints

### Authentication
- `POST /api/auth/login` - User login
- `POST /api/auth/logout` - User logout
- `GET /api/auth/me` - Get current user

### Clients
- `GET /api/clients` - List clients
- `POST /api/clients` - Create client
- `PUT /api/clients/:id` - Update client
- `DELETE /api/clients/:id` - Delete client

### Invoices
- `GET /api/invoices` - List invoices
- `POST /api/invoices/upload` - Upload invoice
- `PUT /api/invoices/:id` - Update invoice
- `POST /api/invoices/:id/approve` - Approve invoice
- `POST /api/invoices/:id/reject` - Reject invoice

### Reports
- `GET /api/reports` - List reports
- `POST /api/reports/generate` - Generate report
- `GET /api/reports/:id/download` - Download report

---

## Troubleshooting

### Database Connection Error
```bash
docker compose logs postgres
docker compose restart postgres
```

### Ollama Connection Error
```bash
# Test Ollama connection
curl http://192.168.1.225:11434/api/version

# Check if model is available
curl http://192.168.1.225:11434/api/tags
```

### OCR Not Working
```bash
# Check Tesseract installation
docker compose exec vat-app tesseract --version
docker compose exec vat-app tesseract --list-langs
```

### Reset Admin Password
```bash
docker compose exec postgres psql -U vat_user -d vat_tax_db -c \
  "UPDATE users SET password_hash = '\$2b\$12\$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4.FVnWdXrKQvKQWm' WHERE username = 'admin';"
```

---

## Backup & Restore

### Backup Database
```bash
docker compose exec postgres pg_dump -U vat_user vat_tax_db > backup.sql
```

### Restore Database
```bash
docker compose exec -i postgres psql -U vat_user vat_tax_db < backup.sql
```

### Backup Files
```bash
docker cp vat-app:/app/storage ./storage_backup
```

---

## Version History

### v3.0.0 (2026-02-03)
- Complete system rewrite
- User management with RBAC
- AI-powered invoice extraction
- NBR-compliant report generation
- System monitoring dashboard
- Activity logging

---

## Support

For issues and questions, please check:
1. This README file
2. The troubleshooting section
3. Docker logs: `docker compose logs -f`

---

## License

Proprietary - All rights reserved.

---

**VAT Tax System v3.0.0** - Bahrain NBR Compliance Made Easy
