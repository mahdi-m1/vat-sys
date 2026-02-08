# VAT Tax System v3.0.0 - Quick Start Guide

## 🚀 Installation (2 Minutes)

### Method 1: Automatic Setup (Recommended)

```bash
# 1. Extract files
unzip vat-system-v3.0.0.zip
cd vat-system-v3

# 2. Run setup script
./setup.sh
```

**That's it!** The system will:
- ✅ Build Docker containers
- ✅ Start all services
- ✅ Initialize database
- ✅ Create admin user
- ✅ Check health

---

### Method 2: Manual Setup

```bash
# 1. Extract files
unzip vat-system-v3.0.0.zip
cd vat-system-v3

# 2. Start services
docker compose up -d

# 3. Wait for PostgreSQL
sleep 15

# 4. Initialize admin user
docker compose exec -T postgres psql -U vat_user -d vat_tax_db < init_admin.sql

# 5. Restart application
docker compose restart vat-app
sleep 5
```

---

## 🔐 Access

- **URL**: http://localhost
- **Username**: `admin`
- **Password**: `admin123`

---

## 🔧 Troubleshooting

### Login Failed?

```bash
# Re-initialize admin user
docker compose exec -T postgres psql -U vat_user -d vat_tax_db < init_admin.sql
docker compose restart vat-app
```

### Check Logs

```bash
# Application logs
docker compose logs -f vat-app

# Database logs
docker compose logs -f postgres

# All logs
docker compose logs -f
```

### Reset Everything

```bash
docker compose down -v
./setup.sh
```

---

## 📊 Verify Installation

```bash
# Check container status
docker compose ps

# Check health
curl http://localhost/api/health

# Check database
docker compose exec postgres psql -U vat_user -d vat_tax_db -c "SELECT username FROM users WHERE username = 'admin';"
```

---

## 🎯 Next Steps

1. ✅ Login with admin/admin123
2. ✅ Change admin password in Settings
3. ✅ Add your first client
4. ✅ Upload test invoice
5. ✅ Review and approve
6. ✅ Generate NBR report

---

## ⚙️ Configuration

### Change Ollama Settings

Edit `.env`:
```bash
OLLAMA_URL=http://192.168.1.225:11434
OLLAMA_MODEL=llama3.2:latest
```

Then restart:
```bash
docker compose restart vat-app
```

### Change Database Password

Edit `.env`:
```bash
DB_PASSWORD=YourNewPassword
```

Then rebuild:
```bash
docker compose down
docker compose up -d
```

---

## 🛑 Stop System

```bash
docker compose down
```

## 🚀 Start System

```bash
docker compose up -d
```

---

**Need Help?** Check `README.md` for detailed documentation.
