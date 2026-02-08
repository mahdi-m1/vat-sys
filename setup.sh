#!/bin/bash
# =====================================================
# VAT Tax System v3.0.0 - Setup Script
# =====================================================

set -e

echo "🚀 Starting VAT Tax System v3.0.0 Setup..."
echo ""

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    exit 1
fi

if ! command -v docker compose &> /dev/null; then
    echo "❌ Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

echo "✅ Docker and Docker Compose are installed"
echo ""

# Stop existing containers
echo "🛑 Stopping existing containers..."
docker compose down 2>/dev/null || true
echo ""

# Build containers
echo "🔨 Building containers..."
docker compose build --no-cache
echo ""

# Start containers
echo "🚀 Starting containers..."
docker compose up -d
echo ""

# Wait for PostgreSQL to be ready
echo "⏳ Waiting for PostgreSQL to be ready..."
sleep 10

# Check PostgreSQL health
for i in {1..30}; do
    if docker compose exec -T postgres pg_isready -U vat_user -d vat_tax_db > /dev/null 2>&1; then
        echo "✅ PostgreSQL is ready"
        break
    fi
    if [ $i -eq 30 ]; then
        echo "❌ PostgreSQL failed to start"
        exit 1
    fi
    sleep 2
done
echo ""

# Initialize admin user
echo "👤 Initializing admin user..."
docker compose exec -T postgres psql -U vat_user -d vat_tax_db < init_admin.sql
echo ""

# Restart application
echo "🔄 Restarting application..."
docker compose restart vat-app
sleep 5
echo ""

# Check application health
echo "🏥 Checking application health..."
for i in {1..10}; do
    if curl -s http://localhost/api/health > /dev/null 2>&1; then
        echo "✅ Application is healthy"
        break
    fi
    if [ $i -eq 10 ]; then
        echo "⚠️  Application health check failed, but it might still be starting..."
    fi
    sleep 2
done
echo ""

# Show status
echo "📊 Container Status:"
docker compose ps
echo ""

echo "✅ Setup completed successfully!"
echo ""
echo "📝 Access Information:"
echo "   URL:      http://localhost"
echo "   Username: admin"
echo "   Password: admin123"
echo ""
echo "🔧 Useful Commands:"
echo "   View logs:    docker compose logs -f vat-app"
echo "   Stop system:  docker compose down"
echo "   Start system: docker compose up -d"
echo ""
