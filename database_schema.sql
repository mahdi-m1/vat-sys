-- =====================================================
-- VAT Tax System v3.0.0 - Database Schema
-- PostgreSQL Database
-- =====================================================

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- =====================================================
-- 1. USERS & AUTHENTICATION
-- =====================================================

-- Roles table
CREATE TABLE IF NOT EXISTS roles (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert default roles
INSERT INTO roles (name, description) VALUES
    ('admin', 'Full system access - can manage everything'),
    ('manager', 'Can manage clients, review and approve reports'),
    ('accountant', 'Can upload invoices, review and create reports'),
    ('data_entry', 'Can only upload invoices'),
    ('auditor', 'Read-only access for auditing')
ON CONFLICT (name) DO NOTHING;

-- Permissions table
CREATE TABLE IF NOT EXISTS permissions (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert default permissions
INSERT INTO permissions (name, description) VALUES
    ('view_clients', 'View client list and details'),
    ('add_client', 'Add new clients'),
    ('edit_client', 'Edit client information'),
    ('delete_client', 'Delete clients'),
    ('upload_invoice', 'Upload invoices'),
    ('review_invoice', 'Review uploaded invoices'),
    ('approve_invoice', 'Approve invoices for reports'),
    ('generate_report', 'Generate VAT reports'),
    ('approve_report', 'Approve and finalize reports'),
    ('export_report', 'Export reports to Excel/PDF'),
    ('manage_users', 'Manage system users'),
    ('view_logs', 'View activity logs'),
    ('manage_settings', 'Manage system settings'),
    ('view_dashboard', 'View monitoring dashboards')
ON CONFLICT (name) DO NOTHING;

-- Role-Permission mapping
CREATE TABLE IF NOT EXISTS role_permissions (
    role_id INTEGER REFERENCES roles(id) ON DELETE CASCADE,
    permission_id INTEGER REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

-- Assign permissions to roles
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.name = 'admin'
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.name = 'manager' AND p.name IN (
    'view_clients', 'add_client', 'edit_client',
    'upload_invoice', 'review_invoice', 'approve_invoice',
    'generate_report', 'approve_report', 'export_report',
    'view_logs', 'view_dashboard'
)
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.name = 'accountant' AND p.name IN (
    'view_clients', 'upload_invoice', 'review_invoice',
    'approve_invoice', 'generate_report', 'export_report', 'view_dashboard'
)
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.name = 'data_entry' AND p.name IN (
    'view_clients', 'upload_invoice', 'view_dashboard'
)
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.name = 'auditor' AND p.name IN (
    'view_clients', 'view_logs', 'view_dashboard'
)
ON CONFLICT DO NOTHING;

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    uuid UUID DEFAULT uuid_generate_v4() UNIQUE,
    username VARCHAR(100) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(255),
    role_id INTEGER REFERENCES roles(id) DEFAULT 4,
    is_active BOOLEAN DEFAULT TRUE,
    is_locked BOOLEAN DEFAULT FALSE,
    failed_login_attempts INTEGER DEFAULT 0,
    last_login TIMESTAMP,
    last_activity TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by INTEGER REFERENCES users(id)
);

-- Create default admin user (password: admin123)
INSERT INTO users (username, email, password_hash, full_name, role_id, is_active)
VALUES ('admin', 'admin@vatsystem.local', 
        '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4.VTtYWLgN3H4Wmu',
        'System Administrator', 1, TRUE)
ON CONFLICT (username) DO NOTHING;

-- =====================================================
-- 2. CLIENTS & COMPANIES
-- =====================================================

CREATE TABLE IF NOT EXISTS clients (
    id SERIAL PRIMARY KEY,
    uuid UUID DEFAULT uuid_generate_v4() UNIQUE,
    name VARCHAR(255) NOT NULL,
    name_ar VARCHAR(255),
    vat_number VARCHAR(50) UNIQUE NOT NULL,
    cr_number VARCHAR(50),
    address TEXT,
    phone VARCHAR(50),
    email VARCHAR(255),
    contact_person VARCHAR(255),
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by INTEGER REFERENCES users(id)
);

-- Client alternative names for fuzzy matching
CREATE TABLE IF NOT EXISTS client_aliases (
    id SERIAL PRIMARY KEY,
    client_id INTEGER REFERENCES clients(id) ON DELETE CASCADE,
    alias_name VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- =====================================================
-- 3. TAX CONFIGURATION
-- =====================================================

CREATE TABLE IF NOT EXISTS tax_types (
    id SERIAL PRIMARY KEY,
    code VARCHAR(20) UNIQUE NOT NULL,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    rate DECIMAL(5,4) NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    nbr_field_code VARCHAR(20),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert default tax types
INSERT INTO tax_types (code, name, description, rate, nbr_field_code) VALUES
    ('VAT_10', 'Standard VAT', 'Standard VAT Rate 10%', 0.10, 'L1C1'),
    ('VAT_0', 'Zero Rate VAT', 'Zero Rate VAT 0%', 0.00, 'L2C1'),
    ('VAT_EXEMPT', 'Exempt', 'VAT Exempt', 0.00, 'L3C1'),
    ('EXCISE_100', 'Excise 100%', 'Tobacco & Alcohol', 1.00, NULL),
    ('EXCISE_50', 'Excise 50%', 'Soft Drinks, Energy Drinks, Sweets', 0.50, NULL)
ON CONFLICT (code) DO NOTHING;

-- =====================================================
-- 4. TAX PERIODS
-- =====================================================

CREATE TABLE IF NOT EXISTS tax_periods (
    id SERIAL PRIMARY KEY,
    client_id INTEGER REFERENCES clients(id) ON DELETE CASCADE,
    year INTEGER NOT NULL,
    quarter INTEGER NOT NULL CHECK (quarter BETWEEN 1 AND 4),
    start_date DATE NOT NULL,
    end_date DATE NOT NULL,
    status VARCHAR(20) DEFAULT 'open' CHECK (status IN ('open', 'in_progress', 'pending_review', 'approved', 'submitted', 'closed')),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by INTEGER REFERENCES users(id),
    approved_by INTEGER REFERENCES users(id),
    approved_at TIMESTAMP,
    UNIQUE(client_id, year, quarter)
);

-- =====================================================
-- 5. INVOICES & DOCUMENTS
-- =====================================================

CREATE TABLE IF NOT EXISTS invoices (
    id SERIAL PRIMARY KEY,
    uuid UUID DEFAULT uuid_generate_v4() UNIQUE,
    client_id INTEGER REFERENCES clients(id) ON DELETE CASCADE,
    tax_period_id INTEGER REFERENCES tax_periods(id),
    
    -- Invoice Type
    invoice_type VARCHAR(20) NOT NULL CHECK (invoice_type IN ('sales', 'purchases')),
    
    -- Extracted Data
    invoice_number VARCHAR(100),
    invoice_date DATE,
    counterparty_name VARCHAR(255),
    counterparty_vat VARCHAR(50),
    description TEXT,
    
    -- Amounts
    amount_exclusive DECIMAL(15,3),
    vat_amount DECIMAL(15,3),
    amount_inclusive DECIMAL(15,3),
    
    -- Tax Classification
    tax_type_id INTEGER REFERENCES tax_types(id),
    
    -- File Information
    original_filename VARCHAR(255),
    stored_filename VARCHAR(255),
    file_path TEXT,
    file_size INTEGER,
    mime_type VARCHAR(100),
    
    -- OCR & AI Processing
    ocr_text TEXT,
    ai_extracted_data JSONB,
    confidence_score DECIMAL(5,2),
    
    -- Status & Review
    status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'processing', 'review', 'approved', 'rejected')),
    review_notes TEXT,
    
    -- Timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    uploaded_by INTEGER REFERENCES users(id),
    reviewed_by INTEGER REFERENCES users(id),
    reviewed_at TIMESTAMP,
    approved_by INTEGER REFERENCES users(id),
    approved_at TIMESTAMP
);

-- =====================================================
-- 6. VAT REPORTS
-- =====================================================

CREATE TABLE IF NOT EXISTS vat_reports (
    id SERIAL PRIMARY KEY,
    uuid UUID DEFAULT uuid_generate_v4() UNIQUE,
    client_id INTEGER REFERENCES clients(id) ON DELETE CASCADE,
    tax_period_id INTEGER REFERENCES tax_periods(id),
    
    -- Report Info
    report_name VARCHAR(255),
    year INTEGER NOT NULL,
    quarter INTEGER NOT NULL,
    
    -- Sales Summary
    total_sales_exclusive DECIMAL(15,3) DEFAULT 0,
    total_sales_vat DECIMAL(15,3) DEFAULT 0,
    total_sales_inclusive DECIMAL(15,3) DEFAULT 0,
    
    -- Purchases Summary
    total_purchases_exclusive DECIMAL(15,3) DEFAULT 0,
    total_purchases_vat DECIMAL(15,3) DEFAULT 0,
    total_purchases_inclusive DECIMAL(15,3) DEFAULT 0,
    
    -- Net VAT
    net_vat DECIMAL(15,3) DEFAULT 0,
    
    -- Status
    status VARCHAR(20) DEFAULT 'draft' CHECK (status IN ('draft', 'pending_review', 'approved', 'exported', 'submitted')),
    
    -- Files
    excel_file_path TEXT,
    pdf_file_path TEXT,
    
    -- Timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by INTEGER REFERENCES users(id),
    reviewed_by INTEGER REFERENCES users(id),
    reviewed_at TIMESTAMP,
    approved_by INTEGER REFERENCES users(id),
    approved_at TIMESTAMP,
    exported_at TIMESTAMP
);

-- =====================================================
-- 7. ACTIVITY LOGS
-- =====================================================

CREATE TABLE IF NOT EXISTS activity_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    action VARCHAR(100) NOT NULL,
    entity_type VARCHAR(50),
    entity_id INTEGER,
    details JSONB,
    ip_address VARCHAR(45),
    user_agent TEXT,
    status VARCHAR(20) DEFAULT 'success' CHECK (status IN ('success', 'failed', 'error')),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create index for faster queries
CREATE INDEX IF NOT EXISTS idx_activity_logs_user ON activity_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_activity_logs_created ON activity_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_activity_logs_action ON activity_logs(action);

-- =====================================================
-- 8. SYSTEM SETTINGS
-- =====================================================

CREATE TABLE IF NOT EXISTS system_settings (
    id SERIAL PRIMARY KEY,
    key VARCHAR(100) UNIQUE NOT NULL,
    value TEXT,
    description TEXT,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_by INTEGER REFERENCES users(id)
);

-- Insert default settings
INSERT INTO system_settings (key, value, description) VALUES
    ('ollama_url', 'http://192.168.1.225:11434', 'Ollama AI Server URL'),
    ('ollama_model', 'llama3.2:latest', 'Ollama Model Name'),
    ('ollama_timeout', '60', 'Ollama Request Timeout (seconds)'),
    ('paperless_url', 'http://paperless:8000', 'Paperless-ngx URL'),
    ('paperless_token', '', 'Paperless-ngx API Token'),
    ('storage_path', '/app/storage', 'Document Storage Path'),
    ('max_file_size', '10485760', 'Maximum File Size (bytes)'),
    ('allowed_extensions', 'pdf,jpg,jpeg,png', 'Allowed File Extensions'),
    ('default_currency', 'BHD', 'Default Currency'),
    ('company_name', 'VAT Tax System', 'Company Name'),
    ('log_retention_days', '180', 'Activity Log Retention Days')
ON CONFLICT (key) DO NOTHING;

-- =====================================================
-- 9. USER SESSIONS (for monitoring)
-- =====================================================

CREATE TABLE IF NOT EXISTS user_sessions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    session_token VARCHAR(255) UNIQUE,
    ip_address VARCHAR(45),
    user_agent TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP
);

-- =====================================================
-- 10. USER PERFORMANCE METRICS
-- =====================================================

CREATE TABLE IF NOT EXISTS user_metrics (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    date DATE NOT NULL,
    invoices_uploaded INTEGER DEFAULT 0,
    invoices_reviewed INTEGER DEFAULT 0,
    invoices_approved INTEGER DEFAULT 0,
    reports_generated INTEGER DEFAULT 0,
    reports_approved INTEGER DEFAULT 0,
    login_count INTEGER DEFAULT 0,
    active_minutes INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, date)
);

-- =====================================================
-- 11. SYSTEM HEALTH LOGS
-- =====================================================

CREATE TABLE IF NOT EXISTS system_health (
    id SERIAL PRIMARY KEY,
    service_name VARCHAR(50) NOT NULL,
    status VARCHAR(20) NOT NULL CHECK (status IN ('healthy', 'degraded', 'down', 'unknown')),
    response_time_ms INTEGER,
    details JSONB,
    checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- =====================================================
-- TRIGGERS
-- =====================================================

-- Update timestamp trigger function
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Apply trigger to tables
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_clients_updated_at BEFORE UPDATE ON clients
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_invoices_updated_at BEFORE UPDATE ON invoices
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_vat_reports_updated_at BEFORE UPDATE ON vat_reports
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_tax_periods_updated_at BEFORE UPDATE ON tax_periods
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_tax_types_updated_at BEFORE UPDATE ON tax_types
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- =====================================================
-- VIEWS
-- =====================================================

-- User activity summary view
CREATE OR REPLACE VIEW user_activity_summary AS
SELECT 
    u.id,
    u.username,
    u.full_name,
    r.name as role,
    u.last_login,
    u.last_activity,
    u.is_active,
    COALESCE(SUM(um.invoices_uploaded), 0) as total_invoices_uploaded,
    COALESCE(SUM(um.invoices_approved), 0) as total_invoices_approved,
    COALESCE(SUM(um.reports_generated), 0) as total_reports_generated
FROM users u
LEFT JOIN roles r ON u.role_id = r.id
LEFT JOIN user_metrics um ON u.id = um.user_id
GROUP BY u.id, u.username, u.full_name, r.name, u.last_login, u.last_activity, u.is_active;

-- Client summary view
CREATE OR REPLACE VIEW client_summary AS
SELECT 
    c.id,
    c.name,
    c.vat_number,
    c.is_active,
    COUNT(DISTINCT i.id) as total_invoices,
    COUNT(DISTINCT CASE WHEN i.status = 'approved' THEN i.id END) as approved_invoices,
    COUNT(DISTINCT vr.id) as total_reports,
    MAX(i.created_at) as last_invoice_date
FROM clients c
LEFT JOIN invoices i ON c.id = i.client_id
LEFT JOIN vat_reports vr ON c.id = vr.client_id
GROUP BY c.id, c.name, c.vat_number, c.is_active;

-- =====================================================
-- END OF SCHEMA
-- =====================================================
