-- =====================================================
-- Initialize Default Admin User
-- Password: admin123
-- =====================================================

-- Delete existing admin if exists
DELETE FROM users WHERE username = 'admin';

-- Insert new admin with correct password hash
-- Password: admin123
-- Hash generated with bcrypt
INSERT INTO users (username, email, password_hash, full_name, role_id, is_active, is_locked, failed_login_attempts)
VALUES (
    'admin',
    'admin@vatsystem.local',
    '$2b$12$ozMg6Phmcn3giQ8ozk5x.unOIXtoNQO81H.P3x1ZQiAJmloIeBfH.',
    'System Administrator',
    1,
    TRUE,
    FALSE,
    0
);

-- Verify
SELECT id, username, email, is_active, is_locked FROM users WHERE username = 'admin';
