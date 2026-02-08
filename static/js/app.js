/* =====================================================
   VAT Tax System v3.0.0 - Main Application JavaScript
   ===================================================== */

// API Base URL
const API_BASE = '/api';

// Global State
let currentUser = null;
let selectedFiles = [];

// =====================================================
// INITIALIZATION
// =====================================================

document.addEventListener('DOMContentLoaded', () => {
    // Check if user is logged in
    const token = localStorage.getItem('token');
    if (token) {
        validateToken(token);
    } else {
        showLoginPage();
    }

    // Setup event listeners
    setupEventListeners();
});

function setupEventListeners() {
    // Login form
    document.getElementById('login-form').addEventListener('submit', handleLogin);

    // Logout button
    document.getElementById('logout-btn').addEventListener('click', handleLogout);

    // Sidebar navigation
    document.querySelectorAll('.sidebar-menu li').forEach(item => {
        item.addEventListener('click', () => {
            const page = item.dataset.page;
            navigateTo(page);
        });
    });

    // File upload
    setupFileUpload();
}

// =====================================================
// AUTHENTICATION
// =====================================================

async function handleLogin(e) {
    e.preventDefault();
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;

    try {
        const response = await fetch(`${API_BASE}/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });

        const data = await response.json();

        if (response.ok) {
            localStorage.setItem('token', data.token);
            currentUser = data.user;
            showMainApp();
            showToast('Login successful!', 'success');
        } else {
            showToast(data.error || 'Login failed', 'error');
        }
    } catch (error) {
        showToast('Connection error', 'error');
    }
}

async function validateToken(token) {
    try {
        const response = await fetch(`${API_BASE}/auth/validate`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });

        if (response.ok) {
            const data = await response.json();
            currentUser = data.user;
            showMainApp();
        } else {
            localStorage.removeItem('token');
            showLoginPage();
        }
    } catch (error) {
        showLoginPage();
    }
}

function handleLogout() {
    localStorage.removeItem('token');
    currentUser = null;
    showLoginPage();
    showToast('Logged out successfully', 'info');
}

function getAuthHeaders() {
    const token = localStorage.getItem('token');
    return {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
    };
}

// =====================================================
// PAGE NAVIGATION
// =====================================================

function showLoginPage() {
    document.getElementById('login-page').classList.add('active');
    document.getElementById('main-app').classList.remove('active');
}

function showMainApp() {
    document.getElementById('login-page').classList.remove('active');
    document.getElementById('main-app').classList.add('active');
    
    // Update user info
    document.getElementById('current-user').textContent = currentUser?.full_name || currentUser?.username || 'User';
    
    // Show admin menu items if admin
    if (currentUser?.role === 'admin') {
        document.body.classList.add('is-admin');
    } else {
        document.body.classList.remove('is-admin');
    }

    // Load dashboard
    navigateTo('dashboard');
}

function navigateTo(page) {
    // Update sidebar
    document.querySelectorAll('.sidebar-menu li').forEach(item => {
        item.classList.toggle('active', item.dataset.page === page);
    });

    // Update content pages
    document.querySelectorAll('.content-page').forEach(p => {
        p.classList.toggle('active', p.id === `page-${page}`);
    });

    // Load page data
    switch (page) {
        case 'dashboard':
            loadDashboard();
            break;
        case 'clients':
            loadClients();
            break;
        case 'invoices':
            loadInvoices();
            break;
        case 'upload':
            loadUploadPage();
            break;
        case 'review':
            loadReviewQueue();
            break;
        case 'reports':
            loadReports();
            break;
        case 'users':
            loadUsers();
            break;
        case 'monitoring':
            loadMonitoring();
            break;
        case 'settings':
            loadSettings();
            break;
    }
}

// =====================================================
// DASHBOARD
// =====================================================

async function loadDashboard() {
    try {
        const response = await fetch(`${API_BASE}/dashboard/stats`, {
            headers: getAuthHeaders()
        });
        const data = await response.json();

        document.getElementById('stat-clients').textContent = data.total_clients || 0;
        document.getElementById('stat-pending').textContent = data.pending_invoices || 0;
        document.getElementById('stat-review').textContent = data.review_invoices || 0;
        document.getElementById('stat-approved').textContent = data.approved_invoices || 0;

        // Load recent invoices
        loadRecentInvoices();
        loadRecentReports();
    } catch (error) {
        console.error('Error loading dashboard:', error);
    }
}

async function loadRecentInvoices() {
    try {
        const response = await fetch(`${API_BASE}/invoices?limit=5`, {
            headers: getAuthHeaders()
        });
        const data = await response.json();
        
        const tbody = document.querySelector('#recent-invoices-table tbody');
        tbody.innerHTML = data.invoices?.map(inv => `
            <tr>
                <td>${inv.invoice_number || '-'}</td>
                <td>${inv.client_name || '-'}</td>
                <td>${inv.invoice_type || '-'}</td>
                <td><span class="status-badge ${inv.status}">${inv.status}</span></td>
                <td>${formatDate(inv.invoice_date)}</td>
            </tr>
        `).join('') || '<tr><td colspan="5" class="empty-state">No invoices yet</td></tr>';
    } catch (error) {
        console.error('Error loading recent invoices:', error);
    }
}

async function loadRecentReports() {
    try {
        const response = await fetch(`${API_BASE}/reports?limit=5`, {
            headers: getAuthHeaders()
        });
        const data = await response.json();
        
        const tbody = document.querySelector('#recent-reports-table tbody');
        tbody.innerHTML = data.reports?.map(rep => `
            <tr>
                <td>${rep.report_name || '-'}</td>
                <td>${rep.client_name || '-'}</td>
                <td>${rep.period || '-'}</td>
                <td><span class="status-badge ${rep.status}">${rep.status}</span></td>
            </tr>
        `).join('') || '<tr><td colspan="4" class="empty-state">No reports yet</td></tr>';
    } catch (error) {
        console.error('Error loading recent reports:', error);
    }
}

// =====================================================
// CLIENTS
// =====================================================

async function loadClients() {
    try {
        const response = await fetch(`${API_BASE}/clients`, {
            headers: getAuthHeaders()
        });
        const data = await response.json();
        
        const tbody = document.querySelector('#clients-table tbody');
        tbody.innerHTML = data.clients?.map(client => `
            <tr>
                <td>${client.name}</td>
                <td>${client.vat_number || '-'}</td>
                <td>${client.cr_number || '-'}</td>
                <td>${client.invoice_count || 0}</td>
                <td>${client.report_count || 0}</td>
                <td class="action-btns">
                    <button class="btn btn-sm btn-secondary" onclick="viewClient(${client.id})">
                        <i class="fas fa-eye"></i>
                    </button>
                    <button class="btn btn-sm btn-secondary" onclick="editClient(${client.id})">
                        <i class="fas fa-edit"></i>
                    </button>
                    <button class="btn btn-sm btn-danger" onclick="deleteClient(${client.id})">
                        <i class="fas fa-trash"></i>
                    </button>
                </td>
            </tr>
        `).join('') || '<tr><td colspan="6" class="empty-state">No clients yet</td></tr>';
    } catch (error) {
        console.error('Error loading clients:', error);
        showToast('Error loading clients', 'error');
    }
}

function showAddClientModal() {
    const content = `
        <form id="add-client-form">
            <div class="form-group">
                <label>Company Name *</label>
                <input type="text" name="name" class="form-control" required>
            </div>
            <div class="form-row">
                <div class="form-group">
                    <label>VAT Number *</label>
                    <input type="text" name="vat_number" class="form-control" required placeholder="BH100000000000">
                </div>
                <div class="form-group">
                    <label>CR Number</label>
                    <input type="text" name="cr_number" class="form-control" placeholder="CR-12345">
                </div>
            </div>
            <div class="form-group">
                <label>Email</label>
                <input type="email" name="email" class="form-control">
            </div>
            <div class="form-group">
                <label>Phone</label>
                <input type="text" name="phone" class="form-control">
            </div>
            <div class="form-group">
                <label>Address</label>
                <textarea name="address" class="form-control" rows="2"></textarea>
            </div>
            <div class="form-row">
                <button type="button" class="btn btn-secondary" onclick="closeModal()">Cancel</button>
                <button type="submit" class="btn btn-primary">Add Client</button>
            </div>
        </form>
    `;
    
    showModal('Add New Client', content);
    
    document.getElementById('add-client-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const formData = new FormData(e.target);
        const clientData = Object.fromEntries(formData);
        
        try {
            const response = await fetch(`${API_BASE}/clients`, {
                method: 'POST',
                headers: getAuthHeaders(),
                body: JSON.stringify(clientData)
            });
            
            if (response.ok) {
                showToast('Client added successfully', 'success');
                closeModal();
                loadClients();
            } else {
                const data = await response.json();
                showToast(data.error || 'Error adding client', 'error');
            }
        } catch (error) {
            showToast('Connection error', 'error');
        }
    });
}

async function deleteClient(id) {
    if (!confirm('Are you sure you want to delete this client?')) return;
    
    try {
        const response = await fetch(`${API_BASE}/clients/${id}`, {
            method: 'DELETE',
            headers: getAuthHeaders()
        });
        
        if (response.ok) {
            showToast('Client deleted successfully', 'success');
            loadClients();
        } else {
            showToast('Error deleting client', 'error');
        }
    } catch (error) {
        showToast('Connection error', 'error');
    }
}

// =====================================================
// INVOICES
// =====================================================

async function loadInvoices() {
    // Load clients for filter
    await loadClientFilter('filter-client');
    
    const clientId = document.getElementById('filter-client').value;
    const type = document.getElementById('filter-type').value;
    const status = document.getElementById('filter-status').value;
    
    let url = `${API_BASE}/invoices?`;
    if (clientId) url += `client_id=${clientId}&`;
    if (type) url += `type=${type}&`;
    if (status) url += `status=${status}&`;
    
    try {
        const response = await fetch(url, {
            headers: getAuthHeaders()
        });
        const data = await response.json();
        
        const tbody = document.querySelector('#invoices-table tbody');
        tbody.innerHTML = data.invoices?.map(inv => `
            <tr>
                <td>${inv.invoice_number || '-'}</td>
                <td>${inv.client_name || '-'}</td>
                <td>${inv.invoice_type || '-'}</td>
                <td>${formatDate(inv.invoice_date)}</td>
                <td>${formatCurrency(inv.total_amount)}</td>
                <td>${formatCurrency(inv.vat_amount)}</td>
                <td>${renderConfidence(inv.confidence_score)}</td>
                <td><span class="status-badge ${inv.status}">${inv.status}</span></td>
                <td class="action-btns">
                    <button class="btn btn-sm btn-secondary" onclick="viewInvoice(${inv.id})">
                        <i class="fas fa-eye"></i>
                    </button>
                </td>
            </tr>
        `).join('') || '<tr><td colspan="9" class="empty-state">No invoices found</td></tr>';
    } catch (error) {
        console.error('Error loading invoices:', error);
    }
}

// =====================================================
// FILE UPLOAD
// =====================================================

function setupFileUpload() {
    const dropZone = document.getElementById('drop-zone');
    const fileInput = document.getElementById('file-input');
    const uploadBtn = document.getElementById('upload-btn');

    // Click to browse
    dropZone.addEventListener('click', () => fileInput.click());

    // Drag and drop
    dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.classList.add('dragover');
    });

    dropZone.addEventListener('dragleave', () => {
        dropZone.classList.remove('dragover');
    });

    dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZone.classList.remove('dragover');
        handleFiles(e.dataTransfer.files);
    });

    // File input change
    fileInput.addEventListener('change', (e) => {
        handleFiles(e.target.files);
    });

    // Upload button
    uploadBtn.addEventListener('click', uploadFiles);
}

function handleFiles(files) {
    const allowedTypes = ['application/pdf', 'image/jpeg', 'image/png'];
    
    for (const file of files) {
        if (allowedTypes.includes(file.type)) {
            selectedFiles.push(file);
        } else {
            showToast(`Invalid file type: ${file.name}`, 'warning');
        }
    }
    
    updateUploadPreview();
}

function updateUploadPreview() {
    const preview = document.getElementById('upload-preview');
    const uploadBtn = document.getElementById('upload-btn');
    
    preview.innerHTML = selectedFiles.map((file, index) => `
        <div class="file-item">
            <i class="fas fa-file-${file.type === 'application/pdf' ? 'pdf' : 'image'}"></i>
            <span class="file-name">${file.name}</span>
            <span class="file-size">${formatFileSize(file.size)}</span>
            <i class="fas fa-times remove-file" onclick="removeFile(${index})"></i>
        </div>
    `).join('');
    
    uploadBtn.disabled = selectedFiles.length === 0;
}

function removeFile(index) {
    selectedFiles.splice(index, 1);
    updateUploadPreview();
}

async function uploadFiles() {
    const clientId = document.getElementById('upload-client').value;
    const type = document.getElementById('upload-type').value;
    const year = document.getElementById('upload-year').value;
    const month = document.getElementById('upload-month').value;
    
    if (!clientId) {
        showToast('Please select a client', 'warning');
        return;
    }
    
    const formData = new FormData();
    formData.append('client_id', clientId);
    formData.append('invoice_type', type);
    formData.append('year', year);
    formData.append('month', month);
    
    selectedFiles.forEach(file => {
        formData.append('files', file);
    });
    
    try {
        const token = localStorage.getItem('token');
        const response = await fetch(`${API_BASE}/invoices/upload`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${token}` },
            body: formData
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showToast(`${data.processed} files uploaded successfully`, 'success');
            selectedFiles = [];
            updateUploadPreview();
            navigateTo('review');
        } else {
            showToast(data.error || 'Upload failed', 'error');
        }
    } catch (error) {
        showToast('Connection error', 'error');
    }
}

async function loadUploadPage() {
    await loadClientFilter('upload-client');
}

// =====================================================
// REVIEW QUEUE
// =====================================================

async function loadReviewQueue() {
    try {
        const response = await fetch(`${API_BASE}/invoices?status=review`, {
            headers: getAuthHeaders()
        });
        const data = await response.json();
        
        const tbody = document.querySelector('#review-table tbody');
        tbody.innerHTML = data.invoices?.map(inv => `
            <tr>
                <td>${inv.invoice_number || '-'}</td>
                <td>${inv.client_name || '-'}</td>
                <td>${inv.invoice_type || '-'}</td>
                <td>${inv.counterparty_name || '-'}</td>
                <td>${formatCurrency(inv.total_amount)}</td>
                <td>${formatCurrency(inv.vat_amount)}</td>
                <td>${renderConfidence(inv.confidence_score)}</td>
                <td class="action-btns">
                    <button class="btn btn-sm btn-secondary" onclick="reviewInvoice(${inv.id})">
                        <i class="fas fa-search"></i> Review
                    </button>
                    <button class="btn btn-sm btn-success" onclick="approveInvoice(${inv.id})">
                        <i class="fas fa-check"></i>
                    </button>
                    <button class="btn btn-sm btn-danger" onclick="rejectInvoice(${inv.id})">
                        <i class="fas fa-times"></i>
                    </button>
                </td>
            </tr>
        `).join('') || '<tr><td colspan="8" class="empty-state">No invoices pending review</td></tr>';
    } catch (error) {
        console.error('Error loading review queue:', error);
    }
}

async function approveInvoice(id) {
    try {
        const response = await fetch(`${API_BASE}/invoices/${id}/approve`, {
            method: 'POST',
            headers: getAuthHeaders()
        });
        
        if (response.ok) {
            showToast('Invoice approved', 'success');
            loadReviewQueue();
        } else {
            showToast('Error approving invoice', 'error');
        }
    } catch (error) {
        showToast('Connection error', 'error');
    }
}

async function rejectInvoice(id) {
    const reason = prompt('Enter rejection reason:');
    if (!reason) return;
    
    try {
        const response = await fetch(`${API_BASE}/invoices/${id}/reject`, {
            method: 'POST',
            headers: getAuthHeaders(),
            body: JSON.stringify({ reason })
        });
        
        if (response.ok) {
            showToast('Invoice rejected', 'success');
            loadReviewQueue();
        } else {
            showToast('Error rejecting invoice', 'error');
        }
    } catch (error) {
        showToast('Connection error', 'error');
    }
}

// =====================================================
// REPORTS
// =====================================================

async function loadReports() {
    try {
        const response = await fetch(`${API_BASE}/reports`, {
            headers: getAuthHeaders()
        });
        const data = await response.json();
        
        const tbody = document.querySelector('#reports-table tbody');
        tbody.innerHTML = data.reports?.map(rep => `
            <tr>
                <td>${rep.report_name || '-'}</td>
                <td>${rep.client_name || '-'}</td>
                <td>${rep.period || '-'}</td>
                <td>${formatCurrency(rep.sales_vat)}</td>
                <td>${formatCurrency(rep.purchases_vat)}</td>
                <td>${formatCurrency(rep.net_vat)}</td>
                <td><span class="status-badge ${rep.status}">${rep.status}</span></td>
                <td class="action-btns">
                    <button class="btn btn-sm btn-secondary" onclick="downloadReport(${rep.id}, 'excel')">
                        <i class="fas fa-file-excel"></i>
                    </button>
                    <button class="btn btn-sm btn-secondary" onclick="downloadReport(${rep.id}, 'pdf')">
                        <i class="fas fa-file-pdf"></i>
                    </button>
                </td>
            </tr>
        `).join('') || '<tr><td colspan="8" class="empty-state">No reports generated yet</td></tr>';
    } catch (error) {
        console.error('Error loading reports:', error);
    }
}

function showGenerateReportModal() {
    const content = `
        <form id="generate-report-form">
            <div class="form-group">
                <label>Client *</label>
                <select name="client_id" id="report-client" class="form-control" required>
                    <option value="">Select Client</option>
                </select>
            </div>
            <div class="form-row">
                <div class="form-group">
                    <label>Year *</label>
                    <select name="year" class="form-control" required>
                        <option value="2026">2026</option>
                        <option value="2025">2025</option>
                        <option value="2024">2024</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>Quarter *</label>
                    <select name="quarter" class="form-control" required>
                        <option value="1">Q1 (Jan-Mar)</option>
                        <option value="2">Q2 (Apr-Jun)</option>
                        <option value="3">Q3 (Jul-Sep)</option>
                        <option value="4">Q4 (Oct-Dec)</option>
                    </select>
                </div>
            </div>
            <div class="form-row">
                <button type="button" class="btn btn-secondary" onclick="closeModal()">Cancel</button>
                <button type="submit" class="btn btn-primary">Generate Report</button>
            </div>
        </form>
    `;
    
    showModal('Generate VAT Report', content);
    loadClientFilter('report-client');
    
    document.getElementById('generate-report-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const formData = new FormData(e.target);
        const reportData = Object.fromEntries(formData);
        
        try {
            const response = await fetch(`${API_BASE}/reports/generate`, {
                method: 'POST',
                headers: getAuthHeaders(),
                body: JSON.stringify(reportData)
            });
            
            if (response.ok) {
                showToast('Report generated successfully', 'success');
                closeModal();
                loadReports();
            } else {
                const data = await response.json();
                showToast(data.error || 'Error generating report', 'error');
            }
        } catch (error) {
            showToast('Connection error', 'error');
        }
    });
}

async function downloadReport(id, format) {
    try {
        const response = await fetch(`${API_BASE}/reports/${id}/download?format=${format}`, {
            headers: getAuthHeaders()
        });
        
        if (response.ok) {
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `report_${id}.${format === 'excel' ? 'xlsx' : 'pdf'}`;
            a.click();
            window.URL.revokeObjectURL(url);
        } else {
            showToast('Error downloading report', 'error');
        }
    } catch (error) {
        showToast('Connection error', 'error');
    }
}

// =====================================================
// USERS
// =====================================================

async function loadUsers() {
    try {
        const response = await fetch(`${API_BASE}/users`, {
            headers: getAuthHeaders()
        });
        const data = await response.json();
        
        const tbody = document.querySelector('#users-table tbody');
        tbody.innerHTML = data.users?.map(user => `
            <tr>
                <td>${user.username}</td>
                <td>${user.full_name || '-'}</td>
                <td>${user.email || '-'}</td>
                <td>${user.role}</td>
                <td>${formatDateTime(user.last_login)}</td>
                <td><span class="status-badge ${user.is_active ? 'active' : 'inactive'}">${user.is_active ? 'Active' : 'Inactive'}</span></td>
                <td class="action-btns">
                    <button class="btn btn-sm btn-secondary" onclick="editUser(${user.id})">
                        <i class="fas fa-edit"></i>
                    </button>
                    <button class="btn btn-sm btn-danger" onclick="deleteUser(${user.id})" ${user.role === 'admin' ? 'disabled' : ''}>
                        <i class="fas fa-trash"></i>
                    </button>
                </td>
            </tr>
        `).join('') || '<tr><td colspan="7" class="empty-state">No users found</td></tr>';
    } catch (error) {
        console.error('Error loading users:', error);
    }
}

function showAddUserModal() {
    const content = `
        <form id="add-user-form">
            <div class="form-row">
                <div class="form-group">
                    <label>Username *</label>
                    <input type="text" name="username" class="form-control" required>
                </div>
                <div class="form-group">
                    <label>Full Name</label>
                    <input type="text" name="full_name" class="form-control">
                </div>
            </div>
            <div class="form-group">
                <label>Email</label>
                <input type="email" name="email" class="form-control">
            </div>
            <div class="form-row">
                <div class="form-group">
                    <label>Password *</label>
                    <input type="password" name="password" class="form-control" required>
                </div>
                <div class="form-group">
                    <label>Role *</label>
                    <select name="role" class="form-control" required>
                        <option value="user">User</option>
                        <option value="reviewer">Reviewer</option>
                        <option value="admin">Admin</option>
                    </select>
                </div>
            </div>
            <div class="form-row">
                <button type="button" class="btn btn-secondary" onclick="closeModal()">Cancel</button>
                <button type="submit" class="btn btn-primary">Add User</button>
            </div>
        </form>
    `;
    
    showModal('Add New User', content);
    
    document.getElementById('add-user-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const formData = new FormData(e.target);
        const userData = Object.fromEntries(formData);
        
        try {
            const response = await fetch(`${API_BASE}/users`, {
                method: 'POST',
                headers: getAuthHeaders(),
                body: JSON.stringify(userData)
            });
            
            if (response.ok) {
                showToast('User added successfully', 'success');
                closeModal();
                loadUsers();
            } else {
                const data = await response.json();
                showToast(data.error || 'Error adding user', 'error');
            }
        } catch (error) {
            showToast('Connection error', 'error');
        }
    });
}

// =====================================================
// MONITORING
// =====================================================

async function loadMonitoring() {
    // Load system resources
    try {
        const response = await fetch(`${API_BASE}/monitoring/system`, {
            headers: getAuthHeaders()
        });
        const data = await response.json();
        
        updateResourceBar('cpu', data.cpu_percent || 0);
        updateResourceBar('memory', data.memory_percent || 0);
        updateResourceBar('disk', data.disk_percent || 0);
        
        // Update service status
        document.getElementById('db-status').className = `status-badge ${data.database_status === 'online' ? 'online' : 'offline'}`;
        document.getElementById('db-status').textContent = data.database_status || 'Unknown';
        
        document.getElementById('ollama-status').className = `status-badge ${data.ollama_status === 'online' ? 'online' : 'offline'}`;
        document.getElementById('ollama-status').textContent = data.ollama_status || 'Unknown';
    } catch (error) {
        console.error('Error loading monitoring:', error);
    }
    
    // Load active users
    loadActiveUsers();
    loadUserMetrics();
}

function updateResourceBar(resource, value) {
    document.getElementById(`${resource}-bar`).style.width = `${value}%`;
    document.getElementById(`${resource}-value`).textContent = `${value}%`;
}

async function loadActiveUsers() {
    try {
        const response = await fetch(`${API_BASE}/monitoring/active-users`, {
            headers: getAuthHeaders()
        });
        const data = await response.json();
        
        const tbody = document.querySelector('#active-users-table tbody');
        tbody.innerHTML = data.users?.map(user => `
            <tr>
                <td>${user.username}</td>
                <td>${user.role}</td>
                <td>${formatDateTime(user.last_activity)}</td>
                <td>${user.actions_today || 0}</td>
            </tr>
        `).join('') || '<tr><td colspan="4" class="empty-state">No active users</td></tr>';
    } catch (error) {
        console.error('Error loading active users:', error);
    }
}

async function loadUserMetrics() {
    try {
        const response = await fetch(`${API_BASE}/monitoring/user-metrics`, {
            headers: getAuthHeaders()
        });
        const data = await response.json();
        
        const tbody = document.querySelector('#user-metrics-table tbody');
        tbody.innerHTML = data.metrics?.map(m => `
            <tr>
                <td>${m.username}</td>
                <td>${m.invoices_uploaded || 0}</td>
                <td>${m.invoices_approved || 0}</td>
                <td>${m.reports_generated || 0}</td>
            </tr>
        `).join('') || '<tr><td colspan="4" class="empty-state">No data available</td></tr>';
    } catch (error) {
        console.error('Error loading user metrics:', error);
    }
}

// =====================================================
// SETTINGS
// =====================================================

async function loadSettings() {
    // Load Ollama settings
    try {
        const response = await fetch(`${API_BASE}/settings/ollama`, {
            headers: getAuthHeaders()
        });
        const data = await response.json();
        
        document.getElementById('setting-ollama-url').value = data.url || '';
        document.getElementById('setting-ollama-model').value = data.model || 'llama3.2:latest';
        document.getElementById('setting-ollama-timeout').value = data.timeout || 60;
    } catch (error) {
        console.error('Error loading settings:', error);
    }
    
    // Load tax types
    loadTaxTypes();
}

async function loadTaxTypes() {
    try {
        const response = await fetch(`${API_BASE}/settings/tax-types`, {
            headers: getAuthHeaders()
        });
        const data = await response.json();
        
        const tbody = document.querySelector('#tax-types-table tbody');
        tbody.innerHTML = data.tax_types?.map(tax => `
            <tr>
                <td>${tax.code}</td>
                <td>${tax.name}</td>
                <td>${tax.rate}%</td>
                <td>${tax.nbr_field || '-'}</td>
            </tr>
        `).join('') || '<tr><td colspan="4" class="empty-state">No tax types configured</td></tr>';
    } catch (error) {
        console.error('Error loading tax types:', error);
    }
}

async function testOllamaConnection() {
    const url = document.getElementById('setting-ollama-url').value;
    const resultDiv = document.getElementById('ollama-test-result');
    
    try {
        const response = await fetch(`${API_BASE}/settings/ollama/test`, {
            method: 'POST',
            headers: getAuthHeaders(),
            body: JSON.stringify({ url })
        });
        
        const data = await response.json();
        
        if (response.ok && data.success) {
            resultDiv.className = 'test-result success';
            resultDiv.innerHTML = `<i class="fas fa-check-circle"></i> Connection successful! Models: ${data.models?.join(', ') || 'None'}`;
        } else {
            resultDiv.className = 'test-result error';
            resultDiv.innerHTML = `<i class="fas fa-times-circle"></i> Connection failed: ${data.error || 'Unknown error'}`;
        }
    } catch (error) {
        resultDiv.className = 'test-result error';
        resultDiv.innerHTML = `<i class="fas fa-times-circle"></i> Connection error`;
    }
}

async function saveOllamaSettings() {
    const settings = {
        url: document.getElementById('setting-ollama-url').value,
        model: document.getElementById('setting-ollama-model').value,
        timeout: parseInt(document.getElementById('setting-ollama-timeout').value)
    };
    
    try {
        const response = await fetch(`${API_BASE}/settings/ollama`, {
            method: 'POST',
            headers: getAuthHeaders(),
            body: JSON.stringify(settings)
        });
        
        if (response.ok) {
            showToast('Settings saved successfully', 'success');
        } else {
            showToast('Error saving settings', 'error');
        }
    } catch (error) {
        showToast('Connection error', 'error');
    }
}

// =====================================================
// UTILITY FUNCTIONS
// =====================================================

async function loadClientFilter(selectId) {
    try {
        const response = await fetch(`${API_BASE}/clients`, {
            headers: getAuthHeaders()
        });
        const data = await response.json();
        
        const select = document.getElementById(selectId);
        const currentValue = select.value;
        
        // Keep the first option
        const firstOption = select.options[0];
        select.innerHTML = '';
        select.appendChild(firstOption);
        
        data.clients?.forEach(client => {
            const option = document.createElement('option');
            option.value = client.id;
            option.textContent = client.name;
            select.appendChild(option);
        });
        
        select.value = currentValue;
    } catch (error) {
        console.error('Error loading clients:', error);
    }
}

function formatDate(dateStr) {
    if (!dateStr) return '-';
    return new Date(dateStr).toLocaleDateString();
}

function formatDateTime(dateStr) {
    if (!dateStr) return '-';
    return new Date(dateStr).toLocaleString();
}

function formatCurrency(amount) {
    if (amount === null || amount === undefined) return '-';
    return new Intl.NumberFormat('en-BH', {
        style: 'currency',
        currency: 'BHD'
    }).format(amount);
}

function formatFileSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
}

function renderConfidence(score) {
    if (score === null || score === undefined) return '-';
    const level = score >= 80 ? 'high' : score >= 50 ? 'medium' : 'low';
    return `
        <div class="confidence-bar">
            <div class="fill ${level}" style="width: ${score}%"></div>
        </div>
        ${score}%
    `;
}

// =====================================================
// MODAL FUNCTIONS
// =====================================================

function showModal(title, content) {
    document.getElementById('modal-title').textContent = title;
    document.getElementById('modal-content').innerHTML = content;
    document.getElementById('modal-overlay').classList.add('active');
}

function closeModal() {
    document.getElementById('modal-overlay').classList.remove('active');
}

// Close modal on overlay click
document.getElementById('modal-overlay').addEventListener('click', (e) => {
    if (e.target === e.currentTarget) {
        closeModal();
    }
});

// =====================================================
// TOAST NOTIFICATIONS
// =====================================================

function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    
    const icon = {
        success: 'check-circle',
        error: 'times-circle',
        warning: 'exclamation-triangle',
        info: 'info-circle'
    }[type] || 'info-circle';
    
    toast.innerHTML = `<i class="fas fa-${icon}"></i> ${message}`;
    container.appendChild(toast);
    
    setTimeout(() => {
        toast.remove();
    }, 5000);
}

// =====================================================
// KEYBOARD SHORTCUTS
// =====================================================

document.addEventListener('keydown', (e) => {
    // ESC to close modal
    if (e.key === 'Escape') {
        closeModal();
    }
});
