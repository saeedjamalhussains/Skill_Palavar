const API_URL = 'http://localhost:8000/api/v1';

const titles = {
    customer: 'Personal Banking Hub',
    teller: 'Branch Operations Center',
    branch_head: 'Branch Security Control',
    regional_head: 'Regional Security Console',
    central_head: 'Central Security Command',
    super_admin: 'Global Root Command'
};

const store = {
    token: localStorage.getItem('token'),
    user: null,
    fingerprint: localStorage.getItem('fingerprint') || ('device_' + Math.random().toString(36).substr(2, 9)),
    chart: null,
    tempUsername: null
};

if (!localStorage.getItem('fingerprint')) {
    localStorage.setItem('fingerprint', store.fingerprint);
}

const ui = {
    showSection(id) {
        document.querySelectorAll('.nav-item').forEach(item => item.classList.remove('active'));
        const navItem = document.getElementById(`nav-${id}`);
        if (navItem) navItem.classList.add('active');

        const currentSection = document.querySelector('.view-section.active');
        const nextSection = document.getElementById(`section-${id}`);

        if (currentSection) currentSection.classList.remove('active');
        if (nextSection) nextSection.classList.add('active');

        const names = {
            overview: titles[store.user?.role] || 'System Overview',
            profile: 'Identity Profile',
            transfer: 'Secure Transfer',
            admin: 'Security Command Center',
            threats: 'Insider Threat Monitoring'
        };
        const sectionTitle = document.getElementById('section-title');
        if (sectionTitle) sectionTitle.innerText = names[id] || 'Dashboard';

        if (window.lucide) lucide.createIcons();
    },

    updateTrustBadge(score) {
        const badge = document.getElementById('trust-indicator');
        if (score < 0.2) {
            badge.className = 'trust-badge';
            badge.innerHTML = '<i data-lucide="shield-check"></i> High Trust';
        } else if (score < 0.5) {
            badge.className = 'trust-badge warning';
            badge.innerHTML = '<i data-lucide="shield-alert"></i> Medium Risk';
        } else {
            badge.className = 'trust-badge danger';
            badge.innerHTML = '<i data-lucide="shield-off"></i> High Risk';
        }
        if (window.lucide) lucide.createIcons();
    }
};

const ApiService = {
    async request(endpoint, options = {}) {
        const headers = {
            'Content-Type': 'application/json',
            'X-Device-Fingerprint': store.fingerprint,
            ...options.headers
        };
        if (store.token) {
            headers['Authorization'] = `Bearer ${store.token}`;
        }

        const response = await fetch(`${API_URL}${endpoint}`, { ...options, headers });
        const data = await response.json();
        if (!response.ok) throw new Error(data.detail || 'Request failed');
        return data;
    }
};

const AuthService = {
    async register(payload) {
        return ApiService.request('/auth/register', {
            method: 'POST',
            body: JSON.stringify(payload)
        });
    },

    async login(username, password) {
        return ApiService.request('/auth/login', {
            method: 'POST',
            body: JSON.stringify({ username, password, fingerprint: store.fingerprint })
        });
    },

    async verifyMFA(username, otp) {
        return ApiService.request('/auth/mfa/verify', {
            method: 'POST',
            body: JSON.stringify({ username, otp, fingerprint: store.fingerprint })
        });
    }
};

const UIComponents = {
    renderStatusTag(status) {
        return `<span class="status-tag ${status.toLowerCase()}">${status}</span>`;
    },

    renderLogEntry(log) {
        return `
            <div class="log-entry" style="display: flex; align-items: center; justify-content: space-between; padding: 0.75rem 1rem; background: rgba(255,255,255,0.02); border-radius: 0.75rem; margin-bottom: 0.5rem; border: 1px solid var(--glass-border); font-size: 0.813rem;">
                <div style="display: flex; align-items: center; gap: 0.75rem;">
                    <div style="color: var(--primary); font-family: monospace;">[${log.timestamp.split('T')[1].substr(0, 8)}]</div>
                    <div>
                        <span style="font-weight: 600;">${log.username}</span>: ${log.action} 
                        <span style="color: var(--text-muted);">on ${log.resource}</span>
                    </div>
                </div>
                <div style="color: var(--text-muted); font-size: 0.75rem;">${log.context}</div>
            </div>
        `;
    },

    renderThreatItem(t) {
        const severityColor = t.severity === 'HIGH' ? 'var(--danger)' : 'var(--warning)';
        let icon = 'alert-octagon';
        if (t.type === 'AUTHENTICATION_ANOMALY') icon = 'log-in';
        if (t.type === 'DATA_EXFILTRATION_RISK') icon = 'download-cloud';

        return `
            <div class="transaction-item">
                <div style="display: flex; align-items: center; gap: 1rem; width: 100%;">
                    <div style="width: 32px; height: 32px; background: rgba(0,0,0,0.05); color: ${severityColor}; border-radius: 8px; display: flex; align-items: center; justify-content: center;">
                        <i data-lucide="${icon}" style="width: 16px; height: 16px;"></i>
                    </div>
                    <div style="flex-grow: 1;">
                        <div style="display: flex; justify-content: space-between;">
                            <span style="font-weight: 600; font-size: 0.875rem;">${t.message}</span>
                            <span style="font-size: 0.688rem; color: var(--text-muted);">${new Date(t.timestamp).toLocaleTimeString()}</span>
                        </div>
                        <div style="font-size: 0.75rem; color: var(--text-secondary); margin-top: 0.25rem;">
                            Entity: <b>${t.user}</b> • ID: ${t.id} • Severity: <span style="color: ${severityColor}; font-weight: 700;">${t.severity}</span>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }
};

const DashboardService = {
    async loadProfile() {
        try {
            const user = await ApiService.request('/auth/me');
            store.user = user;
            return user;
        } catch (err) {
            if (err.message.includes('401') || err.message.includes('Unauthorized')) {
                app.logout();
            }
            throw err;
        }
    },

    async loadAccounts() {
        return ApiService.request('/banking/accounts');
    },

    async loadTransactions() {
        return ApiService.request('/banking/transactions');
    },

    async loadAdminStats() {
        return ApiService.request('/admin/dashboard');
    },

    async loadCustomerDirectory() {
        return ApiService.request('/admin/customer-directory');
    },

    async loadThreatIntelligence() {
        return ApiService.request('/admin/threats');
    },

    async updateAccountStatus(accountId, status) {
        return ApiService.request(`/admin/account/${accountId}/status?status_update=${status}`, { method: 'POST' });
    }
};

const app = {
    toggleAuth(view) {
        document.getElementById('auth-error').innerText = '';
        document.getElementById('login-view').style.display = view === 'login' ? 'block' : 'none';
        document.getElementById('signup-view').style.display = view === 'signup' ? 'block' : 'none';
        document.getElementById('mfa-view').style.display = view === 'mfa' ? 'block' : 'none';
        if (window.lucide) lucide.createIcons();
    },

    async register() {
        const payload = {
            email: document.getElementById('signup-email').value,
            username: document.getElementById('signup-username').value,
            password: document.getElementById('signup-password').value,
            role: 'customer',
            special_code: document.getElementById('signup-special-code').value
        };
        try {
            await AuthService.register(payload);
            alert('Identity Created. Proceed to secure sign in.');
            this.toggleAuth('login');
        } catch (err) {
            document.getElementById('auth-error').innerText = err.message;
        }
    },

    async login() {
        const u = document.getElementById('login-username').value;
        const p = document.getElementById('login-password').value;
        try {
            const data = await AuthService.login(u, p);
            if (data.status === 'MFA_REQUIRED') {
                store.tempUsername = data.username;
                if (data.demo_otp_hint) alert(`[SIMULATED SMS] Security Code: ${data.demo_otp_hint}`);
                this.toggleAuth('mfa');
            } else {
                this.handleAuthSuccess(data.access_token);
            }
        } catch (err) {
            document.getElementById('auth-error').innerText = err.message;
        }
    },

    async verifyMFA() {
        const otp = document.getElementById('mfa-code').value;
        try {
            const data = await AuthService.verifyMFA(store.tempUsername, otp);
            this.handleAuthSuccess(data.access_token);
        } catch (err) {
            alert(err.message);
        }
    },

    handleAuthSuccess(token) {
        store.token = token;
        localStorage.setItem('token', token);
        this.showDashboard();
    },

    logout() {
        localStorage.removeItem('token');
        location.reload();
    },

    async showDashboard() {
        document.getElementById('auth-section').style.display = 'none';
        document.getElementById('dashboard').style.display = 'flex';

        try {
            await DashboardService.loadProfile();
            this.setupRoleUI(store.user);

            await Promise.all([
                this.loadAccountingData(),
                this.loadSecurityData()
            ]);

            ui.showSection('overview');
        } catch (err) {
            console.error('Dashboard init failed', err);
        }
    },

    async loadAccountingData() {
        if (!store.user) return;
        const accounts = await DashboardService.loadAccounts();
        if (accounts.length > 0) {
            const acc = accounts[0];
            const bal = document.getElementById('balance-display');
            if (bal) bal.innerText = `₹${acc.balance.toLocaleString('en-IN')}`;

            const statusTag = document.getElementById('account-status-tag');
            if (statusTag) {
                statusTag.innerText = acc.status;
                statusTag.className = `status-tag ${acc.status.toLowerCase()}`;
            }

            if (document.getElementById('display-acc-id')) {
                document.getElementById('display-acc-id').innerText = acc.account_number;
            }
        }

        const txs = await DashboardService.loadTransactions();
        const list = document.getElementById('transactions-list-overview');
        if (list) {
            list.innerHTML = txs.map(tx => `
                <div class="transaction-item">
                    <div style="flex-grow: 1;">
                        <div style="display: flex; justify-content: space-between;">
                            <span style="font-weight: 600;">${tx.to_account?.owner?.username || 'Transfer'}</span>
                            <span style="font-weight: 700; color: var(--danger);">-₹${tx.amount.toLocaleString('en-IN')}</span>
                        </div>
                        <div style="font-size: 0.75rem; color: var(--text-secondary);">${new Date(tx.timestamp).toLocaleDateString()}</div>
                    </div>
                </div>
            `).join('');
        }
    },

    async loadSecurityData() {
        if (store.user.role === 'customer') return;

        const stats = await DashboardService.loadAdminStats();
        document.getElementById('admin-total-users').innerText = stats.total_users;
        document.getElementById('admin-monitored').innerText = stats.monitored_accounts;

        const logsList = document.getElementById('admin-logs-list');
        if (logsList) logsList.innerHTML = stats.recent_logs.map(UIComponents.renderLogEntry).join('');

        const directory = await DashboardService.loadCustomerDirectory();
        const dirList = document.getElementById('admin-accounts-list');
        if (dirList) {
            dirList.innerHTML = directory.map(acc => `
                <div style="display: flex; align-items: center; justify-content: space-between; padding: 1.25rem; background: rgba(255,255,255,0.02); border-radius: 1rem; margin-bottom: 1rem; border: 1px solid var(--glass-border);">
                    <div style="display: flex; align-items: center; gap: 1.5rem;">
                        <div style="width: 44px; height: 44px; background: rgba(99, 102, 241, 0.1); color: var(--primary); border-radius: 50%; display: flex; align-items: center; justify-content: center; font-weight: 700;">
                            ${acc.owner_name.charAt(0).toUpperCase()}
                        </div>
                        <div>
                            <div style="font-weight: 600; color: var(--text-primary);">${acc.owner_name}</div>
                            <div style="font-size: 0.75rem; color: var(--text-secondary);">${acc.account_number}</div>
                        </div>
                    </div>
                    <div style="text-align: right; display: flex; flex-direction: column; align-items: flex-end; gap: 0.5rem;">
                        <div style="font-weight: 700; color: var(--text-primary);">₹${acc.balance.toLocaleString('en-IN')}</div>
                        <div style="display: flex; gap: 0.5rem; align-items: center;">
                            ${UIComponents.renderStatusTag(acc.status)}
                            <div class="admin-actions" style="display: flex; gap: 0.25rem;">
                                ${acc.status !== 'MONITORED' ? `<button onclick="app.updateAccountStatus(${acc.id}, 'MONITORED')" title="Monitor" style="padding: 0.25rem; background: rgba(245, 158, 11, 0.1); color: var(--warning); border: 1px solid rgba(245, 158, 11, 0.2); border-radius: 4px; cursor: pointer;"><i data-lucide="eye" style="width: 14px; height: 14px;"></i></button>` : ''}
                                ${acc.status !== 'FROZEN' ? `<button onclick="app.updateAccountStatus(${acc.id}, 'FROZEN')" title="Freeze/Block" style="padding: 0.25rem; background: rgba(239, 68, 68, 0.1); color: var(--danger); border: 1px solid rgba(239, 68, 68, 0.2); border-radius: 4px; cursor: pointer;"><i data-lucide="lock" style="width: 14px; height: 14px;"></i></button>` : ''}
                                ${acc.status !== 'ACTIVE' ? `<button onclick="app.updateAccountStatus(${acc.id}, 'ACTIVE')" title="Defreeze/Unlock" style="padding: 0.25rem; background: rgba(34, 197, 94, 0.1); color: var(--success); border: 1px solid rgba(34, 197, 94, 0.2); border-radius: 4px; cursor: pointer;"><i data-lucide="unlock" style="width: 14px; height: 14px;"></i></button>` : ''}
                            </div>
                        </div>
                    </div>
                </div>
            `).join('');
        }

        if (['branch_head', 'regional_head', 'central_head', 'super_admin'].includes(store.user.role)) {
            this.loadThreatIntelligence();
        }
    },

    async loadThreatIntelligence() {
        const threats = await DashboardService.loadThreatIntelligence();
        const list = document.getElementById('threat-list');
        if (list) {
            list.innerHTML = threats.length > 0
                ? threats.map(UIComponents.renderThreatItem).join('')
                : '<div style="text-align: center; padding: 2rem; color: var(--text-muted);">No suspicious activities detected.</div>';

            const uniqueUsers = new Set(threats.map(t => t.user)).size;
            document.getElementById('actor-anomalies').innerText = uniqueUsers;

            const riskIndex = document.getElementById('overall-risk-index');
            if (threats.length > 5) { riskIndex.innerText = 'CRITICAL'; riskIndex.style.color = 'var(--danger)'; }
            else if (threats.length > 0) { riskIndex.innerText = 'ELEVATED'; riskIndex.style.color = 'var(--warning)'; }
            else { riskIndex.innerText = 'NOMINAL'; riskIndex.style.color = 'var(--success)'; }
        }
        if (window.lucide) lucide.createIcons();
    },

    setupRoleUI(user) {
        const badgeText = {
            customer: 'IDENTITY ACCREDITED', teller: 'AUTHORISED TELLER',
            branch_head: 'BRANCH OVERSIGHT', regional_head: 'REGIONAL CLEARANCE',
            central_head: 'CENTRAL AUTHORITY', super_admin: 'ROOT ADMINISTRATOR'
        };

        if (document.getElementById('display-user')) document.getElementById('display-user').innerText = user.username;
        if (document.getElementById('profile-name')) document.getElementById('profile-name').innerText = user.username;
        if (document.getElementById('display-email')) document.getElementById('display-email').innerText = user.email;
        if (document.getElementById('profile-bio')) document.getElementById('profile-bio').innerText = user.bio || "Secure identity active.";
        if (document.getElementById('current-fingerprint')) document.getElementById('current-fingerprint').innerText = store.fingerprint;
        if (document.getElementById('display-role-badge')) document.getElementById('display-role-badge').innerText = user.role.toUpperCase();

        const perfBadge = document.getElementById('role-performance-badge');
        if (perfBadge) perfBadge.innerText = badgeText[user.role] || 'IDENTITY ACCREDITED';

        const isSenior = ['branch_head', 'regional_head', 'central_head', 'super_admin'].includes(user.role);
        const isStaff = user.role !== 'customer';

        document.querySelectorAll('.admin-only').forEach(el => el.style.display = isStaff ? 'flex' : 'none');
        document.getElementById('nav-threats').style.display = isSenior ? 'flex' : 'none';
        document.getElementById('nav-transfer').style.display = (user.role === 'customer' || user.role === 'teller') ? 'flex' : 'none';
        document.getElementById('nav-admin').style.display = isStaff ? 'flex' : 'none';

        document.getElementById('branch-stats-grid').style.display = isStaff ? 'grid' : 'none';

        const balCard = document.getElementById('balance-display')?.closest('.stat-card');
        if (balCard) balCard.style.display = user.role === 'customer' ? 'block' : 'none';

        const limCard = document.getElementById('account-limits-card');
        if (limCard) limCard.style.display = user.role === 'customer' ? 'block' : 'none';

        if (window.lucide) lucide.createIcons();
    },

    async performTransfer() {
        const payload = {
            to_account_number: document.getElementById('transfer-to').value,
            amount: parseFloat(document.getElementById('transfer-amount').value),
            idempotency_key: 'tx_' + Date.now()
        };
        try {
            await ApiService.request('/banking/transfer', { method: 'POST', body: JSON.stringify(payload) });
            alert('Transfer Successful');
            this.showDashboard();
            ui.showSection('overview');
        } catch (err) {
            alert(err.message);
        }
    },

    async simulateFileExport() {
        try {
            const data = await ApiService.request('/admin/export-report', { method: 'POST' });
            alert(data.message);
            this.loadThreatIntelligence();
        } catch (err) {
            alert("Export Blocked: " + err.message);
        }
    },

    async updateAccountStatus(accountId, status) {
        try {
            await DashboardService.updateAccountStatus(accountId, status);
            alert(`Account status updated to ${status}`);
            this.loadSecurityData();
        } catch (err) {
            alert(err.message);
        }
    }
};

// Global Init
if (store.token) app.showDashboard();
window.addEventListener('load', () => { if (window.lucide) lucide.createIcons(); });
