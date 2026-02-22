const API_URL = '/api/v1';

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
        const date = new Date(log.timestamp);
        const today = new Date();
        const isToday = date.toDateString() === today.toDateString();

        const timeStr = date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
        const dateStr = isToday ? '' : date.toLocaleDateString([], { month: 'short', day: 'numeric' }) + ' ';

        return `
            <div class="log-entry" style="display: flex; align-items: center; justify-content: space-between; padding: 0.75rem 1rem; background: rgba(255,255,255,0.02); border-radius: 0.75rem; margin-bottom: 0.5rem; border: 1px solid var(--glass-border); font-size: 0.813rem;">
                <div style="display: flex; align-items: center; gap: 0.75rem;">
                    <div style="color: var(--primary); font-family: monospace; white-space: nowrap;">[${dateStr}${timeStr}]</div>
                    <div>
                        <span style="font-weight: 600;">${log.username}</span>: ${log.action} 
                        <span style="color: var(--text-muted);">on ${log.resource}</span>
                    </div>
                </div>
                <div style="color: var(--text-muted); font-size: 0.75rem; text-align: right; overflow: hidden; text-overflow: ellipsis; max-width: 200px;">${log.context}</div>
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
    },

    renderAccountActions(acc) {
        if (!['branch_head', 'regional_head', 'central_head', 'super_admin'].includes(store.user.role)) return '';

        return `
            <div class="action-buttons" style="display: flex; gap: 0.5rem; margin-top: 0.75rem; justify-content: flex-end;">
                ${acc.status !== 'FROZEN' ? `<button onclick="app.mutateAccountStatus(${acc.id}, 'FROZEN')" class="btn-action danger" title="Freeze Account"><i data-lucide="lock"></i></button>` : `<button onclick="app.requestDefreeze(${acc.id})" class="btn-action" title="Request Defreeze" style="background: rgba(99,102,241,0.1); color: var(--primary); border: 1px solid rgba(99,102,241,0.3);"><i data-lucide="unlock"></i></button>`}
                ${acc.status !== 'MONITORED' ? `<button onclick="app.mutateAccountStatus(${acc.id}, 'MONITORED')" class="btn-action warning" title="Monitor Account"><i data-lucide="eye"></i></button>` : ''}
                ${acc.status !== 'ACTIVE' && acc.status !== 'FROZEN' ? `<button onclick="app.mutateAccountStatus(${acc.id}, 'ACTIVE')" class="btn-action success" title="Set Active"><i data-lucide="check-circle"></i></button>` : ''}
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
        return ApiService.request(`/admin/account/${accountId}/status`, {
            method: 'POST',
            body: JSON.stringify({ status_update: status })
        });
    },

    async loadAdminTransactions() {
        return ApiService.request('/admin/transactions');
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

    async handleAuthSuccess(token) {
        store.token = token;
        localStorage.setItem('token', token);
        await this.showDashboard();
        this.initNotificationSystem();
    },

    initNotificationSystem() {
        if (store.user.role === 'customer') return;

        // Poll for threats every 30 seconds
        if (store.pollingInterval) clearInterval(store.pollingInterval);
        store.lastThreatCount = 0;

        store.pollingInterval = setInterval(async () => {
            try {
                const threats = await DashboardService.loadThreatIntelligence();
                if (threats.length > store.lastThreatCount) {
                    const newThreat = threats[0];
                    if (newThreat.severity === 'HIGH') {
                        app.showNotification(`🚨 HIGH SEVERITY THREAT: ${newThreat.message}`, 'danger');
                    }
                    store.lastThreatCount = threats.length;
                    this.loadThreatIntelligence(); // Refresh UI
                }
            } catch (e) { console.error('Polling error', e); }
        }, 30000);
    },

    showNotification(msg, type = 'info') {
        const container = document.getElementById('notification-container') || document.body;
        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        toast.innerHTML = `
            <div style="display: flex; align-items: center; gap: 0.75rem;">
                <i data-lucide="${type === 'danger' ? 'alert-triangle' : 'info'}"></i>
                <span>${msg}</span>
            </div>
        `;
        container.appendChild(toast);
        if (window.lucide) lucide.createIcons();
        setTimeout(() => toast.remove(), 5000);
    },

    async mutateAccountStatus(id, newStatus) {
        try {
            await DashboardService.updateAccountStatus(id, newStatus);
            app.showNotification(`Account status updated to ${newStatus}`, 'success');
            await this.loadSecurityData(); // Refresh list
        } catch (err) {
            app.showNotification(err.message, 'danger');
        }
    },

    async mutateApproval(approvalId, action) {
        try {
            // Re-using existing approval endpoint
            await ApiService.request(`/banking/approve/${approvalId}`, { method: 'POST' });
            app.showNotification(`Transaction successfully ${action}`, 'success');
            await this.loadSecurityData();
        } catch (err) {
            app.showNotification(err.message, 'danger');
        }
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
        if (!store.user || store.user.role !== 'customer') return;
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
                            <span style="font-weight: 600;">${tx.to_user || (tx.is_debit ? 'Sent' : 'Received')}</span>
                            <span style="font-weight: 700; color: ${tx.is_debit ? 'var(--danger)' : 'var(--success)'};">
                                ${tx.is_debit ? '-' : '+'}₹${tx.amount.toLocaleString('en-IN')}
                            </span>
                        </div>
                        <div style="font-size: 0.75rem; color: var(--text-secondary);">${new Date(tx.timestamp).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' })}</div>
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

        const adminTxs = await DashboardService.loadAdminTransactions();
        const txList = document.getElementById('admin-transactions-list');
        if (txList) {
            txList.innerHTML = adminTxs.map(tx => `
                <div class="transaction-item" style="padding: 1rem; background: rgba(255,255,255,0.02); border-radius: 0.75rem; border: 1px solid var(--glass-border); margin-bottom: 0.5rem;">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <div>
                            <div style="font-weight: 600; font-size: 0.875rem;">${tx.from_account} → ${tx.to_account}</div>
                            <div style="font-size: 0.75rem; color: var(--text-secondary); opacity: 0.7;">${tx.from_user} → ${tx.to_user} • ${new Date(tx.timestamp).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' })}</div>
                        </div>
                        <div style="text-align: right;">
                            <div style="font-weight: 700; color: ${tx.status === 'completed' ? 'var(--success)' : 'var(--warning)'};">₹${tx.amount.toLocaleString('en-IN')}</div>
                            <div style="font-size: 0.625rem; text-transform: uppercase; font-weight: 700;">${tx.status}</div>
                        </div>
                    </div>
                    ${tx.approval && tx.approval.status === 'pending' && ['branch_head', 'regional_head', 'central_head'].includes(store.user.role) ? `
                        <div style="margin-top: 0.75rem; display: flex; align-items: center; justify-content: space-between; padding-top: 0.75rem; border-top: 1px dotted var(--glass-border);">
                            <div style="display: flex; flex-direction: column; gap: 0.125rem;">
                                <span style="font-size: 0.688rem; color: var(--text-muted);">Requires: ${tx.approval.required_role.toUpperCase()}</span>
                                <span style="font-size: 0.625rem; color: var(--text-secondary); opacity: 0.6;">⏳ Pending since ${new Date(tx.approval.created_at || tx.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
                            </div>
                            <button onclick="app.mutateApproval(${tx.approval.id}, 'approved')" class="btn-action success" title="Approve Transaction"><i data-lucide="check-circle"></i></button>
                        </div>
                    ` : ''}
                </div>
            `).join('');
        }

        const overviewList = document.getElementById('transactions-list-overview');
        if (overviewList) {
            overviewList.innerHTML = adminTxs.map(tx => `
                <div class="transaction-item">
                    <div style="flex-grow: 1;">
                        <div style="display: flex; justify-content: space-between;">
                            <span style="font-weight: 600;">${tx.from_user} → ${tx.to_user}</span>
                            <span style="font-weight: 700; color: var(--success);">₹${tx.amount.toLocaleString('en-IN')}</span>
                        </div>
                        <div style="font-size: 0.75rem; color: var(--text-secondary); opacity: 0.7;">${tx.from_account} → ${tx.to_account} • ${new Date(tx.timestamp).toLocaleString([], { dateStyle: 'short', timeStyle: 'short' })}</div>
                    </div>
                </div>
            `).join('');
        }

        const logsList = document.getElementById('admin-logs-list');
        if (logsList) logsList.innerHTML = stats.recent_logs.map(UIComponents.renderLogEntry).join('');

        // Render Hierarchical Stats
        const hierarchySection = document.getElementById('hierarchical-intelligence-section');
        const hierarchyGrid = document.getElementById('hierarchy-stats-grid');
        const scopeLabel = document.getElementById('hierarchy-scope-label');

        if (hierarchySection && hierarchyGrid && stats.hierarchy_stats && stats.hierarchy_stats.length > 0) {
            hierarchySection.style.display = 'block';
            scopeLabel.innerText = `${stats.hierarchy_stats[0].type} LEVEL VISIBILITY`;

            hierarchyGrid.innerHTML = stats.hierarchy_stats.map(s => `
                <div class="stat-card" style="padding: 1rem; border-left: 3px solid var(--primary);">
                    <div style="font-size: 0.688rem; color: var(--text-muted); text-transform: uppercase; font-weight: 700; margin-bottom: 0.25rem;">${s.name}</div>
                    <div style="display: flex; align-items: baseline; gap: 0.5rem;">
                        <span style="font-size: 1.25rem; font-weight: 700;">${s.count}</span>
                        <span style="font-size: 0.625rem; color: var(--text-secondary);">Active Identities</span>
                    </div>
                </div>
            `).join('');
        } else if (hierarchySection) {
            hierarchySection.style.display = 'none';
        }

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
                            <div style="font-size: 0.75rem; color: var(--text-secondary); font-family: monospace;">${acc.account_number} • ${acc.owner_role.toUpperCase()}</div>
                            <div style="font-size: 0.688rem; color: var(--text-muted); margin-top: 0.25rem;">📞 ${acc.phone_number || 'N/A'} • 📄 PAN: ${acc.pan_number || 'N/A'}</div>
                        </div>
                    </div>
                    <div style="text-align: right;">
                        <div style="font-weight: 700; color: var(--text-primary); margin-bottom: 0.25rem;">₹${acc.balance.toLocaleString('en-IN')}</div>
                        ${UIComponents.renderStatusTag(acc.status)}
                        ${UIComponents.renderAccountActions(acc)}
                    </div>
                </div>
            `).join('');
        }

        if (['branch_head', 'regional_head', 'central_head', 'super_admin'].includes(store.user.role)) {
            this.loadThreatIntelligence();
            this.loadAccountAlerts();
        }

        if (['regional_head', 'central_head', 'super_admin'].includes(store.user.role)) {
            const defreezePanel = document.getElementById('defreeze-requests-panel');
            if (defreezePanel) defreezePanel.style.display = 'block';
            this.loadDefreezeRequests();
        }
    },

    async loadAccountAlerts() {
        try {
            const alerts = await ApiService.request('/admin/alerts');
            const list = document.getElementById('account-alerts-list');
            const badge = document.getElementById('alert-count-badge');
            const unresolved = alerts.filter(a => !a.is_resolved);
            if (badge) badge.innerText = unresolved.length;

            if (list) {
                if (alerts.length === 0) {
                    list.innerHTML = '<p class="empty-msg">No active alerts. System is nominal. ✅</p>';
                } else {
                    list.innerHTML = alerts.map(a => {
                        const sevColor = a.severity === 'CRITICAL' ? '#ef4444' : a.severity === 'HIGH' ? '#f59e0b' : '#6366f1';
                        return `
                        <div style="display: flex; align-items: center; justify-content: space-between; padding: 1rem; background: rgba(255,255,255,0.02); border-radius: 0.75rem; margin-bottom: 0.5rem; border: 1px solid var(--glass-border); border-left: 3px solid ${sevColor};">
                            <div>
                                <div style="font-weight: 600; font-size: 0.875rem;">${a.alert_type.replace(/_/g, ' ')}</div>
                                <div style="font-size: 0.75rem; color: var(--text-secondary); margin-top: 0.25rem;">${a.reason}</div>
                                <div style="font-size: 0.688rem; color: var(--text-muted); margin-top: 0.25rem;">${a.account_number} • ${new Date(a.created_at).toLocaleString()}</div>
                            </div>
                            <div style="display: flex; align-items: center; gap: 0.75rem;">
                                <span style="background: ${sevColor}22; color: ${sevColor}; padding: 0.2rem 0.5rem; border-radius: 0.25rem; font-size: 0.688rem; font-weight: 700;">${a.severity}</span>
                                ${!a.is_resolved ? `<button class="btn" onclick="app.resolveAlert(${a.id})" style="padding: 0.3rem 0.75rem; font-size: 0.688rem; background: rgba(34,197,94,0.1); color: #22c55e; border: 1px solid rgba(34,197,94,0.2);">Resolve</button>` : '<span style="color: #22c55e; font-size: 0.688rem; font-weight: 700;">✓ RESOLVED</span>'}
                            </div>
                        </div>`;
                    }).join('');
                }
            }
        } catch (err) { console.warn('Failed to load alerts:', err); }
    },

    async resolveAlert(alertId) {
        try {
            await ApiService.request(`/admin/alert/${alertId}/resolve`, { method: 'POST' });
            app.showNotification('Alert resolved successfully', 'success');
            this.loadAccountAlerts();
        } catch (err) { alert(err.message); }
    },

    async loadDefreezeRequests() {
        try {
            const requests = await ApiService.request('/admin/defreeze-requests');
            const list = document.getElementById('defreeze-requests-list');
            if (list) {
                if (requests.length === 0) {
                    list.innerHTML = '<p class="empty-msg">No pending defreeze requests.</p>';
                } else {
                    list.innerHTML = requests.map(r => `
                        <div style="display: flex; align-items: center; justify-content: space-between; padding: 1rem; background: rgba(255,255,255,0.02); border-radius: 0.75rem; margin-bottom: 0.5rem; border: 1px solid var(--glass-border);">
                            <div>
                                <div style="font-weight: 600;">${r.account_number}</div>
                                <div style="font-size: 0.75rem; color: var(--text-secondary);">Requested by: ${r.requested_by} • ${r.reason}</div>
                                <div style="font-size: 0.688rem; color: var(--text-muted);">${new Date(r.created_at).toLocaleString()}</div>
                            </div>
                            <button class="btn btn-primary" onclick="app.approveDefreeze(${r.id})" style="padding: 0.4rem 1rem; font-size: 0.75rem;">
                                Approve & Unfreeze
                            </button>
                        </div>
                    `).join('');
                }
            }
        } catch (err) { console.warn('Failed to load defreeze requests:', err); }
    },

    async approveDefreeze(requestId) {
        try {
            const result = await ApiService.request(`/admin/defreeze-approve/${requestId}`, { method: 'POST' });
            app.showNotification(result.message, 'success');
            this.loadDefreezeRequests();
            this.loadSecurityData();
        } catch (err) { alert(err.message); }
    },

    async requestDefreeze(accountId) {
        try {
            const result = await ApiService.request(`/admin/defreeze-request/${accountId}`, { method: 'POST' });
            app.showNotification(result.message, 'success');
        } catch (err) { alert(err.message); }
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
        if (document.getElementById('display-phone')) document.getElementById('display-phone').innerText = user.phone_number || "--";
        if (document.getElementById('display-kyc-status')) {
            const ks = document.getElementById('display-kyc-status');
            ks.innerText = (user.kyc_status || 'VERIFIED').toUpperCase();
            ks.className = `status-tag ${(user.kyc_status || 'VERIFIED').toLowerCase()}`;
        }
        if (document.getElementById('display-address')) document.getElementById('display-address').innerText = user.address || "--";
        if (document.getElementById('display-pan')) document.getElementById('display-pan').innerText = user.pan_number || "--";
        if (document.getElementById('display-dob')) document.getElementById('display-dob').innerText = user.date_of_birth || "--";

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

        const balCard = document.getElementById('stat-card-balance');
        if (balCard) balCard.style.display = user.role === 'customer' ? 'flex' : 'none';

        const accCard = document.getElementById('stat-card-account');
        if (accCard) accCard.style.display = user.role === 'customer' ? 'flex' : 'none';

        const limCard = document.getElementById('account-limits-card');
        if (limCard) limCard.style.display = user.role === 'customer' ? 'block' : 'none';

        const kycCard = document.getElementById('kyc-info-card');
        if (kycCard) kycCard.style.display = user.role === 'customer' ? 'block' : 'none';

        if (window.lucide) lucide.createIcons();
    },

    async transfer() {
        const toAccount = document.getElementById('target-account').value.trim();
        const amount = parseFloat(document.getElementById('transfer-amount').value);

        if (!toAccount) { this.showNotification('Please enter a recipient account number', 'error'); return; }
        if (!amount || amount <= 0) { this.showNotification('Please enter a valid amount', 'error'); return; }

        const payload = {
            to_account_number: toAccount,
            amount: amount,
            idempotency_key: 'tx_' + Date.now()
        };
        try {
            const result = await ApiService.request('/banking/transfer', { method: 'POST', body: JSON.stringify(payload) });
            this.showNotification(`Transfer of \u20B9${amount.toLocaleString('en-IN')} to ${toAccount} ${result.status === 'completed' ? 'completed' : 'submitted'} successfully!`, 'success');
            document.getElementById('target-account').value = '';
            document.getElementById('transfer-amount').value = '';
            this.loadAccountingData();
        } catch (err) {
            this.showNotification(err.message || 'Transfer failed', 'error');
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
    }
};

// Global click telemetry: Timestamp every click for forensic auditing
document.addEventListener('click', async (e) => {
    if (!store.token) return; // Only log for authenticated users

    const target = e.target.closest('button, a, .nav-item, .transaction-item, .card, input');
    if (!target) return;

    const payload = {
        element_id: target.id || null,
        element_class: target.className || null,
        tag_name: target.tagName,
        text_content: target.innerText ? target.innerText.trim() : target.value || null
    };

    try {
        // Silent logging - don't await/block UI
        fetch(`${API_URL}/banking/log-interaction`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${store.token}`
            },
            body: JSON.stringify(payload)
        });
    } catch (err) {
        console.warn('Telemetry failed:', err);
    }
});

// Global Init
if (store.token) app.showDashboard();
window.addEventListener('load', () => { if (window.lucide) lucide.createIcons(); });
