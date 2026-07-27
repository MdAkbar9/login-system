/**
 * AuthCrypt - Frontend Logic & Bcrypt Sandbox Manager
 */

document.addEventListener('DOMContentLoaded', () => {
  // Global App State
  let currentUser = null;
  let authToken = localStorage.getItem('auth_token') || null;

  // Dynamic API Base URL
  // If opened directly via file:// or non-3000 port (e.g. Live Server), automatically target http://localhost:3000
  const API_BASE = (window.location.protocol === 'file:' || (window.location.port && window.location.port !== '3000'))
    ? 'http://localhost:3000'
    : '';

  // DOM Element References
  const navTabs = document.querySelectorAll('.nav-btn');
  const tabContents = document.querySelectorAll('.tab-content');
  const navDashboardBtn = document.getElementById('nav-dashboard');
  const userStatusPill = document.getElementById('user-status-pill');
  const statusDot = document.getElementById('status-dot');
  const statusText = document.getElementById('status-text');

  // Login Form
  const loginForm = document.getElementById('login-form');
  const loginIdInput = document.getElementById('login-id');
  const loginPassInput = document.getElementById('login-password');
  const toggleLoginPass = document.getElementById('toggle-login-pass');
  const linkToRegister = document.getElementById('link-to-register');
  const forgotPassBtn = document.getElementById('forgot-pass-btn');

  // Register Form
  const registerForm = document.getElementById('register-form');
  const regUsernameInput = document.getElementById('reg-username');
  const regEmailInput = document.getElementById('reg-email');
  const regPassInput = document.getElementById('reg-password');
  const regConfirmPassInput = document.getElementById('reg-confirm-password');
  const toggleRegPass = document.getElementById('toggle-reg-pass');
  const strengthBar = document.getElementById('strength-bar');
  const strengthLabel = document.getElementById('strength-label');
  const passwordMatchError = document.getElementById('password-match-error');
  const linkToLogin = document.getElementById('link-to-login');

  // Dashboard Elements
  const dashUsername = document.getElementById('dash-username');
  const dashEmail = document.getElementById('dash-email');
  const dashId = document.getElementById('dash-id');
  const dashCreated = document.getElementById('dash-created');
  const dashLogin = document.getElementById('dash-login');
  const dashHash = document.getElementById('dash-hash');
  const userAvatar = document.getElementById('user-avatar');
  const copyHashBtn = document.getElementById('copy-hash-btn');
  const logoutBtn = document.getElementById('logout-btn');
  const changePassForm = document.getElementById('change-pass-form');

  // Bcrypt Sandbox Elements
  const sandboxHashForm = document.getElementById('sandbox-hash-form');
  const sandboxInput = document.getElementById('sandbox-input');
  const sandboxRounds = document.getElementById('sandbox-rounds');
  const roundsDisplay = document.getElementById('rounds-display');
  const sandboxOutput = document.getElementById('sandbox-output');
  const timingBadge = document.getElementById('timing-badge');
  const resultFullHash = document.getElementById('result-full-hash');
  const decompAlgo = document.getElementById('decomp-algo');
  const decompCost = document.getElementById('decomp-cost');
  const decompSalt = document.getElementById('decomp-salt');
  const decompHash = document.getElementById('decomp-hash');

  const sandboxVerifyForm = document.getElementById('sandbox-verify-form');
  const verifyInput = document.getElementById('verify-input');
  const verifyHash = document.getElementById('verify-hash');
  const verifyOutput = document.getElementById('verify-output');
  const verifyBadgeContainer = document.getElementById('verify-badge-container');
  const verifyIcon = document.getElementById('verify-icon');
  const verifyMsg = document.getElementById('verify-msg');

  // ----------------------------------------------------
  // INITIALIZATION & SESSION CHECK
  // ----------------------------------------------------
  checkSession();

  // ----------------------------------------------------
  // TAB NAVIGATION SYSTEM
  // ----------------------------------------------------
  function switchTab(tabId) {
    navTabs.forEach(btn => {
      if (btn.dataset.tab === tabId) {
        btn.classList.add('active');
      } else {
        btn.classList.remove('active');
      }
    });

    tabContents.forEach(content => {
      if (content.id === `tab-${tabId}`) {
        content.classList.add('active');
      } else {
        content.classList.remove('active');
      }
    });
  }

  navTabs.forEach(btn => {
    btn.addEventListener('click', () => {
      switchTab(btn.dataset.tab);
    });
  });

  linkToRegister.addEventListener('click', (e) => {
    e.preventDefault();
    switchTab('register');
  });

  linkToLogin.addEventListener('click', (e) => {
    e.preventDefault();
    switchTab('login');
  });

  forgotPassBtn.addEventListener('click', (e) => {
    e.preventDefault();
    showToast('Bcrypt info: Plaintext passwords are not stored, so forgotten passwords can only be reset via salted re-hashing.', 'info');
  });

  // Toggle Password Visibility
  function setupPasswordToggle(toggleBtn, inputEl) {
    toggleBtn.addEventListener('click', () => {
      const type = inputEl.getAttribute('type') === 'password' ? 'text' : 'password';
      inputEl.setAttribute('type', type);
      toggleBtn.style.color = type === 'text' ? 'var(--primary)' : 'var(--text-dim)';
    });
  }

  setupPasswordToggle(toggleLoginPass, loginPassInput);
  setupPasswordToggle(toggleRegPass, regPassInput);

  // ----------------------------------------------------
  // PASSWORD STRENGTH METER
  // ----------------------------------------------------
  regPassInput.addEventListener('input', () => {
    const val = regPassInput.value;
    const strength = evaluatePasswordStrength(val);
    updateStrengthUI(strength);
    validatePasswordMatch();
  });

  regConfirmPassInput.addEventListener('input', validatePasswordMatch);

  function evaluatePasswordStrength(password) {
    if (!password) return { score: 0, label: 'Password Strength', color: '#6b7280', width: '0%' };
    
    let score = 0;
    if (password.length >= 6) score += 1;
    if (password.length >= 10) score += 1;
    if (/[A-Z]/.test(password)) score += 1;
    if (/[0-9]/.test(password)) score += 1;
    if (/[^A-Za-z0-9]/.test(password)) score += 1;

    switch (score) {
      case 1:
        return { score: 1, label: 'Weak (Bcrypt will still hash it, but make it stronger)', color: '#ef4444', width: '25%' };
      case 2:
      case 3:
        return { score: 2, label: 'Fair (Acceptable)', color: '#f59e0b', width: '55%' };
      case 4:
        return { score: 3, label: 'Strong (Great password)', color: '#10b981', width: '80%' };
      case 5:
        return { score: 4, label: 'Super Strong (Optimal security)', color: '#06b6d4', width: '100%' };
      default:
        return { score: 0, label: 'Too short', color: '#ef4444', width: '10%' };
    }
  }

  function updateStrengthUI(strength) {
    strengthBar.style.width = strength.width;
    strengthBar.style.backgroundColor = strength.color;
    strengthLabel.textContent = strength.label;
    strengthLabel.style.color = strength.color;
  }

  function validatePasswordMatch() {
    if (!regConfirmPassInput.value) {
      passwordMatchError.style.display = 'none';
      return true;
    }
    if (regPassInput.value !== regConfirmPassInput.value) {
      passwordMatchError.style.display = 'block';
      return false;
    } else {
      passwordMatchError.style.display = 'none';
      return true;
    }
  }

  // ----------------------------------------------------
  // AUTHENTICATION LOGIC
  // ----------------------------------------------------

  // Register Form Handler
  registerForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!validatePasswordMatch()) {
      showToast('Passwords do not match!', 'error');
      return;
    }

    const username = regUsernameInput.value.trim();
    const email = regEmailInput.value.trim();
    const password = regPassInput.value;

    const btn = document.getElementById('register-submit-btn');
    setButtonLoading(btn, true, 'Hashing & Registering...');

    try {
      const response = await fetch(`${API_BASE}/api/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, email, password })
      });

      const data = await response.json();

      if (data.success) {
        authToken = data.token;
        localStorage.setItem('auth_token', authToken);
        showToast(`Registration Successful! Bcrypt hashed in ${data.securityInfo.hashTimeMs}ms`, 'success');
        updateUserUI(data.user);
        registerForm.reset();
        updateStrengthUI({ score: 0, label: 'Password Strength', color: '#6b7280', width: '0%' });
        switchTab('dashboard');
      } else {
        showToast(data.message || 'Registration failed', 'error');
      }
    } catch (err) {
      showToast('Network error during registration. Ensure server is running at http://localhost:3000', 'error');
    } finally {
      setButtonLoading(btn, false, 'Register Account');
    }
  });

  // Login Form Handler
  loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const loginId = loginIdInput.value.trim();
    const password = loginPassInput.value;

    const btn = document.getElementById('login-submit-btn');
    setButtonLoading(btn, true, 'Verifying Bcrypt Hash...');

    try {
      const response = await fetch(`${API_BASE}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ loginId, password })
      });

      const data = await response.json();

      if (data.success) {
        authToken = data.token;
        localStorage.setItem('auth_token', authToken);
        showToast(`Welcome back, ${data.user.username}! (Verified in ${data.securityInfo.verifyTimeMs}ms)`, 'success');
        updateUserUI(data.user);
        loginForm.reset();
        switchTab('dashboard');
      } else {
        showToast(data.message || 'Invalid username/email or password.', 'error');
      }
    } catch (err) {
      showToast('Network error during login. Ensure server is running at http://localhost:3000', 'error');
    } finally {
      setButtonLoading(btn, false, 'Sign In');
    }
  });

  // Logout Handler
  logoutBtn.addEventListener('click', async () => {
    try {
      await fetch(`${API_BASE}/api/auth/logout`, { method: 'POST' });
    } catch (err) {}

    localStorage.removeItem('auth_token');
    authToken = null;
    currentUser = null;
    
    statusDot.className = 'status-dot offline';
    statusText.textContent = 'Guest';
    navDashboardBtn.style.display = 'none';

    showToast('Signed out successfully.', 'info');
    switchTab('login');
  });

  // Change Password Handler
  changePassForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const currentPassword = document.getElementById('change-curr-pass').value;
    const newPassword = document.getElementById('change-new-pass').value;

    try {
      const response = await fetch(`${API_BASE}/api/auth/change-password`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${authToken}`
        },
        body: JSON.stringify({ currentPassword, newPassword })
      });

      const data = await response.json();

      if (data.success) {
        showToast(data.message, 'success');
        dashHash.textContent = data.newHashPreview;
        changePassForm.reset();
      } else {
        showToast(data.message || 'Password update failed', 'error');
      }
    } catch (err) {
      showToast('Error updating password', 'error');
    }
  });

  // Copy Hash Button
  copyHashBtn.addEventListener('click', () => {
    const hashText = dashHash.textContent;
    navigator.clipboard.writeText(hashText).then(() => {
      showToast('Bcrypt Hash copied to clipboard!', 'info');
    });
  });

  // Check Current Session
  async function checkSession() {
    if (!authToken) return;

    try {
      const response = await fetch(`${API_BASE}/api/auth/me`, {
        headers: { 'Authorization': `Bearer ${authToken}` }
      });

      const data = await response.json();

      if (data.success && data.user) {
        updateUserUI(data.user);
      } else {
        localStorage.removeItem('auth_token');
        authToken = null;
      }
    } catch (err) {
      localStorage.removeItem('auth_token');
      authToken = null;
    }
  }

  function updateUserUI(user) {
    currentUser = user;
    statusDot.className = 'status-dot online';
    statusText.textContent = user.username;
    navDashboardBtn.style.display = 'inline-block';

    dashUsername.textContent = user.username;
    dashEmail.textContent = user.email;
    dashId.textContent = `#${user.id}`;
    userAvatar.textContent = user.username.charAt(0).toUpperCase();

    if (user.created_at) {
      const d = new Date(user.created_at);
      dashCreated.textContent = d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
    }
    dashLogin.textContent = user.last_login ? new Date(user.last_login).toLocaleTimeString() : 'Just now';

    if (user.passwordHashPreview) {
      dashHash.textContent = user.passwordHashPreview;
    }
  }

  // ----------------------------------------------------
  // BCRYPT INTERACTIVE VISUALIZER SANDBOX LOGIC
  // ----------------------------------------------------

  // Update slider label on range input
  sandboxRounds.addEventListener('input', () => {
    const r = parseInt(sandboxRounds.value, 10);
    const iterations = Math.pow(2, r).toLocaleString();
    roundsDisplay.textContent = `${r} (${iterations} iterations)`;
  });

  // Generate Hash Sandbox Form
  sandboxHashForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const text = sandboxInput.value;
    const saltRounds = sandboxRounds.value;

    const btn = document.getElementById('sandbox-gen-btn');
    setButtonLoading(btn, true, 'Generating Salt & Hashing...');

    try {
      const response = await fetch(`${API_BASE}/api/bcrypt/hash`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text, saltRounds })
      });

      const data = await response.json();

      if (data.success) {
        sandboxOutput.style.display = 'flex';
        resultFullHash.textContent = data.hash;
        timingBadge.textContent = `Time: ${data.durationMs}ms`;

        decompAlgo.textContent = data.breakdown.algorithm;
        decompCost.textContent = data.breakdown.costFactor;
        decompSalt.textContent = data.breakdown.salt22Chars;
        decompHash.textContent = data.breakdown.hash31Chars;

        // Auto-fill verifier hash input for easy testing
        verifyHash.value = data.hash;
        verifyInput.value = text;

        showToast(`Bcrypt Hash generated with cost factor ${saltRounds}!`, 'success');
      } else {
        showToast(data.message || 'Error generating hash', 'error');
      }
    } catch (err) {
      showToast('Server error during hash generation', 'error');
    } finally {
      setButtonLoading(btn, false, 'Generate Hash');
    }
  });

  // Verify Hash Sandbox Form
  sandboxVerifyForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const plainText = verifyInput.value;
    const hash = verifyHash.value.trim();

    try {
      const response = await fetch(`${API_BASE}/api/bcrypt/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ plainText, hash })
      });

      const data = await response.json();

      if (data.success) {
        verifyOutput.style.display = 'block';
        if (data.isMatch) {
          verifyBadgeContainer.className = 'result-banner match';
          verifyIcon.textContent = '✓';
          verifyMsg.textContent = `MATCH CONFIRMED: "${plainText}" produces this bcrypt hash! (${data.durationMs}ms)`;
        } else {
          verifyBadgeContainer.className = 'result-banner no-match';
          verifyIcon.textContent = '✕';
          verifyMsg.textContent = `NO MATCH: The password does NOT produce this hash. (${data.durationMs}ms)`;
        }
      } else {
        showToast(data.message || 'Verification error', 'error');
      }
    } catch (err) {
      showToast('Invalid bcrypt hash format or request failed', 'error');
    }
  });

  // Initial trigger for visualizer on load so inputs are pre-filled
  document.getElementById('sandbox-gen-btn').click();

  // ----------------------------------------------------
  // HELPER UTILITIES
  // ----------------------------------------------------

  function setButtonLoading(button, isLoading, text) {
    if (isLoading) {
      button.disabled = true;
      button.dataset.origText = button.innerHTML;
      button.innerHTML = `<span>${text}</span>`;
    } else {
      button.disabled = false;
      if (button.dataset.origText) {
        button.innerHTML = button.dataset.origText;
      }
    }
  }

  function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    
    let icon = 'ℹ';
    if (type === 'success') icon = '✓';
    if (type === 'error') icon = '✕';

    toast.innerHTML = `<span style="font-weight:bold">${icon}</span> <span>${message}</span>`;
    container.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateX(100%)';
      toast.style.transition = 'all 0.3s ease';
      setTimeout(() => toast.remove(), 300);
    }, 4000);
  }
});
