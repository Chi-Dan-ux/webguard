// ═══════════════════════════════════════════
//  WEBGUARD — auth.js
//  Login / Register page logic
// ═══════════════════════════════════════════

// ── Tab switching ──────────────────────────
function switchTab(tab) {
  const loginForm    = document.getElementById('form-login');
  const registerForm = document.getElementById('form-register');
  const successForm  = document.getElementById('form-success');
  const tabLogin     = document.getElementById('tab-login');
  const tabRegister  = document.getElementById('tab-register');

  // Hide all panels
  loginForm.classList.add('d-none');
  registerForm.classList.add('d-none');
  successForm.classList.add('d-none');
  tabLogin.classList.remove('active');
  tabRegister.classList.remove('active');

  // Show selected
  if (tab === 'login') {
    loginForm.classList.remove('d-none');
    tabLogin.classList.add('active');
  } else {
    registerForm.classList.remove('d-none');
    tabRegister.classList.add('active');
  }

  // Scroll to top of form on mobile
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

// ── Password visibility toggle ─────────────
function togglePassword(inputId, btn) {
  const input = document.getElementById(inputId);
  const icon  = btn.querySelector('i');
  if (input.type === 'password') {
    input.type = 'text';
    icon.classList.replace('bi-eye', 'bi-eye-slash');
  } else {
    input.type = 'password';
    icon.classList.replace('bi-eye-slash', 'bi-eye');
  }
}

// ── Role button toggle ─────────────────────
document.querySelectorAll('.auth-role-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.auth-role-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
  });
});

// ── Helpers ────────────────────────────────
function setError(id, msg) {
  const el = document.getElementById(id);
  if (el) el.textContent = msg ? ('⚠ ' + msg) : '';
}

function setInputState(input, valid) {
  if (!input) return;
  input.classList.toggle('is-invalid', !valid);
  input.classList.toggle('is-valid', valid);
}

function clearState(input, errId) {
  if (input) {
    input.classList.remove('is-invalid', 'is-valid');
  }
  setError(errId, '');
}

// ── Password strength meter ────────────────
const regPasswordInput = document.getElementById('regPassword');
if (regPasswordInput) {
  regPasswordInput.addEventListener('input', () => {
    const val   = regPasswordInput.value;
    const fill  = document.getElementById('strengthFill');
    const label = document.getElementById('strengthLabel');
    let score   = 0;

    if (val.length >= 8)                    score++;
    if (/[A-Z]/.test(val))                  score++;
    if (/[0-9]/.test(val))                  score++;
    if (/[^A-Za-z0-9]/.test(val))           score++;

    const levels = [
      { w: '0%',   bg: 'transparent',    lbl: 'Enter password', col: 'var(--gray-400)' },
      { w: '25%',  bg: '#DC2626',        lbl: 'Weak',           col: '#DC2626' },
      { w: '50%',  bg: '#D97706',        lbl: 'Fair',           col: '#D97706' },
      { w: '75%',  bg: '#2563EB',        lbl: 'Good',           col: '#2563EB' },
      { w: '100%', bg: 'var(--green)',   lbl: 'Strong',         col: 'var(--green)' },
    ];

    const level = val.length === 0 ? levels[0] : levels[score] || levels[1];
    fill.style.width      = level.w;
    fill.style.background = level.bg;
    label.textContent     = level.lbl;
    label.style.color     = level.col;
  });
}

// ── LOGIN form validation ──────────────────
const loginForm = document.getElementById('loginForm');
if (loginForm) {
  loginForm.addEventListener('submit', (e) => {
    e.preventDefault();
    let valid = true;

    const email    = document.getElementById('loginEmail');
    const password = document.getElementById('loginPassword');

    // Clear previous states
    clearState(email, 'loginEmailErr');
    clearState(password, 'loginPassErr');

    // Email
    if (!email.value.trim()) {
      setError('loginEmailErr', 'Email address is required.');
      setInputState(email, false);
      valid = false;
    } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.value)) {
      setError('loginEmailErr', 'Please enter a valid email address.');
      setInputState(email, false);
      valid = false;
    } else {
      setInputState(email, true);
    }

    // Password
    if (!password.value) {
      setError('loginPassErr', 'Password is required.');
      setInputState(password, false);
      valid = false;
    } else {
      setInputState(password, true);
    }

    if (!valid) return;

    // ── Simulate loading (replace this with real Django fetch later) ──
    setLoading('login', true);

    setTimeout(() => {
      setLoading('login', false);
      // TODO: Replace this block with Django form submission or fetch() call
      // For now, redirect to dashboard placeholder
      showToast('Welcome back! Redirecting to dashboard…', 'success');
      setTimeout(() => {
        window.location.href = 'dashboard.html';
        console.log('LOGIN: Would redirect to /dashboard/');
      }, 1500);
    }, 1800);
  });
}

// ── REGISTER form validation ───────────────
const registerForm = document.getElementById('registerForm');
if (registerForm) {
  registerForm.addEventListener('submit', (e) => {
    e.preventDefault();
    let valid = true;

    const firstName = document.getElementById('regFirstName');
    const lastName  = document.getElementById('regLastName');
    const email     = document.getElementById('regEmail');
    const role      = document.getElementById('regRole');
    const password  = document.getElementById('regPassword');
    const confirm   = document.getElementById('regConfirm');
    const terms     = document.getElementById('agreeTerms');

    // Clear all
    [firstName, lastName, email, role, password, confirm].forEach(inp => {
      if (inp) { inp.classList.remove('is-invalid', 'is-valid'); }
    });
    ['regFirstErr','regLastErr','regEmailErr','regRoleErr','regPassErr','regConfirmErr'].forEach(id => setError(id, ''));

    // First name
    if (!firstName.value.trim()) {
      setError('regFirstErr', 'First name is required.');
      setInputState(firstName, false);
      valid = false;
    } else {
      setInputState(firstName, true);
    }

    // Last name
    if (!lastName.value.trim()) {
      setError('regLastErr', 'Last name is required.');
      setInputState(lastName, false);
      valid = false;
    } else {
      setInputState(lastName, true);
    }

    // Email
    if (!email.value.trim()) {
      setError('regEmailErr', 'Email address is required.');
      setInputState(email, false);
      valid = false;
    } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.value)) {
      setError('regEmailErr', 'Enter a valid email address.');
      setInputState(email, false);
      valid = false;
    } else {
      setInputState(email, true);
    }

    // Role
    if (!role.value) {
      setError('regRoleErr', 'Please select your role.');
      setInputState(role, false);
      valid = false;
    } else {
      setInputState(role, true);
    }

    // Password
    if (!password.value) {
      setError('regPassErr', 'Password is required.');
      setInputState(password, false);
      valid = false;
    } else if (password.value.length < 8) {
      setError('regPassErr', 'Password must be at least 8 characters.');
      setInputState(password, false);
      valid = false;
    } else {
      setInputState(password, true);
    }

    // Confirm
    if (!confirm.value) {
      setError('regConfirmErr', 'Please confirm your password.');
      setInputState(confirm, false);
      valid = false;
    } else if (confirm.value !== password.value) {
      setError('regConfirmErr', 'Passwords do not match.');
      setInputState(confirm, false);
      valid = false;
    } else {
      setInputState(confirm, true);
    }

    // Terms
    if (!terms.checked) {
      showToast('Please agree to the Terms of Use to continue.', 'error');
      valid = false;
    }

    if (!valid) return;

    // ── Simulate loading ──
    setLoading('register', true);

    setTimeout(() => {
      setLoading('register', false);
      // TODO: Replace with Django fetch() POST to /api/register/
      // Show success screen
      document.getElementById('form-register').classList.add('d-none');
      document.getElementById('form-success').classList.remove('d-none');
    }, 2000);
  });
}

// ── Loading state helper ───────────────────
function setLoading(form, loading) {
  const prefix = form === 'login' ? 'login' : 'reg';
  const btn     = document.getElementById(prefix + 'SubmitBtn');
  const text    = document.getElementById(prefix + 'BtnText');
  const spinner = document.getElementById(prefix + 'Spinner');
  const arrow   = document.getElementById(prefix + 'Arrow');

  if (!btn) return;
  btn.disabled = loading;
  if (loading) {
    text.textContent = form === 'login' ? 'Signing in…' : 'Creating account…';
    spinner.classList.remove('d-none');
    if (arrow) arrow.classList.add('d-none');
  } else {
    text.textContent = form === 'login' ? 'Sign in to WebGuard' : 'Create Account';
    spinner.classList.add('d-none');
    if (arrow) arrow.classList.remove('d-none');
  }
}

// ── Toast notification ─────────────────────
function showToast(msg, type = 'success') {
  const existing = document.querySelector('.wg-toast');
  if (existing) existing.remove();

  const toast = document.createElement('div');
  toast.className = 'wg-toast';
  toast.innerHTML = `
    <i class="bi ${type === 'success' ? 'bi-check-circle-fill' : 'bi-exclamation-circle-fill'}"></i>
    <span>${msg}</span>
  `;
  toast.style.cssText = `
    position: fixed;
    bottom: 28px;
    right: 28px;
    display: flex;
    align-items: center;
    gap: 10px;
    background: ${type === 'success' ? '#15803D' : '#DC2626'};
    color: white;
    padding: 12px 20px;
    border-radius: 12px;
    font-size: 14px;
    font-family: var(--font-body);
    font-weight: 600;
    box-shadow: 0 8px 24px rgba(0,0,0,0.15);
    z-index: 9999;
    animation: slideInUp 0.3s ease;
    max-width: 340px;
  `;

  // Inject keyframe once
  if (!document.getElementById('wg-toast-anim')) {
    const style = document.createElement('style');
    style.id = 'wg-toast-anim';
    style.textContent = `
      @keyframes slideInUp {
        from { opacity:0; transform:translateY(16px); }
        to   { opacity:1; transform:translateY(0); }
      }
    `;
    document.head.appendChild(style);
  }

  document.body.appendChild(toast);
  setTimeout(() => { toast.style.opacity = '0'; toast.style.transform = 'translateY(16px)'; toast.style.transition = 'all 0.3s'; }, 3000);
  setTimeout(() => toast.remove(), 3400);
}

// ── Live email validation on blur ──────────
['loginEmail', 'regEmail'].forEach(id => {
  const el = document.getElementById(id);
  if (!el) return;
  const errId = id === 'loginEmail' ? 'loginEmailErr' : 'regEmailErr';
  el.addEventListener('blur', () => {
    if (!el.value) return;
    const valid = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(el.value);
    setInputState(el, valid);
    setError(errId, valid ? '' : 'Please enter a valid email address.');
  });
  el.addEventListener('input', () => clearState(el, errId));
});