const status = document.querySelector('#status');
const form = document.querySelector('#password-form');

async function post(path, data) {
  const response = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  const result = await response.json();
  if (!response.ok) throw new Error(result.error);
  return result;
}

async function run(operation) {
  const buttons = document.querySelectorAll('button');
  buttons.forEach((button) => { button.disabled = true; });
  status.textContent = '';
  try {
    await operation();
  } catch (error) {
    if (error instanceof DOMException && error.name === 'NotAllowedError') {
      status.textContent = 'パスキー操作が中断されました。もう一度お試しください。';
    } else {
      status.textContent = error instanceof DOMException
        ? 'パスキー操作を完了できませんでした。'
        : error.message;
    }
  } finally {
    buttons.forEach((button) => { button.disabled = false; });
  }
}

form?.addEventListener('submit', (event) => {
  event.preventDefault();
  const action = event.submitter?.value === 'signup' ? 'signup' : 'login';
  const fields = Object.fromEntries(new FormData(form));
  void run(async () => {
    await post(`/api/${action}`, fields);
    location.assign('/account');
  });
});

async function usePasskey(purpose) {
  if (!window.PublicKeyCredential?.parseCreationOptionsFromJSON ||
      !window.PublicKeyCredential?.parseRequestOptionsFromJSON) {
    throw new Error('このブラウザーではパスキーを利用できません。');
  }
  const path = `/api/passkey/${purpose}`;
  const options = await post(path, { action: 'options' });
  const credential = purpose === 'register'
    ? await navigator.credentials.create({ publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(options) })
    : await navigator.credentials.get({ publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(options) });
  if (!credential) throw new Error('パスキー操作を完了できませんでした。');
  await post(path, { action: 'verify', credential: credential.toJSON() });
}

document.querySelector('#register')?.addEventListener('click', () => void run(async () => {
  await usePasskey('register');
  status.textContent = 'パスキーを追加しました。';
}));
document.querySelector('#authenticate')?.addEventListener('click', () => void run(async () => {
  await usePasskey('authenticate');
  location.assign('/account');
}));
document.querySelector('#logout')?.addEventListener('click', () => void run(async () => {
  await post('/api/logout');
  location.assign('/');
}));
