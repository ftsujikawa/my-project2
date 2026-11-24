import { expect, test } from '@playwright/test';

test('register a passkey, sign in with it, and sign in with a password', async ({ page, context }) => {
  const cdp = await context.newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2', transport: 'internal', hasResidentKey: true,
      hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true,
    },
  });
  await page.goto('/');
  const email = 'user@example.test';
  const password = 'example-password';
  await page.getByLabel('メールアドレス').fill(email);
  await page.getByLabel('パスワード').fill(password);
  await page.getByRole('button', { name: 'アカウントを作成' }).click();
  await expect(page).toHaveURL('/account');
  await page.getByRole('button', { name: 'パスキーを追加' }).click();
  await expect(page.getByRole('status')).toHaveText('パスキーを追加しました。');
  await page.getByRole('button', { name: 'ログアウト' }).click();
  await expect(page).toHaveURL('/');
  await page.getByRole('button', { name: 'パスキーでログイン' }).click();
  await expect(page).toHaveURL('/account');
  const { credentials } = await cdp.send('WebAuthn.getCredentials', { authenticatorId });
  expect(credentials[0].signCount).toBeGreaterThan(0);
  await page.getByRole('button', { name: 'ログアウト' }).click();
  await page.getByLabel('メールアドレス').fill(email);
  await page.getByLabel('パスワード').fill(password);
  await page.getByRole('button', { name: 'ログイン', exact: true }).click();
  await expect(page).toHaveURL('/account');
});

test('sign in with a password after cancelling passkey sign-in', async ({ page }) => {
  await page.addInitScript(() => {
    navigator.credentials.get = async () => {
      throw new DOMException('Passkey prompt cancelled', 'NotAllowedError');
    };
  });
  await page.goto('/');
  const email = 'cancel-passkey@example.test';
  const password = 'example-password';
  const fillCredentials = async () => {
    await page.getByLabel('メールアドレス').fill(email);
    await page.getByLabel('パスワード').fill(password);
  };
  await fillCredentials();
  await page.getByRole('button', { name: 'アカウントを作成' }).click();
  await expect(page.getByText('次回のログインに使うパスキーを追加できます。')).toBeVisible();
  await page.getByRole('button', { name: 'ログアウト' }).click();
  await expect(page).toHaveURL('/');

  await page.getByRole('button', { name: 'パスキーでログイン' }).click();
  await expect(page.getByRole('status')).toHaveText('パスキー操作が中断されました。もう一度お試しください。');
  await expect(page).toHaveURL('/');
  await fillCredentials();
  await page.getByRole('button', { name: 'ログイン', exact: true }).click();
  await expect(page).toHaveURL('/account');
});
