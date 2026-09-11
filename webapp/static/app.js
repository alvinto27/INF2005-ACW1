document.querySelector('#decode-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const result = document.querySelector('#result');
  result.textContent = 'Verifying…';
  const response = await fetch('/decode', { method: 'POST', body: new FormData(event.target) });
  result.textContent = JSON.stringify(await response.json(), null, 2);
});
