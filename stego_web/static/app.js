/* Frontend-only wizard controller. The encode request is the integration seam. */
const encodeForm = document.querySelector("#encode-form");
const cards = [...document.querySelectorAll(".wizard-card")];
const progressBar = document.querySelector("#progress-bar");
const stepCount = document.querySelector("#step-count");
let currentStep = 0;

function showStep(nextStep) {
  currentStep = nextStep;
  cards.forEach((card, index) => { const active = index === currentStep; card.hidden = !active; card.classList.toggle("is-active", active); });
  stepCount.textContent = currentStep <= 4 ? `Step ${currentStep + 1} of 5` : "Complete";
  progressBar.style.width = `${Math.min(100, ((currentStep + 1) / 5) * 100)}%`;
  cards[currentStep].querySelector("input, textarea, button")?.focus();
}

function validCurrentCard() {
  for (const field of cards[currentStep].querySelectorAll("[required]")) { if (!field.checkValidity()) { field.reportValidity(); return false; } }
  return true;
}

async function simulate(card, status, detail, completeStatus, completeDetail) {
  card.querySelector(".next").disabled = true; card.classList.add("is-busy");
  status.textContent = "Working…"; detail.textContent = "Preparing a secure request for the backend.";
  await new Promise(resolve => setTimeout(resolve, 850));
  status.textContent = completeStatus; detail.textContent = completeDetail;
  card.querySelector(".next").disabled = false; card.classList.remove("is-busy");
}

document.querySelectorAll(".next").forEach(button => button.addEventListener("click", async () => {
  if (!validCurrentCard()) return;
  if (currentStep === 1) await simulate(cards[1], document.querySelector("#payload-status"), document.querySelector("#payload-detail"), "Payload initialized", "Hash and metadata are ready for signing.");
  if (currentStep === 2) await simulate(cards[2], document.querySelector("#signature-status"), document.querySelector("#signature-detail"), "Signature ready", "The backend will sign the exact payload bytes during encoding.");
  showStep(currentStep + 1);
}));
document.querySelectorAll(".back").forEach(button => button.addEventListener("click", () => showStep(Math.max(0, currentStep - 1))));

document.querySelector("#cover-input").addEventListener("change", event => {
  const file = event.target.files[0]; document.querySelector("#cover-name").textContent = file ? file.name : "Choose a PNG or WAV file";
  if (file) renderMedia(document.querySelector("#cover-preview"), URL.createObjectURL(file), file.type);
});
const lsb = document.querySelector("#encode-lsb");
lsb.addEventListener("input", () => { document.querySelector("#encode-lsb-output").value = lsb.value; });

document.querySelector("#derive-location").addEventListener("click", async () => {
  const secret = document.querySelector("#start-secret"); const status = document.querySelector("#location-status");
  if (!secret.checkValidity()) { secret.reportValidity(); return; }
  const file = document.querySelector("#cover-input").files[0];
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`${secret.value}|${file?.name ?? "cover"}|${lsb.value}`));
  const preview = 1 + (new DataView(digest).getUint32(0) % 9999);
  status.className = "status-box status-ready"; status.textContent = `Preview location: unit ${preview}. The backend will derive and enforce the authoritative value.`;
  document.querySelector("[data-step='3'] .next").disabled = false;
});

encodeForm.addEventListener("submit", async event => {
  event.preventDefault(); if (!validCurrentCard()) return;
  const resultBox = document.querySelector("#encode-result"); const button = encodeForm.querySelector("[type='submit']"); button.disabled = true; resultBox.textContent = "Signing payload and embedding media…";
  try {
    const response = await fetch("/encode", { method: "POST", body: new FormData(encodeForm) }); const data = await response.json();
    if (!response.ok) throw new Error(data.error ?? "Encode failed");
    const stegoUrl = base64Url(data.stego_base64, data.mime_type); renderMedia(document.querySelector("#stego-preview"), stegoUrl, data.mime_type);
    document.querySelector("#success-summary").textContent = `Embedded at unit ${data.start_location}; capacity ${data.capacity_bytes} bytes.`;
    document.querySelector("#download-links").replaceChildren(downloadLink(stegoUrl, data.filename, "Download stego media"), downloadLink(textUrl(data.public_key_pem), "public-key.pem", "Download public key"), downloadLink(textUrl(data.private_key_pem), "private-key.pem", "Download encrypted private key"));
    resultBox.textContent = ""; showStep(5);
  } catch (error) { resultBox.className = "result verdict-error"; resultBox.textContent = `Error: ${error.message}`; } finally { button.disabled = false; }
});

document.querySelector("#start-over").addEventListener("click", () => { encodeForm.reset(); document.querySelector("#encode-lsb-output").value = "1"; document.querySelector("#location-status").textContent = "No location derived yet."; document.querySelector("#location-status").className = "status-box"; showStep(0); });

const decodeForm = document.querySelector("#decode-form");
decodeForm.addEventListener("submit", async event => {
  event.preventDefault(); const resultBox = document.querySelector("#decode-result"); resultBox.textContent = "Extracting and verifying…";
  try { const response = await fetch("/decode", { method: "POST", body: new FormData(decodeForm) }); const data = await response.json(); resultBox.className = `result verdict-${slug(data.verdict || "error")}`; resultBox.textContent = `${data.verdict || "Error"}: ${data.message || data.error}`; if (data.payload) { const details = document.createElement("pre"); details.textContent = JSON.stringify(data.payload, null, 2); resultBox.append(details); } }
  catch (error) { resultBox.className = "result verdict-error"; resultBox.textContent = `Error: ${error.message}`; }
});

function renderMedia(container, url, mime) { const element = document.createElement(mime.startsWith("audio/") ? "audio" : "img"); element.src = url; element.controls = mime.startsWith("audio/"); element.alt = "Media preview"; container.replaceChildren(element); }
function base64Url(value, mime) { const bytes = Uint8Array.from(atob(value), character => character.charCodeAt(0)); return URL.createObjectURL(new Blob([bytes], { type: mime })); }
function textUrl(value) { return URL.createObjectURL(new Blob([value], { type: "application/x-pem-file" })); }
function downloadLink(url, filename, label) { const link = document.createElement("a"); link.href = url; link.download = filename; link.textContent = label; return link; }
function slug(value) { return value.toLowerCase().replaceAll(" ", "-"); }
