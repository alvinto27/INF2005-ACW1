const encodeForm = document.querySelector("#encode-form");
const decodeForm = document.querySelector("#decode-form");

for (const prefix of ["encode", "decode"]) {
  const slider = document.querySelector(`#${prefix}-lsb`);
  const output = document.querySelector(`#${prefix}-lsb-output`);
  slider.addEventListener("input", () => { output.value = slider.value; });
}

encodeForm.cover.addEventListener("change", () => {
  const file = encodeForm.cover.files[0];
  if (file) renderMedia(document.querySelector("#cover-preview"), URL.createObjectURL(file), file.type);
});

encodeForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const resultBox = document.querySelector("#encode-result");
  resultBox.textContent = "Signing and embedding…";
  try {
    const response = await fetch("/encode", { method: "POST", body: new FormData(encodeForm) });
    const data = await response.json();
    if (!response.ok) return showError(resultBox, data.error ?? "Encode failed");

    const stegoUrl = base64Url(data.stego_base64, data.mime_type);
    renderMedia(document.querySelector("#stego-preview"), stegoUrl, data.mime_type);
    resultBox.replaceChildren(
      textLine(`Embedded at channel ${data.start_location}; capacity ${data.capacity_bytes} bytes.`),
      downloadLink(stegoUrl, data.filename, "Download stego media"),
      downloadLink(textUrl(data.public_key_pem), "public-key.pem", "Download public key"),
      downloadLink(textUrl(data.private_key_pem), "private-key.pem", "Download encrypted private key"),
    );
  } catch (error) {
    showError(resultBox, error.message);
  }
});

decodeForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const resultBox = document.querySelector("#decode-result");
  resultBox.textContent = "Extracting and verifying…";
  try {
    const response = await fetch("/decode", { method: "POST", body: new FormData(decodeForm) });
    const data = await response.json();
    resultBox.className = `result verdict-${slug(data.verdict || "error")}`;
    resultBox.textContent = `${data.verdict || "Error"}: ${data.message || data.error}`;
    if (data.payload) {
      const details = document.createElement("pre");
      details.textContent = JSON.stringify(data.payload, null, 2);
      resultBox.append(details);
    }
  } catch (error) {
    showError(resultBox, error.message);
  }
});

function renderMedia(container, url, mime) {
  const element = document.createElement(mime.startsWith("audio/") ? "audio" : "img");
  element.src = url;
  element.controls = mime.startsWith("audio/");
  element.alt = "Selected media preview";
  container.replaceChildren(element);
}

function base64Url(value, mime) {
  const bytes = Uint8Array.from(atob(value), character => character.charCodeAt(0));
  return URL.createObjectURL(new Blob([bytes], { type: mime }));
}

function textUrl(value) {
  return URL.createObjectURL(new Blob([value], { type: "application/x-pem-file" }));
}

function downloadLink(url, filename, label) {
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.textContent = label;
  return link;
}

function textLine(value) {
  const paragraph = document.createElement("p");
  paragraph.textContent = value;
  return paragraph;
}

function showError(container, message) {
  container.className = "result verdict-error";
  container.textContent = `Error: ${message}`;
}

function slug(value) {
  return value.toLowerCase().replaceAll(" ", "-");
}
