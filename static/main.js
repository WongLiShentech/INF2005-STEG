// Live capacity readout on the protect page. The form still works without
// this: it is a plain multipart POST, and the server recomputes everything.

const coverInput = document.getElementById("cover-input");
if (coverInput) {
  const keyInput = document.getElementById("key-input");
  const depthInput = document.getElementById("depth-input");
  const messageInput = document.getElementById("message-input");
  const depthValue = document.getElementById("depth-value");
  const capacityValue = document.getElementById("capacity-value");
  const offsetValue = document.getElementById("offset-value");
  const describe = document.getElementById("cover-describe");
  const messageSize = document.getElementById("message-size");
  const encryptInput = document.getElementById("encrypt-input");
  const offsetInput = document.getElementById("offset-input");

  let capacities = null;
  let overhead = 0;
  let units = 0;
  let headerUnits = 0;

  const render = () => {
    depthValue.textContent = depthInput.value;
    if (!capacities) return;

    // A start location typed by hand changes the capacity, and we already
    // have everything needed to work it out without asking the server again.
    const depth = Number(depthInput.value);
    const manual = offsetInput && offsetInput.value.trim() !== "" ? Number(offsetInput.value) : null;
    let bytes = capacities[depthInput.value];
    if (manual !== null && Number.isFinite(manual) && manual >= 0 && units) {
      bytes = Math.max(0, Math.floor(((units - manual - headerUnits) * depth) / 8));
      offsetValue.textContent = manual.toLocaleString() + " (chosen)";
    }
    capacityValue.textContent = bytes.toLocaleString() + " bytes";
    // Encryption adds a nonce and an authentication tag, so what has to fit
    // is not what the user typed.
    const typed = new TextEncoder().encode(messageInput.value).length;
    const stored = typed && encryptInput && encryptInput.checked ? typed + overhead : typed;
    capacityValue.style.color = stored > bytes ? "#b3261e" : "";
  };

  const refresh = async () => {
    if (!coverInput.files.length || !keyInput.value.trim()) return;

    const body = new FormData();
    body.append("file", coverInput.files[0]);
    body.append("key", keyInput.value);

    const response = await fetch("/upload", { method: "POST", body });
    const data = await response.json();

    if (data.error) {
      describe.textContent = data.error;
      capacities = null;
      capacityValue.textContent = "—";
      offsetValue.textContent = "—";
      return;
    }

    capacities = data.capacity;
    overhead = data.encryption_overhead || 0;
    units = data.units || 0;
    headerUnits = data.header_units || 0;
    describe.textContent = data.describe;
    offsetValue.textContent = data.offset.toLocaleString();
    render();
  };

  coverInput.addEventListener("change", refresh);
  keyInput.addEventListener("change", refresh);
  depthInput.addEventListener("input", render);
  if (encryptInput) encryptInput.addEventListener("change", render);
  if (offsetInput) {
    offsetInput.addEventListener("input", () => {
      if (offsetInput.value.trim() === "" && capacities) refresh();
      render();
    });
  }
  messageInput.addEventListener("input", () => {
    messageSize.textContent = new TextEncoder().encode(messageInput.value).length.toLocaleString();
    render();
  });
}
