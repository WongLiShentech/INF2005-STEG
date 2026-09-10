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

  let capacities = null;

  const render = () => {
    depthValue.textContent = depthInput.value;
    if (!capacities) return;
    const bytes = capacities[depthInput.value];
    capacityValue.textContent = bytes.toLocaleString() + " bytes";
    const typed = new TextEncoder().encode(messageInput.value).length;
    capacityValue.style.color = typed > bytes ? "#b3261e" : "";
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
    describe.textContent = data.describe;
    offsetValue.textContent = data.offset.toLocaleString();
    render();
  };

  coverInput.addEventListener("change", refresh);
  keyInput.addEventListener("change", refresh);
  depthInput.addEventListener("input", render);
  messageInput.addEventListener("input", () => {
    messageSize.textContent = new TextEncoder().encode(messageInput.value).length.toLocaleString();
    render();
  });
}
