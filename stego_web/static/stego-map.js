import * as THREE from 'three';
import {OrbitControls} from './vendor/three/OrbitControls.js';
import {
  DEFAULT_BOOTSTRAP_UNITS,
  carrierRangeToPixelRectangles,
  firstSelectablePixelUnit,
  pixelToStartUnit,
  startUnitToPixel,
  uvToPixel,
} from './stego-map-geometry.js';

const form = document.querySelector('#encode-form');

function formatNumber(value) {
  return Number.isFinite(value) ? new Intl.NumberFormat().format(value) : '—';
}

function formatBytes(value) {
  if (!Number.isFinite(value)) return '—';
  if (value < 1024) return `${value} B`;
  if (value < 1024 ** 2) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / 1024 ** 2).toFixed(1)} MB`;
}

async function imageSource(file) {
  if ('createImageBitmap' in window) return createImageBitmap(file);
  const url = URL.createObjectURL(file);
  try {
    const image = new Image();
    image.src = url;
    await image.decode();
    return image;
  } finally {
    URL.revokeObjectURL(url);
  }
}

class StegoImageMap {
  constructor(encodeForm) {
    this.form = encodeForm;
    this.coverInput = document.querySelector('#cover-input');
    this.receiverInput = document.querySelector('#receiver-public-key');
    this.startInput = document.querySelector('#start-unit');
    this.lsbInput = document.querySelector('#encode-lsb');
    this.panel = document.querySelector('#stego-map-panel');
    this.stage = document.querySelector('#stego-map-stage');
    this.fallback = document.querySelector('#stego-map-fallback');
    this.status = document.querySelector('#stego-map-status');
    this.manual = document.querySelector('#manual-placement');
    this.wavNote = document.querySelector('#wav-layout-note');
    this.resetButton = document.querySelector('#stego-map-reset');
    this.modeButtons = [...document.querySelectorAll('[data-map-mode]')];
    this.mode = 'normal';
    this.width = 0;
    this.height = 0;
    this.totalUnits = 0;
    this.bootstrapUnits = DEFAULT_BOOTSTRAP_UNITS;
    this.selectedUnit = null;
    this.imageData = null;
    this.estimate = null;
    this.estimateTimer = null;
    this.estimateRequest = null;
    this.pointerStart = null;
    this.webglReady = false;
    this.loadToken = 0;
    this.bindEvents();
    this.initialiseScene();
  }

  bindEvents() {
    this.coverInput.addEventListener('change', () => this.loadCover(this.coverInput.files[0]));
    this.startInput.addEventListener('input', () => this.readManualStart());
    this.lsbInput.addEventListener('input', () => {
      this.updateBitInspector();
      this.scheduleEstimate();
    });
    this.resetButton.addEventListener('click', () => this.reset());
    this.modeButtons.forEach(button => button.addEventListener('click', () => {
      if (!button.disabled) this.setMode(button.dataset.mapMode);
    }));
    this.stage.addEventListener('pointermove', event => this.inspectPointer(event));
    this.stage.addEventListener('pointerleave', () => this.clearHover());
    this.stage.addEventListener('pointerdown', event => {
      this.pointerStart = {x: event.clientX, y: event.clientY};
    });
    this.stage.addEventListener('pointerup', event => this.selectPointer(event));
    this.stage.addEventListener('keydown', event => this.handleKeyboard(event));

    const geometryInputs = this.form.querySelectorAll(
      '#receiver-public-key, #payload-file, #secret-message, #payload-mime, #payload-name, [name="team_id"], [name="sender"], [name="metadata"]',
    );
    geometryInputs.forEach(input => {
      input.addEventListener(input.type === 'file' ? 'change' : 'input', () => this.scheduleEstimate());
    });
    window.addEventListener('stego:encoded', event => this.loadDifference(event.detail));
    window.addEventListener('stego:reset', () => this.loadCover(null));
  }

  initialiseScene() {
    try {
      this.renderer = new THREE.WebGLRenderer({antialias: true, alpha: true, powerPreference: 'high-performance'});
      this.renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
      this.renderer.outputColorSpace = THREE.SRGBColorSpace;
      this.renderer.domElement.setAttribute('aria-hidden', 'true');
      this.scene = new THREE.Scene();
      this.camera = new THREE.PerspectiveCamera(38, 1, 0.01, 1000);
      this.camera.position.set(0, 0, 10);
      this.controls = new OrbitControls(this.camera, this.renderer.domElement);
      this.controls.enableDamping = false;
      this.controls.screenSpacePanning = true;
      this.controls.minDistance = 1;
      this.controls.maxDistance = 50;
      this.controls.minPolarAngle = Math.PI / 2 - 0.65;
      this.controls.maxPolarAngle = Math.PI / 2 + 0.65;
      this.controls.minAzimuthAngle = -0.8;
      this.controls.maxAzimuthAngle = 0.8;
      this.controls.addEventListener('change', () => this.render());
      this.raycaster = new THREE.Raycaster();
      this.pointer = new THREE.Vector2();
      this.planeGroup = new THREE.Group();
      this.planeGroup.rotation.set(-0.06, -0.12, 0);
      this.scene.add(this.planeGroup);
      this.reservedGroup = new THREE.Group();
      this.footprintGroup = new THREE.Group();
      this.planeGroup.add(this.reservedGroup, this.footprintGroup);
      this.stage.append(this.renderer.domElement);
      this.resizeObserver = new ResizeObserver(() => this.resize());
      this.resizeObserver.observe(this.stage);
      this.webglReady = true;
      this.fallback.hidden = true;
      this.resize();
    } catch (error) {
      this.webglReady = false;
      this.fallback.hidden = false;
      this.fallback.textContent = 'WebGL is unavailable. Use the manual start-unit field below; encoding still works normally.';
      this.status.textContent = `3D viewer unavailable: ${error.message}`;
      this.manual.open = true;
    }
  }

  async loadCover(file) {
    const token = ++this.loadToken;
    const isPng = Boolean(file && (file.type === 'image/png' || file.name.toLowerCase().endsWith('.png')));
    const isWav = Boolean(file && (file.type === 'audio/wav' || file.name.toLowerCase().endsWith('.wav')));
    this.panel.hidden = !isPng;
    this.wavNote.hidden = !isWav;
    this.manual.open = !isPng || !this.webglReady;
    this.clearEstimate();
    this.clearDifference();
    this.clearImagePlane();
    if (!file || !isPng) {
      if (isWav) {
        this.startInput.value = String(DEFAULT_BOOTSTRAP_UNITS);
        this.startInput.setCustomValidity('');
      }
      return;
    }

    this.status.textContent = 'Reading PNG dimensions and pixels locally…';
    try {
      const source = await imageSource(file);
      if (token !== this.loadToken) {
        source.close?.();
        return;
      }
      const canvas = document.createElement('canvas');
      canvas.width = source.width;
      canvas.height = source.height;
      const context = canvas.getContext('2d', {willReadFrequently: true});
      if (!context) throw new Error('2D canvas is unavailable');
      context.drawImage(source, 0, 0);
      source.close?.();
      this.width = canvas.width;
      this.height = canvas.height;
      this.totalUnits = this.width * this.height * 3;
      this.imageData = context.getImageData(0, 0, this.width, this.height);
      document.querySelector('#map-total-units').textContent = formatNumber(this.totalUnits);
      if (this.webglReady) {
        this.fallback.hidden = true;
        this.createImagePlane(canvas);
      }
      const firstUnit = firstSelectablePixelUnit(this.bootstrapUnits, this.width, this.height);
      if (firstUnit === null) {
        this.startInput.value = '';
        this.startInput.setCustomValidity('This PNG is too small for the receiver bootstrap.');
        this.status.textContent = 'This PNG has no selectable pixel after the reserved bootstrap region.';
        return;
      }
      this.setSelection(firstUnit, {writeInput: true, estimate: true});
      this.status.textContent = this.canEstimate()
        ? 'Checking this location against the protocol…'
        : 'Defaulted to the first selectable pixel. Complete the payload and receiver steps for exact capacity.';
    } catch (error) {
      this.fallback.hidden = false;
      this.fallback.textContent = 'The PNG preview could not be loaded. Use manual placement; the server will still validate the carrier.';
      this.status.textContent = `Map preview unavailable: ${error.message}`;
      this.manual.open = true;
    }
  }

  createImagePlane(canvas) {
    this.disposeObject(this.imageMesh);
    this.clearGroup(this.reservedGroup);
    this.clearGroup(this.footprintGroup);
    this.disposeObject(this.marker);
    const scale = 8 / Math.max(this.width, this.height);
    this.planeWidth = this.width * scale;
    this.planeHeight = this.height * scale;
    this.imageTexture?.dispose();
    this.imageTexture = new THREE.CanvasTexture(canvas);
    this.imageTexture.colorSpace = THREE.SRGBColorSpace;
    this.imageTexture.minFilter = THREE.LinearFilter;
    const geometry = new THREE.PlaneGeometry(this.planeWidth, this.planeHeight);
    const material = new THREE.MeshBasicMaterial({map: this.imageTexture, side: THREE.DoubleSide});
    this.imageMesh = new THREE.Mesh(geometry, material);
    this.imageMesh.renderOrder = 0;
    this.planeGroup.add(this.imageMesh);
    this.drawRange(this.reservedGroup, 0, Math.min(this.bootstrapUnits, this.totalUnits), 0xa99bff, 0.44, 0.012);

    const pixelSize = Math.max(this.planeWidth / this.width, this.planeHeight / this.height);
    this.marker = new THREE.Mesh(
      new THREE.RingGeometry(Math.max(pixelSize * 2.5, 0.045), Math.max(pixelSize * 3.8, 0.072), 32),
      new THREE.MeshBasicMaterial({color: 0xffd166, transparent: true, opacity: 0.98, depthTest: false, side: THREE.DoubleSide}),
    );
    this.marker.position.z = 0.045;
    this.marker.renderOrder = 4;
    this.marker.visible = false;
    this.planeGroup.add(this.marker);
    this.fitCamera();
    this.render();
  }

  fitCamera() {
    if (!this.webglReady || !this.planeWidth) return;
    const vertical = THREE.MathUtils.degToRad(this.camera.fov);
    const heightDistance = this.planeHeight / (2 * Math.tan(vertical / 2));
    const widthDistance = this.planeWidth / (2 * Math.tan(vertical / 2) * this.camera.aspect);
    const distance = Math.max(heightDistance, widthDistance) * 1.3;
    this.camera.position.set(0, 0, Math.max(distance, 1.4));
    this.controls.target.set(0, 0, 0);
    this.controls.maxDistance = Math.max(distance * 8, 12);
    this.controls.update();
    this.controls.saveState();
    this.render();
  }

  resize() {
    if (!this.webglReady) return;
    const width = Math.max(1, this.stage.clientWidth);
    const height = Math.max(1, this.stage.clientHeight);
    this.renderer.setSize(width, height, false);
    this.camera.aspect = width / height;
    this.camera.updateProjectionMatrix();
    this.render();
  }

  render() {
    if (this.webglReady) this.renderer.render(this.scene, this.camera);
  }

  pointerPixel(event) {
    if (!this.webglReady || !this.imageMesh) return null;
    const bounds = this.renderer.domElement.getBoundingClientRect();
    if (!bounds.width || !bounds.height) return null;
    this.pointer.x = ((event.clientX - bounds.left) / bounds.width) * 2 - 1;
    this.pointer.y = -((event.clientY - bounds.top) / bounds.height) * 2 + 1;
    this.raycaster.setFromCamera(this.pointer, this.camera);
    const hit = this.raycaster.intersectObject(this.imageMesh, false)[0];
    if (!hit?.uv) return null;
    return uvToPixel(hit.uv.x, hit.uv.y, this.width, this.height);
  }

  inspectPointer(event) {
    const pixel = this.pointerPixel(event);
    if (!pixel || !this.imageData) {
      this.clearHover();
      return;
    }
    const offset = (pixel.y * this.width + pixel.x) * 4;
    const rgb = [...this.imageData.data.slice(offset, offset + 3)];
    document.querySelector('#map-hover-pixel').textContent = `${pixel.x}, ${pixel.y}`;
    document.querySelector('#map-hover-index').textContent = formatNumber(pixel.y * this.width + pixel.x);
    document.querySelector('#map-hover-unit').textContent = formatNumber(pixelToStartUnit(pixel.x, pixel.y, this.width, this.height));
    document.querySelector('#map-hover-rgb').textContent = rgb.join(' / ');
    this.hoverRgb = rgb;
    this.updateBitInspector();
  }

  clearHover() {
    document.querySelector('#map-hover-pixel').textContent = '—';
    document.querySelector('#map-hover-index').textContent = '—';
    document.querySelector('#map-hover-unit').textContent = '—';
    document.querySelector('#map-hover-rgb').textContent = '—';
    this.hoverRgb = null;
    document.querySelector('#map-bit-plane').textContent = 'Move over the image to inspect its RGB channels.';
  }

  updateBitInspector() {
    if (!this.hoverRgb) return;
    const lsb = Number(this.lsbInput.value);
    const bits = this.hoverRgb.map(value => value.toString(2).padStart(8, '0')).join(' · ');
    document.querySelector('#map-bit-plane').textContent = `${bits} — final ${lsb} bit${lsb === 1 ? '' : 's'} per channel may carry packet data.`;
  }

  selectPointer(event) {
    if (event.button !== 0 || !this.pointerStart) return;
    const movement = Math.hypot(event.clientX - this.pointerStart.x, event.clientY - this.pointerStart.y);
    this.pointerStart = null;
    if (movement > 5) return;
    const pixel = this.pointerPixel(event);
    if (!pixel) return;
    const startUnit = pixelToStartUnit(pixel.x, pixel.y, this.width, this.height);
    if (startUnit < this.bootstrapUnits) {
      this.status.textContent = `Pixel (${pixel.x}, ${pixel.y}) begins at unit ${formatNumber(startUnit)}, inside the reserved bootstrap region.`;
      this.stage.classList.remove('selection-rejected');
      void this.stage.offsetWidth;
      this.stage.classList.add('selection-rejected');
      return;
    }
    this.setSelection(startUnit, {writeInput: true, estimate: true});
  }

  handleKeyboard(event) {
    if (!['ArrowLeft', 'ArrowRight', 'ArrowUp', 'ArrowDown'].includes(event.key) || !this.width || this.selectedUnit === null) return;
    event.preventDefault();
    const pixel = startUnitToPixel(this.selectedUnit, this.width, this.height);
    const delta = {
      ArrowLeft: [-1, 0], ArrowRight: [1, 0], ArrowUp: [0, -1], ArrowDown: [0, 1],
    }[event.key];
    const x = Math.min(this.width - 1, Math.max(0, pixel.x + delta[0]));
    const y = Math.min(this.height - 1, Math.max(0, pixel.y + delta[1]));
    const unit = pixelToStartUnit(x, y, this.width, this.height);
    if (unit >= this.bootstrapUnits) this.setSelection(unit, {writeInput: true, estimate: true});
  }

  readManualStart() {
    const value = Number(this.startInput.value);
    this.startInput.setCustomValidity('');
    if (!Number.isInteger(value)) {
      this.selectedUnit = null;
      this.hideMarker();
      this.clearEstimate();
      this.status.textContent = 'No valid embedding location selected. Click the PNG or enter a start unit manually.';
      return;
    }
    if (value < this.bootstrapUnits) {
      this.startInput.setCustomValidity(`Packet start must be at least ${this.bootstrapUnits}.`);
      this.status.textContent = `Unit ${formatNumber(value)} is inside the reserved bootstrap region.`;
      this.hideMarker();
      return;
    }
    if (this.totalUnits && value >= this.totalUnits) {
      this.startInput.setCustomValidity('Packet start must be inside the carrier.');
      this.status.textContent = `Unit ${formatNumber(value)} is outside this ${formatNumber(this.totalUnits)}-unit carrier.`;
      this.hideMarker();
      return;
    }
    this.setSelection(value, {writeInput: false, estimate: true});
  }

  setSelection(startUnit, {writeInput, estimate}) {
    this.selectedUnit = startUnit;
    this.startInput.setCustomValidity('');
    if (writeInput) this.startInput.value = String(startUnit);
    document.querySelector('#map-selected-start').textContent = formatNumber(startUnit);
    if (this.width) {
      const pixel = startUnitToPixel(startUnit, this.width, this.height);
      document.querySelector('#map-selected-pixel').textContent = `${pixel.x}, ${pixel.y}`;
    }
    if (this.webglReady && this.marker && this.width) {
      const pixel = startUnitToPixel(startUnit, this.width, this.height);
      const position = this.pixelRectPosition({x: pixel.x, y: pixel.y, width: 1, height: 1});
      this.marker.position.x = position.x;
      this.marker.position.y = position.y;
      this.marker.visible = true;
      this.render();
    }
    this.status.textContent = `Selected unit ${formatNumber(startUnit)}. Calculating the contiguous packet footprint…`;
    if (estimate) this.scheduleEstimate();
  }

  hideMarker() {
    this.selectedUnit = null;
    document.querySelector('#map-selected-start').textContent = '—';
    document.querySelector('#map-selected-pixel').textContent = '—';
    if (this.marker) this.marker.visible = false;
    this.render();
  }

  canEstimate() {
    const hasPayload = Boolean(document.querySelector('#payload-file').files[0] || document.querySelector('#secret-message').value.trim());
    return Boolean(
      this.coverInput.files[0]
      && this.receiverInput.files[0]
      && hasPayload
      && this.form.elements.team_id.value.trim()
      && this.form.elements.sender.value.trim()
      && this.startInput.value,
    );
  }

  scheduleEstimate() {
    window.clearTimeout(this.estimateTimer);
    if (!this.canEstimate()) return;
    this.estimateTimer = window.setTimeout(() => this.requestEstimate(), 180);
  }

  layoutRequestData() {
    const body = new FormData();
    const cover = this.coverInput.files[0];
    const receiver = this.receiverInput.files[0];
    body.set('cover', cover, cover.name);
    body.set('receiver_public_key', receiver, receiver.name);
    const payloadFile = document.querySelector('#payload-file').files[0];
    if (payloadFile) body.set('payload_file', payloadFile, payloadFile.name);
    body.set('secret_message', document.querySelector('#secret-message').value);
    ['payload_mime', 'payload_name', 'team_id', 'sender', 'metadata', 'start_unit', 'lsb_bits'].forEach(name => {
      body.set(name, this.form.elements[name].value);
    });
    return body;
  }

  async requestEstimate() {
    this.estimateRequest?.abort();
    this.estimateRequest = new AbortController();
    this.status.textContent = 'Validating capacity with the protocol layout engine…';
    try {
      const response = await fetch('/layout/estimate', {
        method: 'POST',
        body: this.layoutRequestData(),
        signal: this.estimateRequest.signal,
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error ?? 'Layout estimate failed');
      this.estimate = data;
      this.bootstrapUnits = data.bootstrap_span;
      this.startInput.setCustomValidity('');
      document.querySelector('#map-total-units').textContent = formatNumber(data.total_units);
      document.querySelector('#map-selected-start').textContent = formatNumber(data.start_unit);
      document.querySelector('#map-footprint').textContent = `${formatNumber(data.footprint)} units`;
      document.querySelector('#map-available').textContent = formatNumber(data.available_after_start);
      document.querySelector('#map-remaining').textContent = formatNumber(data.remaining_units);
      document.querySelector('#map-capacity').textContent = `${formatBytes(data.payload_bytes)} / ${formatBytes(data.capacity_bytes)}`;
      document.querySelector('#map-usage').textContent = `${(data.usage_ratio * 100).toFixed(3)}%`;
      document.querySelector('#map-preserved').textContent = `${(data.preserved_ratio * 100).toFixed(4)}%`;
      if (data.media_type === 'image' && this.webglReady) {
        this.clearGroup(this.footprintGroup);
        this.drawRange(this.footprintGroup, data.start_unit, data.footprint, 0x62efb8, this.mode === 'embedding' ? 0.58 : 0.2, 0.025);
      }
      this.status.textContent = `Valid placement: units ${formatNumber(data.start_unit)}–${formatNumber(data.packet_end_unit - 1)}. ${(data.preserved_ratio * 100).toFixed(4)}% of carrier bits remain unchanged.`;
      this.render();
    } catch (error) {
      if (error.name === 'AbortError') return;
      this.estimate = null;
      this.clearGroup(this.footprintGroup);
      const spatialError = /start_unit|footprint|capacity|carrier cannot hold|record overhead/i.test(error.message);
      if (spatialError) this.startInput.setCustomValidity(error.message);
      this.status.textContent = `Layout not valid: ${error.message}`;
      document.querySelector('#map-footprint').textContent = 'Does not fit';
      document.querySelector('#map-available').textContent = '—';
      document.querySelector('#map-remaining').textContent = '—';
      document.querySelector('#map-capacity').textContent = '—';
      document.querySelector('#map-usage').textContent = '—';
      document.querySelector('#map-preserved').textContent = '—';
      this.render();
    }
  }

  pixelRectPosition(rectangle) {
    return {
      x: -this.planeWidth / 2 + ((rectangle.x + rectangle.width / 2) / this.width) * this.planeWidth,
      y: this.planeHeight / 2 - ((rectangle.y + rectangle.height / 2) / this.height) * this.planeHeight,
      width: (rectangle.width / this.width) * this.planeWidth,
      height: (rectangle.height / this.height) * this.planeHeight,
    };
  }

  drawRange(group, startUnit, footprint, colour, opacity, z) {
    const rectangles = carrierRangeToPixelRectangles(startUnit, footprint, this.width, this.height);
    rectangles.forEach(rectangle => {
      const position = this.pixelRectPosition(rectangle);
      const mesh = new THREE.Mesh(
        new THREE.PlaneGeometry(position.width, position.height),
        new THREE.MeshBasicMaterial({color: colour, transparent: true, opacity, depthTest: false, side: THREE.DoubleSide}),
      );
      mesh.position.set(position.x, position.y, z);
      mesh.renderOrder = 2;
      group.add(mesh);
    });
  }

  setMode(mode) {
    this.mode = mode;
    this.modeButtons.forEach(button => {
      const active = button.dataset.mapMode === mode;
      button.classList.toggle('is-active', active);
      button.setAttribute('aria-pressed', String(active));
    });
    this.footprintGroup.children.forEach(mesh => {
      mesh.material.opacity = mode === 'embedding' ? 0.58 : 0.2;
    });
    if (this.differenceMesh) this.differenceMesh.visible = mode === 'difference';
    const modeNote = document.querySelector('#map-mode-note');
    if (mode === 'difference') {
      modeNote.textContent = 'Difference visualization exaggerates pixels whose RGB carrier values changed after encoding.';
      this.status.textContent = 'Difference mode highlights pixels changed by the completed encode.';
    } else if (mode === 'embedding') {
      modeNote.textContent = 'Embedding visualization exaggerates the exact contiguous packet region; it is not a prediction of visible distortion.';
      if (this.estimate) this.status.textContent = 'Showing the exact contiguous packet region.';
    } else {
      modeNote.textContent = 'Normal view keeps the exact packet footprint subtle.';
      if (this.estimate) this.status.textContent = 'Showing the carrier with a light footprint overlay.';
    }
    this.render();
  }

  async loadDifference(detail) {
    if (!detail || detail.mediaType !== 'image' || !this.imageData) return;
    const token = this.loadToken;
    try {
      const binary = atob(detail.stegoBase64);
      const bytes = Uint8Array.from(binary, character => character.charCodeAt(0));
      const source = await imageSource(new Blob([bytes], {type: detail.mimeType || 'image/png'}));
      if (token !== this.loadToken) {
        source.close?.();
        return;
      }
      if (source.width !== this.width || source.height !== this.height) {
        source.close?.();
        throw new Error('encoded image dimensions changed');
      }
      const outputCanvas = document.createElement('canvas');
      outputCanvas.width = this.width;
      outputCanvas.height = this.height;
      const outputContext = outputCanvas.getContext('2d', {willReadFrequently: true});
      outputContext.drawImage(source, 0, 0);
      source.close?.();
      const encoded = outputContext.getImageData(0, 0, this.width, this.height);
      const differenceCanvas = document.createElement('canvas');
      differenceCanvas.width = this.width;
      differenceCanvas.height = this.height;
      const differenceContext = differenceCanvas.getContext('2d');
      const difference = differenceContext.createImageData(this.width, this.height);
      let changedPixels = 0;
      for (let index = 0; index < encoded.data.length; index += 4) {
        const delta = Math.max(
          Math.abs(encoded.data[index] - this.imageData.data[index]),
          Math.abs(encoded.data[index + 1] - this.imageData.data[index + 1]),
          Math.abs(encoded.data[index + 2] - this.imageData.data[index + 2]),
        );
        if (!delta) continue;
        changedPixels += 1;
        difference.data[index] = 255;
        difference.data[index + 1] = 86;
        difference.data[index + 2] = 118;
        difference.data[index + 3] = Math.min(235, 105 + delta * 16);
      }
      differenceContext.putImageData(difference, 0, 0);
      this.clearDifference();
      this.differenceTexture = new THREE.CanvasTexture(differenceCanvas);
      this.differenceMesh = new THREE.Mesh(
        new THREE.PlaneGeometry(this.planeWidth, this.planeHeight),
        new THREE.MeshBasicMaterial({map: this.differenceTexture, transparent: true, depthTest: false, side: THREE.DoubleSide}),
      );
      this.differenceMesh.position.z = 0.038;
      this.differenceMesh.renderOrder = 3;
      this.differenceMesh.visible = false;
      this.planeGroup.add(this.differenceMesh);
      const button = this.modeButtons.find(item => item.dataset.mapMode === 'difference');
      button.disabled = false;
      button.title = `${formatNumber(changedPixels)} pixels differ from the cover`;
      this.render();
    } catch (error) {
      this.status.textContent = `Difference view unavailable: ${error.message}`;
    }
  }

  clearDifference() {
    if (this.differenceMesh) {
      this.disposeObject(this.differenceMesh);
      this.differenceMesh = null;
    }
    this.differenceTexture?.dispose();
    this.differenceTexture = null;
    const button = this.modeButtons.find(item => item.dataset.mapMode === 'difference');
    if (button) button.disabled = true;
    if (this.mode === 'difference') this.setMode('normal');
  }

  clearImagePlane() {
    this.disposeObject(this.imageMesh);
    this.imageMesh = null;
    this.imageTexture?.dispose();
    this.imageTexture = null;
    this.disposeObject(this.marker);
    this.marker = null;
    this.clearGroup(this.reservedGroup);
    this.clearGroup(this.footprintGroup);
    this.imageData = null;
    this.hoverRgb = null;
    this.width = 0;
    this.height = 0;
    this.totalUnits = 0;
    this.selectedUnit = null;
    document.querySelector('#map-total-units').textContent = '—';
    document.querySelector('#map-selected-pixel').textContent = '—';
    document.querySelector('#map-selected-start').textContent = '—';
    this.render();
  }

  reset() {
    if (!this.width) {
      this.startInput.value = String(DEFAULT_BOOTSTRAP_UNITS);
      this.startInput.setCustomValidity('');
      return;
    }
    this.controls?.reset();
    const firstUnit = firstSelectablePixelUnit(this.bootstrapUnits, this.width, this.height);
    if (firstUnit !== null) this.setSelection(firstUnit, {writeInput: true, estimate: true});
    this.setMode('normal');
  }

  clearEstimate() {
    this.estimateRequest?.abort();
    this.estimate = null;
    ['#map-footprint', '#map-available', '#map-remaining', '#map-capacity', '#map-usage', '#map-preserved'].forEach(selector => {
      document.querySelector(selector).textContent = '—';
    });
    if (this.footprintGroup) this.clearGroup(this.footprintGroup);
  }

  clearGroup(group) {
    if (!group) return;
    while (group.children.length) {
      const child = group.children[0];
      group.remove(child);
      child.geometry?.dispose();
      if (Array.isArray(child.material)) child.material.forEach(material => material.dispose());
      else child.material?.dispose();
    }
  }

  disposeObject(object) {
    if (!object) return;
    object.parent?.remove(object);
    object.geometry?.dispose();
    if (Array.isArray(object.material)) object.material.forEach(material => material.dispose());
    else object.material?.dispose();
  }
}

if (form) {
  window.StegoImageMap = new StegoImageMap(form);
}
