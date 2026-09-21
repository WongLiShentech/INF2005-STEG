/* Sound level: the original and the stego file side by side.

   A wave that sits low when the music is soft and rises when it is loud,
   drawn for both files over a fixed stretch around the payload: a lead-in
   where they are identical, the payload itself in a box, and a tail where
   they are identical again. On the stego chart the original is laid over the
   top as a dashed line, and every gap between them is filled — red where the
   payload made that moment louder, blue where it made it quieter.

   Nothing scrolls. Only the playhead moves, so a difference can be studied
   rather than watched go past, and pointing at any moment shows the exact
   values from both files.

   Both WAVs are read as integers, so every value is a real sample. */

(function (root) {
  'use strict';

  const COLOUR = {
    ink: '#08120e',
    grid: 'rgba(120,220,175,0.07)',
    axis: 'rgba(120,220,175,0.25)',
    label: 'rgba(205,235,222,0.55)',
    cover: '#3ef2a0',
    stego: '#ffb454',
    higher: '#ff5a4e',
    lower: '#4ea8ff',
    box: 'rgba(255,214,102,0.95)',
  };

  const HOP = 16;       // frames per precomputed moment
  const STEP = 3;       // CSS pixels between drawn moments

  let sharedContext = null;
  function audioContext() {
    if (!sharedContext) {
      const Context = root.AudioContext || root.webkitAudioContext;
      sharedContext = new Context();
    }
    return sharedContext;
  }

  function parseWav(buffer) {
    const view = new DataView(buffer);
    const tag = at => String.fromCharCode(
      view.getUint8(at), view.getUint8(at + 1), view.getUint8(at + 2), view.getUint8(at + 3));
    if (view.byteLength < 12 || tag(0) !== 'RIFF' || tag(8) !== 'WAVE') {
      throw new Error('not a WAV file');
    }

    let at = 12, format = null, data = null;
    while (at + 8 <= view.byteLength) {
      const id = tag(at), size = view.getUint32(at + 4, true), body = at + 8;
      if (id === 'fmt ') {
        format = {
          channels: view.getUint16(body + 2, true),
          rate: view.getUint32(body + 4, true),
          bits: view.getUint16(body + 14, true),
        };
      } else if (id === 'data') {
        data = {start: body, size: Math.min(size, view.byteLength - body)};
      }
      at = body + size + (size & 1);          // chunks are word-aligned
    }
    if (!format || !data) throw new Error('the WAV file has no format or no data');

    const width = format.bits / 8;
    const count = Math.floor(data.size / width);
    let samples, full;
    if (format.bits === 16) {
      samples = new Int16Array(count);
      for (let i = 0; i < count; i += 1) samples[i] = view.getInt16(data.start + i * 2, true);
      full = 32768;
    } else if (format.bits === 8) {
      // 8-bit PCM is unsigned on disk; centring it makes zero mean silence.
      samples = new Int16Array(count);
      for (let i = 0; i < count; i += 1) samples[i] = view.getUint8(data.start + i) - 128;
      full = 128;
    } else if (format.bits === 32) {
      samples = new Int32Array(count);
      for (let i = 0; i < count; i += 1) samples[i] = view.getInt32(data.start + i * 4, true);
      full = 2147483648;
    } else {
      throw new Error(format.bits + '-bit audio is not supported by the monitor');
    }

    return {
      channels: format.channels,
      rate: format.rate,
      bits: format.bits,
      full: full,
      samples: samples,
      frames: Math.floor(count / format.channels),
    };
  }

  /* Loudness for the sound-level charts. In each run of HOP frames, find the
     loudest sample of the original; its size is how loud that moment is. The
     change is how much the stego file altered the size of that same sample:
     positive if the payload made it louder, negative if quieter. */
  function levelTrack(original, stego) {
    const a = original.samples, b = stego.samples;
    const span = HOP * original.channels;
    const buckets = Math.ceil(a.length / span);
    const level = new Float32Array(buckets), change = new Float32Array(buckets);
    let peak = 0, worst = 0;
    for (let k = 0; k < buckets; k += 1) {
      const from = k * span, to = Math.min(from + span, a.length);
      let loudest = from;
      for (let i = from; i < to; i += 1) {
        if (Math.abs(a[i]) > Math.abs(a[loudest])) loudest = i;
      }
      const size = Math.abs(a[loudest]);
      const delta = Math.abs(b[loudest]) - size;
      level[k] = size;
      change[k] = delta;
      if (size > peak) peak = size;
      if (Math.abs(delta) > worst) worst = Math.abs(delta);
    }
    return {level, change, peak: peak || 1, worst, buckets};
  }

  /* Enough magnification that the largest change is clearly visible against
     the loudest moment, rounded to a 1-2-5 step so it reads as a chosen
     number. */
  function levelGain(peak, worst) {
    if (!worst) return 1;
    const raw = (peak * 0.45) / worst;
    if (raw <= 1) return 1;
    const scale = Math.pow(10, Math.floor(Math.log10(raw)));
    const lead = raw / scale;
    return (lead >= 5 ? 5 : lead >= 2 ? 2 : 1) * scale;
  }

  function clock(seconds) {
    const safe = Math.max(0, seconds || 0);
    const minutes = Math.floor(safe / 60), rest = safe - minutes * 60;
    return minutes + ':' + (rest < 10 ? '0' : '') + rest.toFixed(1);
  }

  function element(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  /* The stretch to draw: the payload plus room either side, so there is an
     identical lead-in and tail to compare it against. */
  function viewAround(start, end, duration) {
    const margin = Math.max(0.6, Math.min(2, (end - start) * 0.35));
    return [Math.max(0, start - margin), Math.min(duration, end + margin)];
  }

  class Monitor {
    constructor(coverUrl, stegoUrl, region, card) {
      this.coverUrl = coverUrl;
      this.stegoUrl = stegoUrl;
      this.region = region;
      this.card = card;
      this.players = Array.from(card.querySelectorAll('.compare audio'));
      this.ready = false;
      this.playing = false;
      this.position = null;
      this.hover = null;
      this.tick = this.tick.bind(this);
      this.element = this.build();

      // The players above drive the waveform and difference charts only.
      // Two sources of sound at once would be noise, so whichever starts,
      // the other stops.
      this.players.forEach(player => player.addEventListener('play', () => this.pause()));
    }

    build() {
      const block = element('section', 'chart-block live-monitor');

      const head = element('div', 'lm-head');
      const title = element('div', 'lm-title-row');
      title.append(element('h4', '', 'Sound level'),
                   element('span', 'lm-group-sub', 'Original vs stego, zoomed onto the payload'));
      const controls = element('div', 'lm-controls');
      this.timeLabel = element('span', 'lm-time', '');
      this.playButton = element('button', 'lm-play', '▶  Play both');
      this.playButton.type = 'button';
      this.playButton.disabled = true;
      this.playButton.addEventListener('click', () => (this.playing ? this.pause() : this.play()));
      controls.append(this.timeLabel, this.playButton);
      head.append(title, controls);

      const pair = element('div', 'lm-pair');
      this.canvases = {};
      for (const side of ['cover', 'stego']) {
        const canvas = element('canvas', 'lm-canvas');
        canvas.dataset.side = side;
        canvas.setAttribute('role', 'img');
        canvas.setAttribute('aria-label', (side === 'cover' ? 'Original' : 'Stego') + ' sound level');
        canvas.addEventListener('mousemove', event => this.pointAt(event, canvas));
        canvas.addEventListener('mouseleave', () => { this.hover = null; this.draw(); });
        canvas.addEventListener('click', event => this.seekTo(event, canvas));
        pair.append(canvas);
        this.canvases[side] = canvas;
      }

      this.readout = element('div', 'lm-now', 'Loading…');
      this.foot = element('div', 'lm-foot');

      block.append(head, pair, this.readout, this.foot);

      if ('ResizeObserver' in root) {
        const watch = new ResizeObserver(() => this.resize());
        Object.values(this.canvases).forEach(canvas => watch.observe(canvas));
      }
      if ('IntersectionObserver' in root) {
        const seen = new IntersectionObserver(entries => {
          if (entries.some(entry => entry.isIntersecting)) { seen.disconnect(); this.load(); }
        });
        seen.observe(block);
      } else {
        this.load();
      }
      return block;
    }

    chip(text, swatch) {
      const node = element('span', 'lm-chip', text);
      if (swatch) node.prepend(swatch);
      return node;
    }

    swatch(kind, colour) {
      const node = element('i', 'lm-swatch ' + kind);
      node.style.setProperty('--c', colour);
      return node;
    }

    async load() {
      try {
        const fetchWav = async url => {
          const response = await fetch(url);
          if (!response.ok) throw new Error('could not load the audio');
          return parseWav(await response.arrayBuffer());
        };
        const [original, stego] = await Promise.all([fetchWav(this.coverUrl), fetchWav(this.stegoUrl)]);
        if (original.channels !== stego.channels || original.rate !== stego.rate
            || original.samples.length !== stego.samples.length) {
          throw new Error('the two files differ in format');
        }
        this.original = original;
        this.stegoFile = stego;
        this.duration = original.frames / original.rate;
        this.level = levelTrack(original, stego);
        this.payload = [this.region[0] * this.duration, this.region[1] * this.duration];
        this.view = viewAround(this.payload[0], this.payload[1], this.duration);
        this.position = this.view[0];
        this.prepare();
        this.ready = true;
        this.playButton.disabled = false;
      } catch (error) {
        this.failure = error.message;
        this.readout.textContent = 'Unavailable: ' + this.failure;
      }
      this.draw();
    }

    /* Everything that depends only on the view: the scale both charts share,
       the magnification, and the tally of louder and quieter moments inside
       the box. Worked out once, because the view does not move. */
    prepare() {
      const [v0, v1] = this.view;
      const rate = this.original.rate;
      const {level, change} = this.level;
      const from = Math.floor((v0 * rate) / HOP), to = Math.min(this.level.buckets - 1, Math.ceil((v1 * rate) / HOP));
      const inFrom = Math.floor((this.payload[0] * rate) / HOP), inTo = Math.ceil((this.payload[1] * rate) / HOP);
      let peak = 1, worst = 0, louder = 0, quieter = 0;
      for (let k = from; k <= to; k += 1) {
        if (level[k] > peak) peak = level[k];
        if (k >= inFrom && k <= inTo) {
          if (change[k] > 0) louder += 1;
          if (change[k] < 0) quieter += 1;
          if (Math.abs(change[k]) > worst) worst = Math.abs(change[k]);
        }
      }
      this.gain = levelGain(peak, worst);
      this.scale = peak * (1 + 0.5 * (worst ? 1 : 0)) * 1.05;
      this.worst = worst;

      this.foot.replaceChildren(
        this.chip('Payload', this.swatch('box', COLOUR.box)),
        this.chip('Original', this.swatch('dash', '#ffffff')),
        this.chip('Louder ' + louder.toLocaleString(), this.swatch('dot', COLOUR.higher)),
        this.chip('Quieter ' + quieter.toLocaleString(), this.swatch('dot', COLOUR.lower)),
        this.chip('Largest change ±' + worst.toLocaleString()),
        this.chip(this.gain === 1 ? 'True scale' : 'Difference shown ×' + this.gain.toLocaleString()));
    }

    /* The loudest moment in a slice of time, and how much the payload
       changed it. */
    levelAt(from, to) {
      const rate = this.original.rate;
      const {level, change} = this.level;
      const first = Math.max(0, Math.floor((from * rate) / HOP));
      const last = Math.min(this.level.buckets - 1, Math.floor((to * rate) / HOP));
      let at = first;
      for (let k = first; k <= last; k += 1) if (level[k] > level[at]) at = k;
      return [level[at] || 0, change[at] || 0];
    }

    /* --- sound: both files together, locked to one clock --------------------- */

    buffers() {
      if (this.sound) return this.sound;
      const context = audioContext();
      const {channels, rate, frames, full} = this.original;
      const make = samples => {
        const buffer = context.createBuffer(channels, frames, rate);
        for (let c = 0; c < channels; c += 1) {
          const out = buffer.getChannelData(c);
          for (let f = 0; f < frames; f += 1) out[f] = samples[f * channels + c] / full;
        }
        return buffer;
      };
      this.sound = {cover: make(this.original.samples), stego: make(this.stegoFile.samples)};
      return this.sound;
    }

    now() {
      if (!this.playing) return this.position;
      return Math.min(this.view[1], this.offset + Math.max(0, audioContext().currentTime - this.startedAt));
    }

    play() {
      if (!this.ready) return;
      this.players.forEach(player => player.pause());
      const context = audioContext();
      context.resume();
      const sound = this.buffers();
      let from = this.position;
      if (from < this.view[0] || from >= this.view[1] - 0.05) from = this.view[0];

      // Both start on the same sample of the same clock, each at half volume
      // so that together they are no louder than either alone.
      const when = context.currentTime + 0.04;
      const token = (this.token = (this.token || 0) + 1);
      this.voices = ['cover', 'stego'].map(key => {
        const source = context.createBufferSource();
        source.buffer = sound[key];
        const volume = context.createGain();
        volume.gain.value = 0.5;
        source.connect(volume).connect(context.destination);
        source.start(when, from, this.view[1] - from);
        return source;
      });
      this.voices[0].onended = () => { if (this.token === token && this.playing) this.finish(); };
      this.offset = from;
      this.startedAt = when;
      this.playing = true;
      this.playButton.textContent = '❚❚  Pause';
      this.raf = root.requestAnimationFrame(this.tick);
    }

    silence() {
      (this.voices || []).forEach(source => { try { source.stop(); } catch (ignored) { /* stopped */ } });
      this.voices = null;
    }

    pause() {
      if (!this.playing) return;
      this.position = this.now();
      this.token += 1;
      this.playing = false;
      this.silence();
      root.cancelAnimationFrame(this.raf);
      this.playButton.textContent = '▶  Play both';
      this.draw();
    }

    finish() {
      this.playing = false;
      this.position = this.view[0];
      this.silence();
      root.cancelAnimationFrame(this.raf);
      this.playButton.textContent = '▶  Play both';
      this.draw();
    }

    tick() {
      if (!this.element.isConnected) { this.pause(); return; }
      this.draw();
      if (this.playing) this.raf = root.requestAnimationFrame(this.tick);
    }

    /* --- pointing and seeking ------------------------------------------------ */

    timeAt(event, canvas) {
      const box = canvas.getBoundingClientRect();
      const fraction = Math.max(0, Math.min(1, (event.clientX - box.left) / box.width));
      return this.view[0] + fraction * (this.view[1] - this.view[0]);
    }

    pointAt(event, canvas) {
      if (!this.ready) return;
      this.hover = this.timeAt(event, canvas);
      if (!this.playing) this.draw();
    }

    seekTo(event, canvas) {
      if (!this.ready) return;
      const resume = this.playing;
      if (resume) this.pause();
      this.position = this.timeAt(event, canvas);
      if (resume) this.play(); else this.draw();
    }

    /* --- drawing -------------------------------------------------------------- */

    resize() {
      const ratio = root.devicePixelRatio || 1;
      for (const canvas of Object.values(this.canvases)) {
        const box = canvas.getBoundingClientRect();
        const width = Math.round(box.width * ratio), height = Math.round(box.height * ratio);
        if (width && height && (canvas.width !== width || canvas.height !== height)) {
          canvas.width = width;
          canvas.height = height;
        }
      }
      this.draw();
    }

    draw() {
      if (this.ready) {
        const time = clock(this.now()) + ' / ' + clock(this.duration);
        if (this.timeLabel.textContent !== time) this.timeLabel.textContent = time;
      }
      for (const canvas of Object.values(this.canvases)) this.drawChart(canvas);
      if (this.ready) this.describe();
    }

    drawChart(canvas) {
      if (!canvas.width || !canvas.height) return;
      const ratio = root.devicePixelRatio || 1;
      const g = canvas.getContext('2d');
      g.setTransform(ratio, 0, 0, ratio, 0, 0);
      const w = canvas.width / ratio, h = canvas.height / ratio;
      const stego = canvas.dataset.side === 'stego';

      g.fillStyle = COLOUR.ink;
      g.fillRect(0, 0, w, h);
      if (!this.ready) {
        g.fillStyle = COLOUR.label;
        g.font = '12px system-ui, sans-serif';
        g.textAlign = 'center';
        g.fillText(this.failure ? 'Unavailable' : 'Loading…', w / 2, h / 2 + 4);
        return;
      }

      const [v0, v1] = this.view;
      const span = v1 - v0;
      const x = time => ((time - v0) / span) * w;
      const base = h - 22, top = 30;
      const y = value => base - Math.max(0, Math.min(1, value / this.scale)) * (base - top);

      // Time rules every half second, labelled every second.
      g.lineWidth = 1;
      g.font = '10px system-ui, sans-serif';
      g.textAlign = 'center';
      for (let s = Math.ceil(v0 / 0.5) * 0.5; s <= v1; s += 0.5) {
        const px = Math.round(x(s)) + 0.5;
        g.strokeStyle = COLOUR.grid;
        g.beginPath(); g.moveTo(px, 0); g.lineTo(px, base); g.stroke();
        if (Math.abs(s - Math.round(s)) < 1e-6) {
          g.fillStyle = COLOUR.label;
          g.fillText(Math.round(s) + 's', px, h - 7);
        }
      }
      g.strokeStyle = COLOUR.axis;
      g.beginPath(); g.moveTo(0, base + 0.5); g.lineTo(w, base + 0.5); g.stroke();

      // The payload, boxed, in the same place on both charts.
      const bx = x(this.payload[0]), bw = Math.max(2, x(this.payload[1]) - bx);
      g.fillStyle = 'rgba(255,214,102,0.06)';
      g.fillRect(bx, top - 12, bw, base - top + 12);
      g.strokeStyle = COLOUR.box;
      g.lineWidth = 1.5;
      g.setLineDash([6, 4]);
      g.strokeRect(bx + 0.75, top - 12 + 0.75, bw - 1.5, base - top + 12 - 1.5);
      g.setLineDash([]);
      g.fillStyle = COLOUR.box;
      g.font = '700 10px system-ui, sans-serif';
      g.textAlign = 'left';
      g.fillText('PAYLOAD', bx + 6, top - 1);

      // One moment every few pixels, each the loudest in its slice.
      const slice = (STEP / w) * span;
      const points = [];
      for (let px = 0; px <= w; px += STEP) {
        const t = v0 + (px / w) * span;
        points.push([px, ...this.levelAt(t, t + slice)]);
      }
      const originalLine = new Path2D();
      points.forEach(([px, level], i) => (i ? originalLine.lineTo(px, y(level)) : originalLine.moveTo(px, y(level))));

      if (!stego) {
        this.fillUnder(g, originalLine, points, base, top, '62,242,160');
        g.lineWidth = 2;
        g.lineJoin = 'round';
        g.strokeStyle = g.shadowColor = COLOUR.cover;
        g.shadowBlur = 6;
        g.stroke(originalLine);
        g.shadowBlur = 0;
      } else {
        const lifted = ([, level, change]) => y(level + change * this.gain);
        const stegoLine = new Path2D();
        points.forEach((point, i) => (i ? stegoLine.lineTo(point[0], lifted(point)) : stegoLine.moveTo(point[0], lifted(point))));
        this.fillUnder(g, stegoLine, points, base, top, '255,180,84', lifted);

        // The gap between the stego wave and the original, moment by moment.
        const higher = new Path2D(), lower = new Path2D();
        for (const point of points) {
          if (!point[2]) continue;
          const from = y(point[1]), to = lifted(point);
          (point[2] > 0 ? higher : lower).rect(point[0] - STEP / 2, Math.min(from, to), STEP, Math.abs(to - from));
        }
        g.fillStyle = COLOUR.higher;
        g.fill(higher);
        g.fillStyle = COLOUR.lower;
        g.fill(lower);

        g.lineWidth = 1.6;
        g.lineJoin = 'round';
        g.strokeStyle = COLOUR.stego;
        g.stroke(stegoLine);

        // The original laid over the top, so every departure is measured
        // against it.
        g.setLineDash([5, 4]);
        g.lineWidth = 1.4;
        g.strokeStyle = 'rgba(255,255,255,0.9)';
        g.stroke(originalLine);
        g.setLineDash([]);
      }

      // Pointer, then playhead, on both charts at the same instant.
      if (this.hover !== null) {
        const px = x(this.hover);
        this.marker(g, px, base, top, stego, 'rgba(255,255,255,0.8)', true);
        // Where each file actually sits at that instant: on the stego chart
        // both are marked, joined, so the gap between them is the answer.
        const [level, change] = this.levelAt(this.hover, this.hover + (STEP / w) * span);
        const at = y(level);
        if (stego) {
          const moved = y(level + change * this.gain);
          if (change) {
            g.strokeStyle = change > 0 ? COLOUR.higher : COLOUR.lower;
            g.lineWidth = 3;
            g.beginPath(); g.moveTo(px, at); g.lineTo(px, moved); g.stroke();
          }
          this.spot(g, px, at, '#ffffff');
          this.spot(g, px, moved, change > 0 ? COLOUR.higher : change < 0 ? COLOUR.lower : COLOUR.stego);
        } else {
          this.spot(g, px, at, COLOUR.cover);
        }
      }
      const now = this.now();
      if (now >= v0 && now <= v1 && (this.playing || now > v0)) this.marker(g, x(now), base, top, stego, '#ffffff', false);

      g.font = '700 9.5px system-ui, sans-serif';
      g.textAlign = 'right';
      g.fillStyle = stego ? 'rgba(255,180,84,0.95)' : 'rgba(62,242,160,0.9)';
      g.fillText(stego ? 'STEGO' : 'ORIGINAL', w - 10, 16);
    }

    fillUnder(g, line, points, base, top, tint, lift) {
      const area = new Path2D(line);
      area.lineTo(points[points.length - 1][0], base);
      area.lineTo(points[0][0], base);
      area.closePath();
      const shade = g.createLinearGradient(0, top, 0, base);
      shade.addColorStop(0, 'rgba(' + tint + ',0.26)');
      shade.addColorStop(1, 'rgba(' + tint + ',0.02)');
      g.fillStyle = shade;
      g.fill(area);
    }

    spot(g, px, py, colour) {
      g.save();
      g.fillStyle = colour;
      g.strokeStyle = COLOUR.ink;
      g.lineWidth = 2;
      g.beginPath(); g.arc(px, py, 4.5, 0, Math.PI * 2); g.fill(); g.stroke();
      g.restore();
    }

    marker(g, px, base, top, stego, colour, dashed) {
      g.save();
      g.strokeStyle = colour;
      g.lineWidth = dashed ? 1 : 1.6;
      if (dashed) g.setLineDash([3, 3]);
      else { g.shadowColor = colour; g.shadowBlur = 8; }
      g.beginPath(); g.moveTo(px, top - 14); g.lineTo(px, base); g.stroke();
      g.restore();
    }

    /* The line under the charts: exact values at the moment being pointed
       at, or at the playhead. Refreshed a few times a second at most, so it
       can actually be read while the sound plays. */
    describe() {
      const stamp = performance.now();
      if (this.playing && this.hover === null && stamp - (this.lastDescribed || 0) < 180) return;
      this.lastDescribed = stamp;

      const at = this.hover !== null ? this.hover : this.now();
      const inside = at >= this.payload[0] && at <= this.payload[1];
      const slice = 0.012;
      const [level, change] = this.levelAt(at, at + slice);
      const stegoLevel = level + change;
      const fmt = value => Math.round(value).toLocaleString();
      let text, tone;
      if (!inside) {
        text = clock(at) + '  ·  outside the payload  ·  original ' + fmt(level) + '  =  stego ' + fmt(stegoLevel);
        tone = 'calm';
      } else if (change > 0) {
        text = clock(at) + '  ·  original ' + fmt(level) + '  →  stego ' + fmt(stegoLevel) + '  ·  ▲ louder by ' + change;
        tone = 'higher';
      } else if (change < 0) {
        text = clock(at) + '  ·  original ' + fmt(level) + '  →  stego ' + fmt(stegoLevel) + '  ·  ▼ quieter by ' + (-change);
        tone = 'lower';
      } else {
        text = clock(at) + '  ·  original ' + fmt(level) + '  =  stego ' + fmt(stegoLevel) + '  ·  unchanged here';
        tone = 'calm';
      }
      if (this.hover === null && !this.playing && this.position === this.view[0]) {
        text = 'Point at either chart to compare exact values, or press Play both.';
        tone = 'calm';
      }
      if (this.readout.textContent !== text) this.readout.textContent = text;
      const name = 'lm-now ' + tone;
      if (this.readout.className !== name) this.readout.className = name;
    }
  }

  const api = {
    parseWav, levelTrack, levelGain, viewAround, HOP,
    create(coverUrl, stegoUrl, region, card) {
      return new Monitor(coverUrl, stegoUrl, region, card);
    },
  };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.StegMonitor = api;
})(typeof window !== 'undefined' ? window : globalThis);
