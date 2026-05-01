const RTCServers = [
  {url: 'stun:stun.l.google.com:19302'},
  {url: 'stun:stun1.l.google.com:19302'},
  {url: 'stun:stun2.l.google.com:19302'},
  {url: 'stun:stun3.l.google.com:19302'},
  {url: 'stun:stun3.l.google.com:19302'},
  {url: 'stun:stun4.l.google.com:19302'},
  {url: 'turn:turn.bistri.com:80', credential: 'homeo', username: 'homeo'},
  {url: 'turn:turn.anyfirewall.com:443?transport=tcp', credential: 'webrtc', username: 'webrtc'}
];

const codec = 'VP8';
const frameRate = 1;
const keyFrame = 10000;
const bitrates = {
  turn: {
    max: 2500,
    min: 1000,
    start: 2500
  },
  stun: {
    max: 100000,
    min: 10000,
    start: 50000
  }
};

let canvas, canvasCtx, connectionHandler, getStatsInt, img, sender;

// //
// listener for messages from worker
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.target !== 'offscreen') {
    return;
  }

  switch (message.action) {
    case 'capture':
      captureImageToStream(message.data);
      break;

    case 'request_rtc':
      connectionHandler.onRequestRtc(message.data);
      break;

    case 'answer_rtc':
      connectionHandler.onAnswerRtc(message.data);
      break;

    case 'answer_rtc_ice':
      connectionHandler.onAnswerIce(message.data);
      break;

    default:
      break;
  }
});

// //
// draw image to canvas
function captureImageToStream(data) {
  if (!data) {
    console.debug('[captureImageToStream] no data');
    return;
  }

  if (typeof(img) === 'undefined') {
    img = document.createElement('img');
  }

  // Set onload handler each time to ensure it fires for every new image
  img.onload = () => {
    console.debug(`[captureImageToStream] img width: ${img.width}, img height: ${img.height}`);
    if (img.width > 0 && img.height > 0) {
      // Only resize canvas if dimensions changed (resizing clears the canvas)
      if (canvas.width !== img.width || canvas.height !== img.height) {
        canvas.width = img.width;
        canvas.height = img.height;
        console.debug(`[captureImageToStream] resized canvas to: ${canvas.width} x ${canvas.height}`);
      }
            
      canvasCtx.drawImage(img, 0, 0, canvas.width, canvas.height);
      console.debug(`[captureImageToStream] drawing image to canvas: ${canvas.width} x ${canvas.height}`);
    }
  };

  console.debug('[captureImageToStream] setting img src');
  img.setAttribute('src', data);
}

class CoRTCConnectionHandler {
  constructor(stream) {
    if (typeof(stream) !== 'object') {
      throw new Error('stream required');
    }

    this.stream = stream;
    this.connections = {};
    this.presentSessionIds = [];
    this.cleanConnectionsInt = setInterval(
      this.cleanConnections.bind(this),
      30000
    );
  }

  // //
  // handle rtc request from worker
  onRequestRtc(msg) {
    console.debug('[onRequestRtc] msg ->', msg);
    try {
      const sessionId = msg.data.sessionId;
      this.addPresence(sessionId);

      let rtc = this.connections[sessionId];
      if (typeof(rtc) === 'undefined') {
        const args = {sessionId: sessionId};
        if (Array.isArray(msg.data.customIce)) {
          args.customIce = msg.data.customIce;
          chrome.runtime.sendMessage({target: 'rtc_handler', action: 'ice_servers', data: args.customIce});
        }

        // create new rtc connection
        rtc = this.connections[sessionId] = new CoRTCConnection(args);
        rtc.setStream(this.stream);
        console.debug('[onRequestRtc] no rtc for session id, creating new one ->', this.connections);
      }

      rtc.addIceCallback((ice) => {
        if (ice) {
          this.sendIce(sessionId, ice);
        }
      });

      rtc.createOffer().then(this.onRtcOffer.bind(this, sessionId));
    } catch (err) {
      errLog('[onRequestRtc] error ->', err);
      throw err;
    }
  }

  // //
  // set offer and send
  onRtcOffer(sessionId, offer) {
    console.debug('[onRtcOffer] sessionId:', sessionId, ' offer:', offer);
    const rtc = this.connections[sessionId];
    if (typeof(rtc) === 'undefined') {
      throw new Error(`no RTC for sessionId: ${sessionId}`);
    }

    rtc.setOffer(offer);
    const data = {
      sessionId: sessionId,
      offer: offer
    };
    chrome.runtime.sendMessage({target: 'rtc_handler', action: 'offer_rtc', data: data});
  }

  // //
  // send ice server
  sendIce(sessionId, ice) {
    if (typeof(sessionId) === 'undefined') {
      throw new Error('sessionId required');
    }
    if (typeof(ice) === 'undefined') {
      throw new Error('ice required');
    }
    const data = {
      sessionId: sessionId,
      ice: ice
    };
    chrome.runtime.sendMessage({target: 'rtc_handler', action: 'offer_rtc_ice', data: data});
  }

  // //
  // set answer
  onAnswerRtc(msg) {
    console.debug('[onAnswerRtc] msg ->', msg);

    const sessionId = msg.data.sessionId;
    const rtc = this.connections[sessionId];
    if (typeof(rtc) === 'undefined') {
      throw new Error(`sessionId ${sessionId} does not have a rtc connection`);
    }
    rtc.setAnswer(msg.data.answer);
  }

  // //
  // set ice server
  onAnswerIce(msg) {
    console.debug('[onAnswerIce] msg ->', msg);

    const sessionId = msg.data.sessionId;
    const rtc = this.connections[sessionId];
    if (typeof(rtc) === 'undefined') {
      throw new Error(`sessionId ${sessionId} does not have a rtc connection`);
    }
    rtc.addIce(msg.data.ice);
  }

  // //
  // update presence
  updatePresence(sessionIds) {
    if (!Array.isArray(sessionIds)) {
      throw new Error('sessionIds required');
    }
    this.presentSessionIds = sessionIds;
  }

  // //
  // add presence
  addPresence(sessionId) {
    if (typeof(sessionId) === 'undefined') {
      throw new Error('sessionId required');
    }
    if (this.presentSessionIds.indexOf(sessionId) === -1) {
      this.presentSessionIds.push(sessionId);
    }
  }

  // //
  // clean up/remove stale connections
  cleanConnections() {
    Object.keys(this.connections).forEach((sessionId) => {
      if (this.presentSessionIds.indexOf(sessionId) === -1) {
        const rtcObj = this.connections[sessionId];
        if (typeof(rtcObj) !== 'undefined' && typeof(rtcObj.rtc) !== 'undefined') {
          rtcObj.rtc.close();
          delete rtcObj.rtc;
        }
        delete this.connections[sessionId];
      }
    });
  }
}

class CoRTCConnection {
  constructor(args) {
    let servers = RTCServers;
    if (typeof(args) === 'object') {
      if (typeof(args.customIce) !== 'undefined') {
        if (!Array.isArray(args.customIce)) { throw new Error('custom ice must be an array');}
        this.customIce = args.customIce;
        servers = this.customIce;
      }
    } else if (typeof(args) !== 'undefined') {
      throw new Error('args must be an object when provided');
    }

    this.sessionId = args.sessionId;
    this.ice = [];
    this.onIceCallbacks = [];
    this.onOfferCallbacks = [];
    this.haveAllIce = false;

    if (typeof(RTCPeerConnection) !== 'undefined') {
      this.rtc = new RTCPeerConnection({iceServers: servers});
      this.rtc.onicecandidate = this.onIce.bind(this);

      // gather stats
      if (getStatsInt) {
        clearInterval(getStatsInt);
      }

      getStatsInt = setInterval(() => {
        this.getStats();
      }, 5000);
    }
  }

  // //
  // create offer
  createOffer() {
    return this.rtc.createOffer();
  }

  // //
  // on ice candidate
  onIce(event) {
    console.debug('[onIce] ->', event);
    if (typeof(event) === 'undefined') { throw new Error('rtc event required');}
    if (event.candidate) {
      this.haveAllIce = false;

      this.ice.push(event.candidate);
      this.onIceCallbacks.forEach((callback) => {
        callback(event.candidate);
      });

    } else {
      this.haveAllIce = true;
      this.onIceCallbacks.forEach((callback) => {
        callback(null);
      });
    }
  }

  // //
  // set stream and add tracks
  setStream(stream) {
    if (typeof(stream) !== 'object') { throw new Error('stream must be an object');}
    this.stream = stream;
    stream.getTracks().forEach((track) => {
      sender = this.rtc.addTrack(track, stream);
    });
  }

  // //
  // set offer
  setOffer(offer) {
    if (typeof(offer) !== 'object') { throw new Error('offer must be an object');}
    if (typeof(this.rtc) !== 'undefined') {

      offer.sdp = setCodec(offer.sdp);
      offer.sdp = setBitrate(offer.sdp);
      offer.sdp = setKeyFrameInterval(offer.sdp);
      offer.sdp = setFrameRate(offer.sdp);

      console.debug('[setOffer] offer ->', offer);

      this.rtc.setLocalDescription(offer).catch((err) => {
        console.error('[setLocalDescription] error ->', err);
        chrome.runtime.sendMessage({target: 'rtc_handler', action: 'webrtc_error', data: err.message});
      });

      this.offer = offer;
      this.onOfferCallbacks.forEach((callback) => {
        console.debug('[onOfferCallbacks] calling offer callback');
        callback();
      });

      this.onOfferCallbacks = [];
    }
  }

  // //
  // set answer
  setAnswer(answer) {
    if (typeof(answer) === 'undefined') { throw new Error('answer required');}

    answer.sdp = setCodec(answer.sdp);
    answer.sdp = setBitrate(answer.sdp);
    answer.sdp = setKeyFrameInterval(answer.sdp);
    answer.sdp = setFrameRate(answer.sdp);

    console.debug('[setAnswer] answer ->', answer);

    this.rtc.setRemoteDescription(answer).catch((err) => {
      console.error('[setRemoteDescription] error ->', err);
      chrome.runtime.sendMessage({target: 'rtc_handler', action: 'webrtc_error', data: err.message});
    });

    console.debug('[setAnswer] rtc ->', this.rtc);
  }

  // //
  // add ice
  addIce(ice) {
    console.debug('[addIce] ->', ice);
    if (typeof(ice) === 'undefined') { throw new Error('ice required');}

    this.rtc.addIceCandidate(ice).catch((err) => {
      console.error('[addIceCandidate] error ->', err);
      chrome.runtime.sendMessage({target: 'rtc_handler', action: 'webrtc_error', data: err.message});
    });

    console.debug('[addIce] rtc ->', this.rtc);
  }

  // //
  // add ice callback
  addIceCallback(callback) {
    if (typeof(callback) !== 'function') { throw new Error('callback function requred');}
    this.onIceCallbacks.push(callback);
  }

  // //
  // gather stats
  async getStats() {
    if (typeof(this.rtc) === 'undefined') { 
      return
    }

    let candidatePair, localCandidate, remoteCandidate, outboundRtp;
    const stats = await this.rtc.getStats();

    // process stats reports
    stats.forEach(report => {
      if (report.type === 'outbound-rtp' && report.kind === 'video') {
        outboundRtp = report;
      }
      if (report.type === 'candidate-pair' && report.state === 'succeeded') {
        candidatePair = report;
      }
    });

    // process selected candidate pair
    if (candidatePair) {
      // find local and remote candidates
      stats.forEach(report => {
        if (report.type === 'local-candidate' && report.id === candidatePair.localCandidateId) {
          localCandidate = report;
        }
        if (report.type === 'remote-candidate' && report.id === candidatePair.remoteCandidateId) {
          remoteCandidate = report;
        }
      });

      if (localCandidate && remoteCandidate) {
        const type = localCandidate.candidateType === 'relay' || remoteCandidate.candidateType === 'relay' ? 'turn' : 'stun';
        console.debug('[getStats] type ->', type);
        this.setSenderBitrate(type);

        // send data to telemetry
        const data = {sessionId: this.sessionId, type: type, bytes: outboundRtp.bytesSent}
        chrome.runtime.sendMessage({target: 'rtc_handler', action: 'webrtc_data', data: data});
      }
    }
  }

  // //
  // set sender bitrate
  setSenderBitrate(type) {
    const parameters = sender.getParameters();
    if (!parameters.encodings) {
      console.debug('[setSenderBitrate] No encodings found');
      return;
    }

    const br = bitrates[type];
    if (parameters.encodings[0].maxBitrate === (br.max * 1000)) {
      console.debug('[setSenderBitrate] bitrate already set');
      return;
    }

    parameters.encodings[0].maxBitrate = br.max * 1000;
    parameters.encodings[0].minBitrate = br.min * 1000;
    parameters.encodings[0].startBitrate = br.start * 1000;

    sender.setParameters(parameters).then(() => {
      console.debug('[setSenderBitrate] bitrate set ->', br);
    }).catch(err => {
      console.error('[setSenderBitrate] error setting bitrate ->', err);
    });
  }
}

// //
// set preferred codec
function setCodec(sdp) {
  const codecRegex = new RegExp(`a=rtpmap:(\\d+) ${codec}/\\d+`);
  const match = sdp.match(codecRegex);
  if (!match) {
    console.warn(`Codec ${codec} not found in SDP`);
    return sdp;
  }

  const codecPayloadType = match[1];
  console.debug(`[setCodec] codecPayloadType -> ${codecPayloadType}`);

  const lines = sdp.split('\r\n');
  // Move the codec to the top of the m= line
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].startsWith('m=video')) {
      console.debug(`[setCodec] m=video -> ${lines[i]}`);
      const parts = lines[i].split(' ');
      const mLine = parts.slice(0, 3).concat([codecPayloadType]).concat(parts.slice(3).filter(pt => pt !== codecPayloadType));
      lines[i] = mLine.join(' ');
      console.debug(`[setCodec] m=video -> ${lines[i]}`);
      break;
    }
  }

  return lines.join('\r\n');
}

// //
// set preferred bitrate
function setBitrate(sdp) {
  const lines = sdp.split('\r\n');
  let mLineIndex = -1;

  // Find the m=video line
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].startsWith('m=video')) {
      mLineIndex = i;
      break;
    }
  }

  if (mLineIndex === -1) {
    console.warn('m=video line not found in SDP');
    return sdp;
  }

  // Add b=AS lines for bitrate settings
  lines.splice(mLineIndex + 1, 0, `b=AS:${bitrates.stun.max}`);
  lines.splice(mLineIndex + 1, 0, `a=fmtp:${lines[mLineIndex].split(' ')[3]} x-google-start-bitrate=${bitrates.stun.start};x-google-min-bitrate=${bitrates.stun.min};x-google-max-bitrate=${bitrates.stun.max}`);

  return lines.join('\r\n');
}

// //
// set key frame interval
function setKeyFrameInterval(sdp) {
  const lines = sdp.split('\r\n');

  const newLines = lines.map(line => {
    if (line.startsWith('a=fmtp:')) {
      return `${line};x-google-min-interval=${keyFrame}`;
    }
    return line;
  });

  return newLines.join('\r\n');
}

// //
// set frame rate
function setFrameRate(sdp) {
  const lines = sdp.split('\r\n');

  const newLines = lines.map(line => {
    if (line.startsWith('a=fmtp:')) {
      return `${line};max-fr=${frameRate}`;
    }
    return line;
  });

  return newLines.join('\r\n');
}

// //
// Start webrtc connection
function load() {
  canvas = document.createElement('canvas');
  canvasCtx = canvas.getContext('2d');

  const stream = canvas.captureStream(1);
  connectionHandler = new CoRTCConnectionHandler(stream);

  console.debug('[setUser] connectionHandler');
  rtcPresenceInt = setInterval(() => {
    const sessionIds = [];
    Object.keys(user.presence).forEach((clientId) => {
      if (user.presence[clientId]) {
        const sessionId = user.presence[clientId].sessionId;
        if (typeof(sessionId) !== 'undefined' && sessionIds.indexOf(sessionId) === -1) {
          sessionIds.push(sessionId);
        }
      }
    });
    connectionHandler.updatePresence(sessionIds);
  }, 30000);
}
load();