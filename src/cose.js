import * as cose from '@transmute/cose';
import * as edn from '@transmute/edn';
import {holder, issuer} from '@transmute/verifiable-credentials';

function buf2hex(buffer) { // buffer is an ArrayBuffer
  return [...new Uint8Array(buffer)]
    .map(x => x.toString(16).padStart(2, '0'))
    .join('');
}

// eslint-disable-next-line max-len
const getCredential = async (privateKey, byteSigner, messageType, messageJson) => {
  return issuer({
    alg: privateKey.alg,
    type: messageType,
    signer: byteSigner,
  }).issue({
    claimset: new TextEncoder().encode(JSON.stringify(messageJson, null, 2)),
  });
};

// eslint-disable-next-line max-len
const getPresentation = async (privateKey, byteSigner, messageType, messageJson) => {
  // eslint-disable-next-line max-len
  const disclosures = (messageJson.verifiableCredential || []).map(enveloped => {
    const {id} = enveloped;
    // eslint-disable-next-line max-len
    const type = id.includes('base64url') ? id.split(';base64url,')[0].replace('data:', '') : id.split(';')[0].replace('data:', '');
    // eslint-disable-next-line max-len
    const content = id.includes('base64url') ? new TextEncoder().encode(id.split('base64url,').pop()) : new TextEncoder().encode(id.split(';').pop());
    return {
      type,
      credential: content,
    };
  });
  return holder({
    alg: privateKey.alg,
    type: messageType,
  }).issue({
    signer: byteSigner,
    presentation: messageJson,
    disclosures,
  });
};

const getBinaryMessage = async (privateKey, messageType, messageJson) => {
  const signer = cose.detached.signer({
    remote: cose.crypto.signer({
      secretKeyJwk: privateKey,
    }),
  });
  const byteSigner = {
    sign: async payload => {
      return signer.sign({
        protectedHeader: new Map([[1, -35]]),
        unprotectedHeader: new Map(),
        payload,
      });
    },
  };
  switch(messageType) {
    case 'application/vc+ld+json+cose': {
      return getCredential(privateKey, byteSigner, messageType, messageJson);
    }
    case 'application/vp+ld+json+cose': {
      return getPresentation(privateKey, byteSigner, messageType, messageJson);
    }
    default: {
      throw new Error('Unknown message type');
    }
  }
};

export const getCoseExample = async (privateKey, messageJson) => {
  // eslint-disable-next-line max-len
  const type = Array.isArray(messageJson.type) ? messageJson.type : [messageJson.type];
  // eslint-disable-next-line max-len
  const messageType = type.includes('VerifiableCredential') ? 'application/vc+ld+json+cose' : 'application/vp+ld+json+cose';
  const message = await getBinaryMessage(privateKey, messageType, messageJson);
  const messageHex = buf2hex(message);
  const messageBuffer = Buffer.from(messageHex, 'hex');
  // eslint-disable-next-line max-len
  const diagnostic = await edn.render(messageBuffer, 'application/cbor-diagnostic');
  return `
<h1>${messageType.replace('+cose', '')}</h1>
<pre>
${JSON.stringify(messageJson, null, 2)}
</pre>
<h1>application/cbor-diagnostic</h1>
<div class="cose-text">
<pre><code>${diagnostic.trim()}</code></pre>
</div>
<h1>${messageType} (detached payload)</h1>
<div class="cose-text">
${messageHex}
</div>
  `.trim();
};
