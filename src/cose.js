import * as cose from '@transmute/cose';
import * as edn from '@transmute/edn';
import {holder, issuer} from '@transmute/verifiable-credentials';

function buf2hex(buffer) {
  return [...new Uint8Array(buffer)]
    .map(x => x.toString(16).padStart(2, '0'))
    .join('');
}

const getCredential = async (
  privateKey,
  byteSigner,
  messageJson,
) => {
  return issuer({
    alg: privateKey.alg,
    type: 'application/vc+ld+json+cose',
    signer: byteSigner,
  }).issue({
    claimset: new TextEncoder().encode(JSON.stringify(messageJson, null, 2)),
  });
};

const getPresentation = async (
  privateKey,
  byteSigner,
  message,
) => {
  if(Array.isArray(message.verifiableCredential) &&
    message.verifiableCredential.length === 0) {
    delete message.verifiableCredential;
  }

  const disclosures = (message.verifiableCredential || []).map(enveloped => {
    const {id} = enveloped;
    const type = id.includes('base64url') ?
      id.split(';base64url,')[0].replace('data:', '') :
      id.split(';')[0].replace('data:', '');
    const content = id.includes('base64url') ?
      new TextEncoder().encode(id.split('base64url,').pop()) :
      new TextEncoder().encode(id.split(';').pop());
    return {
      type,
      credential: content,
    };
  });
  return holder({
    alg: privateKey.alg,
    type: 'application/vp+ld+json+cose',
  }).issue({
    signer: byteSigner,
    presentation: message,
    disclosures,
  });
};

const getBinaryMessage = async (privateKey, messageType, messageJson) => {
  const signer = cose.signer({
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
    case 'application/vc+ld+cose': {
      return getCredential(privateKey, byteSigner, messageJson);
    }
    case 'application/vp+ld+cose':
    case 'EnvelopedVerifiablePresentation': {
      return getPresentation(privateKey, byteSigner, messageJson);
    }
    default: {
      throw new Error('Unknown message type');
    }
  }
};

export const getCoseExample = async (privateKey, messageJson) => {
  const type = Array.isArray(messageJson.type) ?
    messageJson.type : [messageJson.type];
  let messageType;
  if(type.includes('VerifiableCredential')) {
    messageType = 'application/vc+ld+cose';
  } else if(type.includes('VerifiablePresentation') ||
    type.includes('EnvelopedVerifiablePresentation')) {
    messageType = 'application/vp+ld+cose';
  } else {
    throw new Error('Unknown message type');
  }
  const message = await getBinaryMessage(privateKey, messageType, messageJson);
  const messageHex = buf2hex(message);

  if(Array.isArray(messageJson.verifiableCredential) &&
    messageJson.verifiableCredential.length === 0) {
    delete messageJson.verifiableCredential;
  }
  const contentHtml = `<strong>${messageType.replace('+ld+cose', '')}</strong>
<pre>
${JSON.stringify(messageJson, null, 2)}
</pre>`;

  return `
${contentHtml}
<strong>${messageType.replace('+ld+cose', '+cose')}</strong>
<div class="cose-text">
${messageHex}
</div>
  `.trim();
};
