import {holder, issuer, key, text} from '@transmute/verifiable-credentials';

import * as jose from 'jose';

const getCredential = async (
  privateKey,
  byteSigner,
  messageJson
) => {
  return issuer({
    alg: privateKey.alg,
    type: 'application/vc+ld+json+jwt',
    signer: byteSigner,
  }).issue({
    claimset: new TextEncoder().encode(JSON.stringify(messageJson, null, 2)),
  });
};

const getPresentation = async (
  privateKey,
  byteSigner,
  message
) => {
  // Remove empty verifiableCredential array if present
  if(Array.isArray(message.verifiableCredential) &&
    message.verifiableCredential.length === 0) {
    delete message.verifiableCredential;
  }

  const disclosures = (message.verifiableCredential || []).map(enveloped => {
    const {id} = enveloped;
    const type = id.includes('base64url') ? id.split(';base64url,')[0].
      replace('data:', '') : id.split(';')[0].replace('data:', '');
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
    type: 'application/vp+ld+json+jwt',
  }).issue({
    signer: byteSigner,
    presentation: message,
    disclosures,
  });
};

const getJoseHtml = token => {
  const [header, payload, signature] = token.split('.');
  return `
<div class="jwt-compact">
<span class="jwt-header">${header}</span>
.<span class="jwt-payload">${payload}</span>
.<span class="jwt-signature">${signature}</span>
</div>`.trim();
};

const getBinaryMessage = async (privateKey, messageType, messageJson) => {
  const byteSigner = {
    sign: async bytes => {
      const jws = await new jose.CompactSign(bytes)
        .setProtectedHeader({kid: privateKey.kid, alg: privateKey.alg})
        .sign(await key.importKeyLike({
          type: 'application/jwk+json',
          content: new TextEncoder().encode(JSON.stringify(privateKey)),
        }));
      return text.encoder.encode(jws);
    },
  };
  switch(messageType) {
    case 'application/vc+ld+jwt': {
      return getCredential(privateKey, byteSigner, messageJson);
    }
    case 'application/vp+ld+jwt':
    case 'EnvelopedVerifiablePresentation': {
      return getPresentation(privateKey, byteSigner, messageJson);
    }
    default: {
      throw new Error('Unknown message type');
    }
  }
};

export const getJoseExample = async (privateKey, messageJson) => {
  const type = Array.isArray(messageJson.type) ?
    messageJson.type : [messageJson.type];
  let messageType;
  if(type.includes('VerifiableCredential')) {
    messageType = 'application/vc+ld+jwt';
  } else if(type.includes('VerifiablePresentation') ||
    type.includes('EnvelopedVerifiablePresentation')) {
    messageType = 'application/vp+ld+jwt';
  } else {
    throw new Error('Unknown message type');
  }
  const message = await getBinaryMessage(privateKey, messageType, messageJson);
  const messageEncoded = new TextDecoder().decode(message);
  const decodedHeader = jose.decodeProtectedHeader(messageEncoded);

  if(Array.isArray(messageJson.verifiableCredential) &&
    messageJson.verifiableCredential.length === 0) {
    delete messageJson.verifiableCredential;
  }
  const contentHtml = `<h1>${messageType.replace('+ld+jwt', '')}</h1>
<pre>
${JSON.stringify(messageJson, null, 2)}
</pre>
<h1>${messageType.replace('+ld+jwt', '-ld+jwt')}</h1>`;

  return `
<h1>Protected Headers</h1>
<pre>
${JSON.stringify(decodedHeader, null, 2)}
</pre>
${contentHtml}
<div class="jose-text">
${getJoseHtml(messageEncoded)}
</div>
  `.trim();
};
