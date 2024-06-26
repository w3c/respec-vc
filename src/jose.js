import {
  holder,
  issuer,
  key,
  text,
} from '@transmute/verifiable-credentials';

import * as jose from 'jose';

const getCredential = async (
  privateKey,
  byteSigner,
  messageType,
  messageJson
) => {
  let oldMessageType = (messageType === 'application/vc+jwt')
    ? 'application/vc+ld+json+jwt' : 'application/vp+ld+json+jwt';
  return issuer({
    alg: privateKey.alg,
    type: oldMessageType,
    signer: byteSigner,
  }).issue({
    claimset: new TextEncoder().encode(JSON.stringify(messageJson, null, 2)),
  });
};

const getPresentation = async (
  privateKey,
  byteSigner,
  messageType,
  message
) => {
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
    type: messageType,
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
    case 'application/vc+jwt': {
      return getCredential(privateKey, byteSigner, messageType, messageJson);
    }
    case 'application/vp+jwt': {
      return getPresentation(privateKey, byteSigner, messageType, messageJson);
    }
    default: {
      throw new Error('Unknown message type');
    }
  }
};

export const getJoseExample = async (privateKey, messageJson) => {
  const type = Array.isArray(messageJson.type) ?
    messageJson.type : [messageJson.type];
  const messageType = type.includes('VerifiableCredential') ?
    'application/vc+jwt' : 'application/vp+jwt';
  const message = await getBinaryMessage(privateKey, messageType, messageJson);
  const messageEncoded = new TextDecoder().decode(message);
  const decodedHeader = jose.decodeProtectedHeader(messageEncoded);
  return `
<h1>Protected Headers</h1>
<pre>
${JSON.stringify(decodedHeader, null, 2)}
</pre>
<h1>${messageType.replace('+jwt', '')}</h1>
<pre>
${JSON.stringify(messageJson, null, 2)}
</pre>
<h1>${messageType}</h1>
<div class="jose-text">
${getJoseHtml(messageEncoded)}
</div>
  `.trim();
};
