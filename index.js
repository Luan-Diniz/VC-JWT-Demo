import crypto from 'crypto';
import * as ed25519 from '@transmute/did-key-ed25519';
import { createVerifiableCredentialJwt, verifyCredential } from 'did-jwt-vc';
import { EdDSASigner } from 'did-jwt';

import { Resolver } from 'did-resolver';
import { getResolver as getKeyResolver } from 'key-did-resolver';

// ******** Generating the issuer's did:key *********
// ed255519 from @transmute/did-key-ed25519.
// It will generate a did:key.
const { didDocument, keys } = await ed25519.generate(
  {
    secureRandom: () => {
      return crypto.randomBytes(32);
    },
  },                                                
  { accept: 'application/did+json' }   // specifically requests that the DID Document be returned in the official, standardized JSON format.
                                       // it is 'application/did+json' or 'application/did+ld+json'
);

// Note: Jwk stands for Json Web Key (RFC 7517), it's a standardized JSON structure for representing a cryptographic key. 
// The public key can be accessed from the didDocument: didDocument.verificationMethod[0].publicKeyJwk
// console.log('Generated DID Document:', didDocument);

console.log('Generated DID :', didDocument.id);

// The variable keys have both keys, the public and the private one, stored in a json structure.
// To access them: keys[0].privateKeyJwk and keys[0].publicKeyJwk;
// console.log('Generated keys :', keys);

// A deep dive into Ed25519 curves: https://cendyne.dev/posts/2022-03-06-ed25519-signatures.html
const privateKeyJwk = keys[0].privateKeyJwk;
const keyId = keys[0].id;
// If you look at both Jwk key structures, you'll notice that 'x' is actually the public key and 'd', the private key.
const privateKeyBytes = Buffer.from(privateKeyJwk.d, 'base64url');



// ******** Preparing the Issuer *********
const signer = EdDSASigner(privateKeyBytes);
// It is, actually, an Issuer instance.
const issuer = {
  did: didDocument.id,
  signer: signer,
  alg: 'EdDSA',
  kid: keyId
};



// ******** Defining the vc Payload *********
// Specification: https://www.w3.org/TR/vc-data-model/
// Some examples: https://www.w3.org/TR/vc-use-cases/
const vcPayload = {
  '@context': ['https://www.w3.org/2018/credentials/v1'],
  type: ['VerifiableCredential', 'UniversityDegree'],
  credentialSubject: {
    id: 'did:example:ebfeb1f712ebc6f1c276e12ec21',
    degree: {
      type: 'BachelorDegree',
      name: 'Computer Science'
    }
  },
};



// ******** Creating and signing the VC in the JWT format *********
/*
  When creating a VC-JWT, a proof field is not added to the JSON payload.
  The cryptographic proof is the JWT's own signature.
*/ 
console.log('\nCreating a JWT Credential...');
const vcJwt = await createVerifiableCredentialJwt(vcPayload, issuer);
console.log('\nJWT Credential successfully generated!');
// A VC-JWT is literally just a JWT (JSON Web Token) whose payload includes a VC object.
// Structure of a JWT: HEADER.PAYLOAD.SIGNATURE  , each part is Base64URL-encoded JSON.
console.log(vcJwt);



// ******** Verifying Credential *********
console.log('\n--------------------------------------------------');
console.log('Starting Credential Verification...');

// Configuring the Resolver (it receives a DID and finds it's respective DID Document).
// Getting the specific implementation for did:key
const keyResolver = getKeyResolver();

// Creating the main Resolver, instantiating it with the resolvers I want it to support. 
const resolver = new Resolver({
  ...keyResolver
});

try {
  // Throws an error if verification fails. 
  const verifiedVc = await verifyCredential(vcJwt, resolver);

  console.log('\n✅ Verification completed successfully!');
  console.log('The credential is authentic.');

  console.log('\nCredential Payload:');
  console.log(JSON.stringify(verifiedVc, null, 2));

} catch (error) {
  console.error('\n❌ Failed when verifying the credential:', error.message);
}