import { IonKey, IonSignature } from '../lib/index';

describe('IonSignature', async () => {
  const jwsHelloWorld = Buffer.from('hello world', 'utf8');
  const jwsGoodbyeWorld = Buffer.from('goodbye world', 'utf8');
  const [publicKey1, privateKey1] = await IonKey.generateEs256kOperationKeyPair();
  const [publicKey2, privateKey2] = await IonKey.generateEs256kOperationKeyPair();
  const jws1 = await IonSignature.generateEs256kJws({
    payload: jwsHelloWorld,
    privateKeyJwk: privateKey1
  });
  const jws2 = await IonSignature.generateEs256kJws({
    payload: jwsHelloWorld,
    privateKeyJwk: privateKey1
  });
  const jwsDifferentKeys = await IonSignature.generateEs256kJws({
    payload: jwsHelloWorld,
    privateKeyJwk: privateKey2
  });
  const jwsDifferentPayload = await IonSignature.generateEs256kJws({
    payload: jwsGoodbyeWorld,
    privateKeyJwk: privateKey1
  });
  const jwsDetached1 = await IonSignature.generateEs256kDetachedJws({
    payload: jwsHelloWorld,
    privateKeyJwk: privateKey1
  });
  const jwsDetached2 = await IonSignature.generateEs256kDetachedJws({
    payload: jwsHelloWorld,
    privateKeyJwk: privateKey1
  });
  const jwsDetachedDifferentKeys = await IonSignature.generateEs256kDetachedJws({
    payload: jwsHelloWorld,
    privateKeyJwk: privateKey2
  });
  const jwsDetachedDifferentPayload = await IonSignature.generateEs256kDetachedJws({
    payload: jwsGoodbyeWorld,
    privateKeyJwk: privateKey1
  });
  describe('generateEs256kJws()', async () => {
    it('should generate a JWS based on provided ES256K keys.', async () => {
      expect(jws1).toEqual(jws2);
      expect(jws1).not.toEqual(jwsDifferentKeys);
      expect(jws1).not.toEqual(jwsDifferentPayload);
    });
  });

  describe('verifyEs256kJws()', async () => {
    it('should verify a JWS based on provided ES256K keys.', async () => {
      const verified1 = await IonSignature.verifyEs256kJws(jws1, publicKey1);
      const verified2 = await IonSignature.verifyEs256kJws(jws1, publicKey2);
      expect(verified1).toEqual(true);
      expect(verified2).toEqual(false);
    });
  });

  describe('generateEs256kDetachedJws()', async () => {
    it('should generate a JWS based on provided ES256K keys.', async () => {
      expect(jwsDetached1).toEqual(jwsDetached2);
      expect(jwsDetached1).not.toEqual(jwsDetachedDifferentKeys);
      expect(jwsDetached1).not.toEqual(jwsDetachedDifferentPayload);
    });
  });

  describe('verifyEs256kDetachedJws()', async () => {
    it('should verify a JWS based on provided ES256K keys.', async () => {
      const verified1 = await IonSignature.verifyEs256kDetachedJws(jwsDetached1, publicKey1, jwsHelloWorld);
      const verified2 = await IonSignature.verifyEs256kDetachedJws(jwsDetached1, publicKey2, jwsHelloWorld);
      const verified3 = await IonSignature.verifyEs256kDetachedJws(jwsDetached1, publicKey1, jwsGoodbyeWorld);
      const verified4 = await IonSignature.verifyEs256kDetachedJws(jwsDetachedDifferentKeys, publicKey2, jwsHelloWorld);
      const verified5 = await IonSignature.verifyEs256kDetachedJws(jwsDetachedDifferentPayload, publicKey1, jwsGoodbyeWorld);
      expect(verified1).toEqual(true);
      expect(verified2).toEqual(false);
      expect(verified3).toEqual(false);
      expect(verified4).toEqual(true);
      expect(verified5).toEqual(true);
    });
  });
});
