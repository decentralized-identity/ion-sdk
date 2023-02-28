// NOTE: Aliases to classes and interfaces are used for external consumption.

// SDK exports.
import AdaDid from './AdaDid';
import AdaNetwork from './enums/AdaNetwork';
import DidKey from './DidKey';
import DidRequest from './DidRequest';
import IonDocumentModel from './models/IonDocumentModel';
import IonPublicKeyModel from './models/IonPublicKeyModel';
import IonPublicKeyPurpose from './enums/IonPublicKeyPurpose';
import IonSdkConfig from './IonSdkConfig';
import IonServiceModel from './models/IonServiceModel';
import ISigner from './interfaces/ISigner';
import JwkEd25519 from './models/JwkEd25519';
import JwkEs256k from './models/JwkEs256k';
import LocalSigner from './LocalSigner';

export {
  ISigner,
  AdaDid,
  IonDocumentModel,
  DidKey,
  AdaNetwork,
  IonPublicKeyModel,
  IonPublicKeyPurpose,
  DidRequest,
  IonSdkConfig,
  IonServiceModel,
  JwkEd25519,
  JwkEs256k,
  LocalSigner
};
