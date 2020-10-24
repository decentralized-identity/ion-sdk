/**
 * Defines the data structure of a service declared in a DID Document.
 */
export default interface IonServiceModel {
  id: string;
  type: string;
  serviceEndpoint: string | object ;
};
