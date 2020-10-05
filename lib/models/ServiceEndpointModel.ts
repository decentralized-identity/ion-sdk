/**
 * Defines the data structure of a service endpoint.
 */
export default interface ServiceEndpointModel {
  id: string;
  type: string;
  endpoint: string | object ;
};
