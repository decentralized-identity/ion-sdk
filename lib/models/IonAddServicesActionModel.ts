import IonServiceModel from './IonServiceModel.js';

export default interface IonAddServicesActionModel {
    action: string;
    services: IonServiceModel[];
}
