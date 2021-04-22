import IonServiceModel from './IonServiceModel';

export default interface IonAddServicesActionModel {
    action: string;
    services: IonServiceModel[];
}
