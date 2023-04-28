import {TokenRequestHandler} from './token_request_handler';
import {AuthorizationRequestHandler} from './authorization_request_handler';
import { AuthorizationServiceConfiguration } from './authorization_configuration';
import {log} from '../logger';

export default class Auth {

    authorizationRequestHandler: AuthorizationRequestHandler;
    tokenRequestHandler: TokenRequestHandler;
    authorizationServiceConfiguration: AuthorizationServiceConfiguration;
    openIdConnectUrl: string;
    configuration: AuthorizationServiceConfiguration;


    async fetchServiceConfiguration(): Promise<void> {
        log("Fetching service configuration", this.openIdConnectUrl)
        try {
            const response = await AuthorizationServiceConfiguration.fetchFromIssuer(this.openIdConnectUrl);
            log('Fetched service configuration', response);
            this.configuration = response;
        } catch (error) {
            log('Something bad happened', error);
            log(`Something bad happened ${error}`);
        }
      }

}