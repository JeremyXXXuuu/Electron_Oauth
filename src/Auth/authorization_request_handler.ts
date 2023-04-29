import * as Http from "http";
import * as Url from "url";
import { BasicQueryStringUtils, QueryStringUtils } from "./query_string_utils";
import { AuthorizationRequest } from "./authorization_request";
import { AuthorizationServiceConfiguration } from "./authorization_configuration";
import { Crypto, NodeCrypto } from "./crypto_utils";
import { log } from "../logger";
import { EventEmitter } from "events";
import { StringMap } from "./types";
import { AuthorizationResponse, AuthorizationError } from "./authorization_response";

import opener = require('opener');

export const BUILT_IN_PARAMETERS = [
  "redirect_uri",
  "client_id",
  "response_type",
  "state",
  "scope",
];

class ServerEventsEmitter extends EventEmitter {
  static ON_UNABLE_TO_START = "unable_to_start";
  static ON_AUTHORIZATION_RESPONSE = "authorization_response";
}

export class AuthorizationRequestHandler {
  constructor(
    public httpServerPort: number,
    public utils = new BasicQueryStringUtils(),
    protected crypto: Crypto = new NodeCrypto()
  ) {}

  protected buildRequestUrl(
    configuration: AuthorizationServiceConfiguration,
    request: AuthorizationRequest
  ) {
    // build the query string
    // coerce to any type for convenience
    let requestMap: StringMap = {
      redirect_uri: request.redirectUri,
      client_id: request.clientId,
      response_type: request.responseType,
      state: request.state,
      scope: request.scope,
    };

    // copy over extras
    if (request.extras) {
      for (let extra in request.extras) {
        if (request.extras.hasOwnProperty(extra)) {
          // check before inserting to requestMap
          if (BUILT_IN_PARAMETERS.indexOf(extra) < 0) {
            requestMap[extra] = request.extras[extra];
          }
        }
      }
    }

    let query = this.utils.stringify(requestMap);
    let baseUrl = configuration.authorizationEndpoint;
    let url = `${baseUrl}?${query}`;
    return url;
  }

  async performAuthorizationRequest(
    configuration: AuthorizationServiceConfiguration,
    request: AuthorizationRequest,
    emitter: EventEmitter
  ): Promise<void> {
    const requestHandler = (
      httpRequest: Http.IncomingMessage,
      httpResponse: Http.ServerResponse
    ) => {
      if (!httpRequest.url) {
        return;
      }
      const url = httpRequest.url;
      const urlParts = Url.parse(url ? url : "", true);
      const search = urlParts.search;
      const query = urlParts.query;
      if (!search) {
        httpResponse.statusCode = 500;
        httpResponse.end();
        return;
      }
      const requestState = query.state as string;
      const code = query.code as string;
      const error = query.error as string;
      const errorDescription = query.error_description as string;
      const errorUri = query.error_uri as string;
      if (!requestState || (!code && !error)) {
        httpResponse.statusCode = 500;
        httpResponse.end();
        return;
      }
      if (requestState !== request.state) {
        httpResponse.statusCode = 500;
        httpResponse.end();
        return;
      }
      log("Handling Authorization Request ", query, requestState, code, error);
      let authorizationResponse: AuthorizationResponse|null = null;
      let authorizationError: AuthorizationError|null = null;
      if(query.error) {
        authorizationError = new AuthorizationError( {error: error, error_description: errorDescription, error_uri: errorUri, state: requestState});
      } else {
      authorizationResponse = new AuthorizationResponse({ code: code, state: requestState });
      }
      const response = {
        request,
        response: authorizationResponse,
        error: authorizationError
      };
      emitter.emit(ServerEventsEmitter.ON_AUTHORIZATION_RESPONSE, response);
    };

    let server: Http.Server;
    request
      .setupCodeVerifier()
      .then(() => {
        server = Http.createServer(requestHandler);
        server.listen(this.httpServerPort);
        const url = this.buildRequestUrl(configuration, request);
        log("Making a request to ", request, url);
        // open authorization request in external browser
        opener(url);
      })
      .catch((error) => {
        log("Something bad happened ", error);
        emitter.emit(ServerEventsEmitter.ON_UNABLE_TO_START);
      });
  }
}
