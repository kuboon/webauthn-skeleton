/* global base64, loadMainContainer, preformatMakeCredReq, preformatGetAssertReq, publicKeyCredentialToJSON */
/* exported register, login */
import {
  preformatGetAssertReq,
  preformatMakeCredReq,
  publicKeyCredentialToJSON,
} from "./utils.mjs";

const getMakeCredentialsChallenge = (formBody, additional) => {
  return fetch(additional ? "webauthn/add" : "webauthn/register", {
    method: "POST",
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(formBody),
  })
    .then((response) => response.json())
    .then((response) => {
      if (response.status !== "ok") {
        throw new Error(
          `Server responed with error. The message is: ${response.message}`,
        );
      }

      return response;
    });
};

const sendWebAuthnResponse = (body) => {
  return fetch("webauthn/response", {
    method: "POST",
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  })
    .then((response) => response.json())
    .then((response) => {
      if (response.status !== "ok") {
        throw new Error(
          `Server responed with error. The message is: ${response.message}`,
        );
      }

      return response;
    });
};

const getGetAssertionChallenge = (formBody) => {
  return fetch("webauthn/login", {
    method: "POST",
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(formBody),
  })
    .then((response) => response.json())
    .then((response) => {
      if (response.status !== "ok") {
        throw new Error(
          `Server responed with error. The message is: ${response.message}`,
        );
      }
      return response;
    });
};

/* Handle for register form submission */
export function register(username, additional) {
  const name = username;

  return getMakeCredentialsChallenge({ username, name }, additional)
    .then((response) => {
      const publicKey = preformatMakeCredReq(response);
      return navigator.credentials.create({ publicKey });
    })
    .then((response) => {
      const transports = response.response.getTransports
          ? response.response.getTransports()
          : undefined,
        makeCredResponse = {
          id: response.id,
          rawId: base64.fromArrayBuffer(response.rawId, true),
          transports: transports,
          response: {
            attestationObject: base64.fromArrayBuffer(
              response.response.attestationObject,
              true,
            ),
            clientDataJSON: base64.fromArrayBuffer(
              response.response.clientDataJSON,
              true,
            ),
          },
          type: response.type,
        };
      return sendWebAuthnResponse(makeCredResponse);
    })
    .then((response) => {
      if (response.status !== "ok") {
        return Promise.reject(
          `Server responed with error. The message is: ${response.message}`,
        );
      }
    });
}

/* Handler for login form submission */
export function login(username) {
  return getGetAssertionChallenge({ username })
    .then((response) => {
      const publicKey = preformatGetAssertReq(response);
      return navigator.credentials.get({ publicKey });
    })
    .then((response) => {
      const getAssertionResponse = publicKeyCredentialToJSON(response);
      return sendWebAuthnResponse(getAssertionResponse);
    })
    .then((response) => {
      if (response.status !== "ok") {
        return Promise.reject(
          `Server responed with error. The message is: ${response.message}`,
        );
      }
    });
}
