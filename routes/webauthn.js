const express   = require("express");
const Fido2     = require("../utils/fido2");
const config    = require("../config");
const crypto    = require("crypto");
const router    = express.Router();
const database  = require("../utils/db");
const username  = require("../utils/username");

const base64url = require("@hexagon/base64-arraybuffer");

let f2l = new Fido2(config.rpId, config.rpName, undefined, config.challengeTimeoutMs);

/**
 * Returns base64url encoded buffer of the given length
 * @param  {Number} len - length of the buffer
 * @return {String}     - base64url random buffer
 */
let randomBase64URLBuffer = (len) => {
	len = len || 32;
	let buff = crypto.randomBytes(len);
	return base64url.encode(buff, true);
};

router.post("/register", async (request, response) => {
	//console.log("register");
	if(!request.body || !request.body.username || !request.body.name) {
		response.json({
			"status": "failed",
			"message": "Request missing name or username field!"
		});
		return;
	}

	let usernameClean = username.clean(request.body.username),
		name     = usernameClean;

	if (!usernameClean) {
		response.json({
			"status": "failed",
			"message": "Invalid username!"
		});
	}
    
	let db = database.getData("/");
	//if(database.users[usernameClean] && database.users[usernameClean].registered) {
	if(db.users[usernameClean] && db.users[usernameClean].registered) {
		response.json({
			"status": "failed",
			"message": "Username " + usernameClean + " already exists"
		});
		return;
	}
	//console.log("usernameClean " + usernameClean);
	//console.log("db.users[usernameClean] " + db.users[usernameClean].name);

	let id = randomBase64URLBuffer();

	//database.users[usernameClean] = {
		database.push("/users",
		{
		[usernameClean]: {
			name: name,
			registered: false,
			id: id,
			authenticators: [],
			oneTimeToken: undefined,
			recoveryEmail: undefined
	}});

	let challengeMakeCred = await f2l.registration(usernameClean, name, id);
    
	// Transfer challenge and username to session
	request.session.challenge = challengeMakeCred.challenge;
	request.session.username  = usernameClean;

	// Respond with credentials
	response.json(challengeMakeCred);
});


router.post("/add", async (request, response) => {
	if(!request.body) {
		response.json({
			"status": "failed",
			"message": "Request missing name or username field!"
		});

		return;
	}

	if(!request.session.loggedIn) {
		response.json({
			"status": "failed",
			"message": "User not logged in!"
		});

		return;
	}

	let usernameClean = username.clean(request.session.username),
		name     = usernameClean,
		//id       = database.users[request.session.username].id;
		id = database.getData("/users/" + request.session.username + "/id");

	let challengeMakeCred = await f2l.registration(usernameClean, name, id);
    
	// Transfer challenge to session
	request.session.challenge = challengeMakeCred.challenge;

	// Exclude existing credentials
	//challengeMakeCred.excludeCredentials = database.users[request.session.username].authenticators.map((e) => { return { id: base64url.encode(e.credId, true), type: e.type }; });
	challengeMakeCred.excludeCredentials = database.getData("/users/" + request.session.username + "/authenticators").map((e) => { return { id: base64url.encode(e.credId, true), type: e.type }; });

	// Respond with credentials
	response.json(challengeMakeCred);
});

router.post("/login", async (request, response) => {
	if(!request.body || !request.body.username) {
		response.json({
			"status": "failed",
			"message": "Request missing username field!"
		});

		return;
	}

	let usernameClean = username.clean(request.body.username);
	let db = database.getData("/");
	//if(!database.users[usernameClean] || !database.users[usernameClean].registered) {
	if(!db.users[usernameClean] || !db.users[usernameClean].registered) {
		response.json({
			"status": "failed",
			"message": `User ${usernameClean} does not exist!`
		});

		return;
	}

	let assertionOptions = await f2l.login(usernameClean);

	// Transfer challenge and username to session
	request.session.challenge = assertionOptions.challenge;
	request.session.username  = usernameClean;

	// Pass this, to limit selectable credentials for user... This may be set in response instead, so that
	// all of a users server (public) credentials isn't exposed to anyone
	let allowCredentials = [];
	//for(let authr of database.users[request.session.username].authenticators) {
	for(let authr of database.getData("/users/" + request.session.username + "/authenticators")) {
		//console.log(authr);
		allowCredentials.push({
			type: authr.type,
			id: base64url.encode(authr.credId, true),
			transports: ["usb", "nfc", "ble","internal"]
		});
	}

	assertionOptions.allowCredentials = allowCredentials;

	request.session.allowCredentials = allowCredentials;

	response.json(assertionOptions);
	//console.log("uscita");

});

router.post("/response", async (request, response) => {
	if(!request.body       || !request.body.id
    || !request.body.rawId || !request.body.response
    || !request.body.type  || request.body.type !== "public-key" ) {
		response.json({
			"status": "failed",
			"message": "Response missing one or more of id/rawId/response/type fields, or type is not public-key!"
		});

		return;
	}
	let webauthnResp = request.body;
	if(webauthnResp.response.attestationObject !== undefined) {
		/* This is create cred */
		webauthnResp.rawId = base64url.decode(webauthnResp.rawId, true);
		webauthnResp.response.attestationObject = base64url.decode(webauthnResp.response.attestationObject, true);
		const result = await f2l.attestation(webauthnResp, config.origin, request.session.challenge);
        
		const token = {
			credId: result.authnrData.get("credId"),
			publicKey: result.authnrData.get("credentialPublicKeyPem"),
			type: webauthnResp.type,
			counter: result.authnrData.get("counter"),
			created: new Date().getTime()
		};


		//database.users[request.session.username].authenticators.push(token);
		database.push("/users/" + request.session.username + "/authenticators[]", token);
		//database.users[request.session.username].registered = true;
		database.push("/users/" + request.session.username + "/registered", true);
		request.session.loggedIn = true;

		return response.json({ "status": "ok" });


	} else if(webauthnResp.response.authenticatorData !== undefined) {
		/* This is get assertion */
		//result = utils.verifyAuthenticatorAssertionResponse(webauthnResp, database.users[request.session.username].authenticators);
		// add allowCredentials to limit the number of allowed credential for the authentication process. For further details refer to webauthn specs: (https://www.w3.org/TR/webauthn-2/#dom-publickeycredentialrequestoptions-allowcredentials).
		// save the challenge in the session information...
		// send authnOptions to client and pass them in to `navigator.credentials.get()`...
		// get response back from client (clientAssertionResponse)
		webauthnResp.rawId = base64url.decode(webauthnResp.rawId, true);
		webauthnResp.response.userHandle = base64url.decode(webauthnResp.rawId, true);

		//let validAuthenticators = database.users[request.session.username].authenticators,
		let validAuthenticators = database.getData("/users/" + request.session.username + "/authenticators"),
			winningAuthenticator;            
		for(let authrIdx in validAuthenticators) {
			let authr = validAuthenticators[authrIdx];
			try {

				let assertionExpectations = {
					// Remove the following comment if allowCredentials has been added into authnOptions so the credential received will be validate against allowCredentials array.
					allowCredentials: request.session.allowCredentials,
					challenge: request.session.challenge,
					origin: config.origin,
					factor: "either",
					publicKey: authr.publicKey,
					prevCounter: authr.counter,
					userHandle: authr.credId
				};

				let result = await f2l.assertion(webauthnResp, assertionExpectations);

				winningAuthenticator = result;
				if (database.users[request.session.username].authenticators[authrIdx]) {
					database.users[request.session.username].authenticators[authrIdx].counter = result.authnrData.get("counter");
				}                    
				break;
        
			} catch (e) {
				// Ignore
			}
		}
		// authentication complete!
		//if (winningAuthenticator && database.users[request.session.username].registered ) {
		if (winningAuthenticator && database.getData("/users/" + request.session.username + "/registered") ) {
			request.session.loggedIn = true;
			return response.json({ "status": "ok" });

			// Authentication failed
		} else {
			return response.json({
				"status": "failed",
				"message": "Can not authenticate signature!"
			});
		}
	} else {
		return response.json({
			"status": "failed",
			"message": "Can not authenticate signature!"
		});
	}
});

module.exports = router;
