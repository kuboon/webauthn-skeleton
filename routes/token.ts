import { Router } from "../deps.ts";
import { config } from "../config.ts";
import { token } from "../utils/token.ts";
import { getUser, updateUser } from "../db/db.ts";
import { username } from "../utils/username.ts";

const router = new Router ();


router.get("/login/:userName/:oneTimeToken", async (request, response) => {

	// Get session
	// @ts-ignore: session exists
	const session = request.session;

	// Check that token exists
	if(!request.params.oneTimeToken) {
		return response.json({
			"status": "failed",
			"message": "Invalid token"
		});
	}

	// Check username
	const usernameClean = username.clean(request.params.userName);
	if(!usernameClean) {
		return response.json({
			"status": "failed",
			"message": "Invalid user"
		});
	}

	// Check that user exists
	const userInfo = await getUser(usernameClean);
	if(!userInfo || !userInfo.registered) {
		return response.json({
			"status": "failed",
			"message": `User ${usernameClean} does not exist!`
		});
	}

	// Check that token validator exists
	if (!userInfo.oneTimeToken) {
		return response.json({
			"status": "failed",
			"message": "Invalid token!"
		});
	}

	// Validate token
	if (token.validate(usernameClean, request.params.oneTimeToken, userInfo.oneTimeToken )) {

		// Log in user
		await session.set("username", usernameClean);
		await session.set("loggedIn", true);

		// Remove token
		await updateUser(usernameClean, {oneTimeToken: undefined});

		// Success
		return response.redirect(config.baseUrl);
	} else {
		return response.json({
			"status": "failed",
			"message": "Invalid token!"
		});
	}

});

router.get("/generate", async (request, response) => {

	// Get session
	// @ts-ignore: session exists
	const session = request.session;

	if(!await session.get("loggedIn")) {
		response.json({
			"status": "failed"
		});
	} else {

		const
			username = await session.get("username"),
			tokenValidator = token.generate(username, config.loginTokenExpireSeconds*1000);

		if (tokenValidator) {

			const tokenEncoded = token.encode(tokenValidator.token);

			await updateUser(username, {oneTimeToken: tokenValidator});

			response.json({
				"status": "ok",
				"token": tokenEncoded,
				"validForSeconds": config.loginTokenExpireSeconds,
				"url": config.baseUrl + "/token/login/" + username + "/" + tokenEncoded
			});

		}

	}
});

export default router;
