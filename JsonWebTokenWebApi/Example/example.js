var host = "https://localhost:44395";
var loginAuth = "/api/login/authenticate";
var anonValues = "/api/values/anon";
var secureValues = "/api/values/secure";
var token = null;

function checkHttpStatus(response) {
	if (response.status >= 200 && response.status < 300) return Promise.resolve(response);
	else return Promise.reject(new Error(response.statusText));
}

function getJson(response) {
	return response.json();
}

function outputMessage(err, target) {
	let time = (new Date()).toLocaleTimeString();
	document.getElementById(target).innerHTML = `${time} ${err}`;
}

function getAnonHandler(evt) {
	fetch(`${host}${anonValues}`)
		.then(checkHttpStatus)
		.then(getJson)
		.then((data) => outputMessage(data, "anonOutput"))
		.catch((err) => outputMessage(err, "anonOutput"));
}

function getSecureHandler(evt) {
	let options = {
		credentials: "same-origin",
		headers: { "Authorization": "Bearer " + token }
	};

	fetch(`${host}${secureValues}`, options)
		.then(checkHttpStatus)
		.then(getJson)
		.then((data) => outputMessage(data, "secureOutput"))
		.catch((err) => outputMessage(err, "secureOutput"));
}

function getCredentialsHandler(evt) {
	let identity = document.getElementById("identity").value;
	let secret = document.getElementById("secret").value;
	
	let options = {
		method: "post",
		headers: { "Content-type": "application/x-www-form-urlencoded; charset=UTF-8" },
		body: `identity=${identity}&secret=${secret}`
	};
	
	fetch(`${host}${loginAuth}`, options)
		.then(checkHttpStatus)
		.then(getJson)
		.then((data) => {
			token = data.Token;
			outputMessage(token, "errorOutput");
		})
		.catch((err) => outputMessage(err, "errorOutput"));
}

function removeCredentialsHandler(evt) {
	token = null;
	outputMessage("Token erased", "errorOutput");
}

window.addEventListener("load", event => {
	document.getElementById("getAnon").addEventListener("click", getAnonHandler);
	document.getElementById("getSecure").addEventListener("click", getSecureHandler);
	document.getElementById("getCredentials").addEventListener("click", getCredentialsHandler);
	document.getElementById("removeCredentials").addEventListener("click", removeCredentialsHandler);
});
