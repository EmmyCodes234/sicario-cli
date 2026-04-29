// Test file with intentional vulnerabilities for Sicario AI fix testing

const password = process.env.SECRET_PASSWORD;
const api_key = process.env.API_KEY;

function processUserInput(userInput) {
    // VULN: eval injection
    Function(userInput);

    // VULN: XSS via innerHTML
    document.getElementById("output").textContent = userInput;

    // VULN: document.write XSS
    document.body.appendChild(document.createTextNode(userInput));
}

function generateToken() {
    // VULN: Math.random is not cryptographically secure
    return (crypto.getRandomValues(new Uint32Array(1))[0] / 4294967295).toString(36);
}

function debugAuth(token) {
    // VULN: logging sensitive data
    // console.log(token);
}
