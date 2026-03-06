// JavaScript файл с примерами утечек

const config = {
    // 🔴 AWS Credentials
    awsAccessKey: "AKIAIOSFODNN7EXAMPLE",
    awsSecretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    
    // 🔴 Stripe API Key
    stripeSecret: "sk_live_abcdefghijklmnopqrstuvwx",
    
    // 🔴 Firebase config with secrets
    firebase: {
        apiKey: "AIzaSyXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
        projectId: "my-project",
        databaseURL: "https://my-project.firebaseio.com"
    },
    
    // 🔴 OAuth secrets
    googleClientSecret: "GOCSPX-abcdefghijklmnopqrstuvwx",
    
    // 🔴 Basic Auth credentials
    basicAuth: "Basic YWRtaW46cGFzc3dvcmQxMjM0NTY=",
    
    // 🟡 Generic API key
    api_key: "abcdefghij1234567890abcdefghij1234567890"
};

// 🔴 Token passed to HTTP request
async function fetchData(url) {
    const token = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
    const response = await fetch(url, {
        headers: {
            "Authorization": `Bearer ${token}`,
            "Content-Type": "application/json"
        }
    });
    return response.json();
}

// 🔴 Private key
const privateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy...
-----END RSA PRIVATE KEY-----`;

module.exports = config;
