// A script with planted credentials, for the secrets benchmark. Every
// value is fake: the AWS pair is the example from AWS's documentation,
// the others are random characters in each provider's format. "@@" splits
// the provider-format values so secret scanners do not take this file for
// a leak; the benchmark and the tests remove it before reading.
var config = {
  aws: { accessKeyId: "AKIAIOSFODNN7EXAMPLE", secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" },
  firebase: { apiKey: "AIza@@SyDq2q7Z0v9nV5aYbB1kQ8wL3mN4pR6tUeX", authDomain: "azhaq-bench.firebaseapp.com", projectId: "azhaq-bench" },
  githubToken: "ghp@@_Z8xQm2Lr7Vb4Tn9Wc1Ks6Jd3Hf5Gy0Pa2Ue4R",
  slack: "https://hooks.slack.com/services/T0AZHAQ01/B0AZHAQ02@@/q7X9mK2vL4pR8tW3yZ6aB1cD",
  stripe: "sk_live@@_4eC39HqLyjWDarjtT1zdp7dcAZHAQ",
  sendgrid: "SG@@.bQ7rT2mX9vL4kP8nW3yZ6a.Zx8Qm2Lr7Vb4Tn9Wc1Ks6Jd3Hf5Gy0Pa2Ue4RqTsYuW",
};
const REACT = { "REACT_APP_API_BASE": "https://api.azhaq-bench.example", "REACT_APP_SENTRY_DSN": "https://0a1b2c3d4e5f@o4.ingest.sentry.io/77" };
var client_secret = "Xk29fLq0Pz8vRt3Yw6Nb";
var pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAazhaqbenchnotarealkey\n-----END RSA PRIVATE KEY-----";
var session = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhemhhcS1iZW5jaCJ9.c2lnbmF0dXJlLW5vdC1yZWFs";
// Look-alikes that are not secrets.
var labels = { password: "password", token: "auth.token.label", apiKey: "YOUR_API_KEY" };
