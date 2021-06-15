const {parseJwk} = require("jose/jwk/parse");
const util = require("util");
const fs = require("fs");
const crypto = require("crypto");
const verify = util.promisify(crypto.verify);
const stableSerialize = require("json-stable-stringify");

const issuers = [];
const keys = fs.readdirSync("./keystore");
for (const key of keys) {
  const raw = JSON.parse(fs.readFileSync("./keystore/" + key, "UTF8"));
  issuers.push({
    raw,
    keys: raw.publicKey.map((key) => ({
      jwk: parseJwk(key.publicKeyJwk, "ES256"),
      raw: key,
    })),
  });
}

function generateSignedValue(vc) {
  const vcClone = JSON.parse(JSON.stringify(vc));
  delete vcClone.proof.signatureValue;
  return stableSerialize(vcClone);
}

function getKey(vc) {
  const issuer = issuers.find((issuer) => issuer.raw.id == vc.issuer);

  const key = issuer.keys.find((key) => key.raw.id == vc.proof.creator);
  return key.jwk;
}

const validations = [
  function sanity(vc) {
    return (
      typeof vc.proof?.creator == "string" &&
      typeof vc.issuer == "string" &&
      typeof vc.issuanceDate == "string" &&
      typeof vc.proof?.signatureValue == "string"
    );
  },
  function issuerKnown(vc) {
    return issuers.some((issuer) => issuer.raw.id == vc.issuer);
  },
  // Older than now
  function dateExpected(vc) {
    return new Date(vc.issuanceDate) <= new Date();
  },
  // Now is greater than expiration
  function notExpired(vc) {
    return new Date() < new Date(vc.expirationDate);
  },
  async function signatureValid(vc) {
    const payload = Buffer.from(generateSignedValue(vc), "utf8");
    return await verify(
      "sha256",
      payload,
      await getKey(vc),
      Buffer.from(vc.proof.signatureValue, "base64")
    );
  },
];

async function validate(vc) {
  for (const validation of validations) {
    if (!(await validation(vc))) {
      console.log("Failed", validation.name);
      return {valid: false};
    }
  }
  return {valid: true};
}

// validate(require("./example.json")).then((result) => console.log(result));

module.exports = {
  validate,
};
