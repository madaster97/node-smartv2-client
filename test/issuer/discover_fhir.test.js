const { expect } = require('chai');
// const sinon = require('sinon');
const nock = require('nock');

const { Issuer } = require('../../lib');

const fail = () => { throw new Error('expected promise to be rejected'); };

const capabilitySuccess = {
  issuer: 'https://op.example.com',
  authorization_endpoint: 'https://op.example.com/o/oauth2/v2/auth',
  token_endpoint: 'https://op.example.com/oauth2/v4/token',
  capabilities: ['sso-openid-connect'],
  code_challenge_methods_supported: ['S256'],
};

const incapable = {
  ...capabilitySuccess,
  capabilities: [],
};

const noCapabilites = {
  ...capabilitySuccess,
  capabilities: undefined,
};

const noIssuer = {
  ...capabilitySuccess,
  issuer: undefined,
};

const issuerSuccess = {
  authorization_endpoint: 'https://op.example.com/o/oauth2/v2/auth',
  issuer: 'https://op.example.com',
  jwks_uri: 'https://op.example.com/oauth2/v3/certs',
  token_endpoint: 'https://op.example.com/oauth2/v4/token',
  userinfo_endpoint: 'https://op.example.com/oauth2/v3/userinfo',
};

function incapableCheck(err) {
  expect(err.name).to.equal('RPError');
  expect(err.message).to.eql('Issuer doesn\'t claim to be OIDC capable');
  expect(err).to.have.property('body');
  if (err.body.capabilities) {
    expect(err.body.capabilities).to.be.an('array', 'response.capabilities is not an array');
    expect(err.body.capabilities).to.not.include('sso-openid-connect');
  }
}

function successCheck(issuer) {
  expect(issuer).to.have.property('authorization_endpoint', 'https://op.example.com/o/oauth2/v2/auth');
  expect(issuer).to.have.property('issuer', 'https://op.example.com');
  expect(issuer).to.have.property('jwks_uri', 'https://op.example.com/oauth2/v3/certs');
  expect(issuer).to.have.property('token_endpoint', 'https://op.example.com/oauth2/v4/token');
  expect(issuer).to.have.property('userinfo_endpoint', 'https://op.example.com/oauth2/v3/userinfo');
}

describe('Issuer#fhirDiscover()', () => {
  afterEach(nock.cleanAll);
  it('accepts and assigns the discovered metadata', function () {
    nock('https://op.example.com', { allowUnmocked: true })
      .get('/.well-known/example-configuration')
      .reply(200, capabilitySuccess);

    nock('https://op.example.com', { allowUnmocked: true })
      .get('/.well-known/openid-configuration')
      .reply(200, issuerSuccess);

    return Issuer.fhirDiscover('https://op.example.com/.well-known/example-configuration').then(successCheck);
  });

  it('Appends smart-config to base url', function () {
    nock('https://op.example.com', { allowUnmocked: true })
      .get('/.well-known/smart-configuration')
      .reply(200, capabilitySuccess);

    nock('https://op.example.com', { allowUnmocked: true })
      .get('/.well-known/openid-configuration')
      .reply(200, issuerSuccess);

    return Issuer.fhirDiscover('https://op.example.com').then(successCheck);
  });

  it('Requires sso-openid-connect capability', function () {
    nock('https://op.example.com', { allowUnmocked: true })
      .get('/.well-known/smart-configuration')
      .reply(200, incapable);

    nock('https://op.example.com', { allowUnmocked: true })
      .get('/.well-known/openid-configuration')
      .reply(200, issuerSuccess);

    return Issuer.fhirDiscover('https://op.example.com')
      .then(fail, function () {
        /**
         * We shouldn't request openid-config
         * even if `issuer` is populated
         */
        expect(nock.isDone()).to.be.false;
      }, incapableCheck);
  });

  it('Requires capabilities to be an array', function () {
    nock('https://op.example.com', { allowUnmocked: true })
      .get('/.well-known/smart-configuration')
      .reply(200, noCapabilites);

    nock('https://op.example.com', { allowUnmocked: true })
      .get('/.well-known/openid-configuration')
      .reply(200, issuerSuccess);

    return Issuer.fhirDiscover('https://op.example.com')
      .then(fail, function () {
        /**
         * We shouldn't request openid-config
         * even if `issuer` is populated
         */
        expect(nock.isDone()).to.be.false;
      }, incapableCheck);
  });

  it('Requires issuer field', function () {
    nock('https://op.example.com', { allowUnmocked: true })
      .get('/.well-known/smart-configuration')
      .reply(200, noIssuer);

    return Issuer.fhirDiscover('https://op.example.com')
      .then(fail, function (err) {
        expect(err.name).to.equal('RPError');
        expect(err.message).to.eql('Fhir server did not present an \'issuer\' url');
        expect(err).to.have.property('body');
        expect(err.body.issuer).to.not.exist;
      });
  });
});
