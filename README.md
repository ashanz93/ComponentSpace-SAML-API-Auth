# ComponentSpace-SAML-API-Auth
The goal of this repo is to understand how to create a SAML API based Authentication with ComponentSpace code and address some challenges associated with API based SAML Auth

Reference: Component Space ASP.NET Core Examples Guide and Developer Guide

Challenge with API based auth if there is an external  command line client or non-web client using traditional forms based input for authentication:

1) Cannot pass credentials to IdP by bypassing the login screen
2) Even if a wrapper is written in the IdP to take the parameters in a POST Request and call SingleSignOn(), at await ReceiveSSOAsync() an error is thrown stating that, no SAMl Auth request has been initiated.

Possible way to address this challenge:

Register the non-web client with the IdP and use access tokens to perform authentication
