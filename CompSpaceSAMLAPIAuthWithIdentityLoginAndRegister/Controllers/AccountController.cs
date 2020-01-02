using ComponentSpace.Saml2;
using ComponentSpace.Saml2.Metadata.Export;
using CompSpaceSAMLAPIAuthWithIdentityLoginAndRegister.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace CompSpaceSAMLAPIAuthWithIdentityLoginAndRegister.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AccountController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly ISamlServiceProvider _samlServiceProvider;
        private readonly IConfigurationToMetadata _configurationToMetadata;
        private readonly IConfiguration _configuration;

        public AccountController(UserManager<IdentityUser> userManager,
            SignInManager<IdentityUser> signInManager,
            ISamlServiceProvider samlServiceProvider,
            IConfigurationToMetadata configurationToMetadata,
            IConfiguration configuration)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _samlServiceProvider = samlServiceProvider;
            _configurationToMetadata = configurationToMetadata;
            _configuration = configuration;
        }

        public async Task<IActionResult> InitiateSingleSignOn(string returnUrl = null)
        {
            var partnerName = _configuration["PartnerName"];

            // To login automatically at the service provider, 
            // initiate single sign-on to the identity provider (SP-initiated SSO).            
            // The return URL is remembered as SAML relay state.

            await _samlServiceProvider.InitiateSsoAsync(partnerName, returnUrl);

            return new EmptyResult();
        }

        public async Task<IActionResult> AssertionConsumerService()
        {
            // Receive and process the SAML assertion contained in the SAML response.
            // The SAML response is received either as part of IdP-initiated or SP-initiated SSO.
            var ssoResult = await _samlServiceProvider.ReceiveSsoAsync();

            // Automatically provision the user.
            // If the user doesn't exist locally then create the user.
            // Automatic provisioning is an optional step.
            var user = await _userManager.FindByNameAsync(ssoResult.UserID);

            if (user == null)
            {
                user = new IdentityUser { UserName = ssoResult.UserID, Email = ssoResult.UserID };

                var result = await _userManager.CreateAsync(user);

                if (!result.Succeeded)
                {
                    throw new Exception($"The user {ssoResult.UserID} couldn't be created - {result}");
                }

                // For demonstration purposes, create some additional claims.
                if (ssoResult.Attributes != null)
                {
                    var samlAttribute = ssoResult.Attributes.SingleOrDefault(a => a.Name == ClaimTypes.Email);

                    if (samlAttribute != null)
                    {
                        await _userManager.AddClaimAsync(user, new Claim(ClaimTypes.Email, samlAttribute.ToString()));
                    }

                    samlAttribute = ssoResult.Attributes.SingleOrDefault(a => a.Name == ClaimTypes.GivenName);

                    if (samlAttribute != null)
                    {
                        await _userManager.AddClaimAsync(user, new Claim(ClaimTypes.GivenName, samlAttribute.ToString()));
                    }

                    samlAttribute = ssoResult.Attributes.SingleOrDefault(a => a.Name == ClaimTypes.Surname);

                    if (samlAttribute != null)
                    {
                        await _userManager.AddClaimAsync(user, new Claim(ClaimTypes.Surname, samlAttribute.ToString()));
                    }
                }
            }

            // Automatically login using the asserted identity.
            await _signInManager.SignInAsync(user, isPersistent: false);

            // Redirect to the target URL if specified.
            if (!string.IsNullOrEmpty(ssoResult.RelayState))
            {
                return LocalRedirect(ssoResult.RelayState);
            }

            return Ok(new { message = " User logged in " });
        }

        public async Task<IActionResult> Login(AccountDetailsDto ad)
        {
            /*if (string.IsNullOrWhiteSpace(ad.Email) || string.IsNullOrWhiteSpace(ad.Password))
            {
                return BadRequest(new { Message = "email or password is null" });
            }

            var user = await _userManager.FindByEmailAsync(ad.Email);
            if (user == null)
            {
                return BadRequest(new 
                {
                    Message = "Invalid Login and/or password"
                });
            }

            var passwordSignInResult = await _signInManager.PasswordSignInAsync(user.UserName, ad.Password, isPersistent: true, lockoutOnFailure: false);
            if (!passwordSignInResult.Succeeded)
            {
                return BadRequest(new 
                {
                    Message = "Invalid Login and/or password"
                });
            }

            return Ok(new 
            {
                Message = "Cookie created"
            });*/
            return await InitiateSingleSignOn();
        }
    }
}
