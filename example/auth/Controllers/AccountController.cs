using auth.Models;
using IdentityModel;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Security.Claims;
using System.Threading.Tasks;

namespace auth.Controllers
{
    public class AccountController : Controller
    {
        // *******************************************************************************************************************************
        #region -  Login  -

        [HttpGet]
        public async Task<IActionResult> Login(string returnUrl)
        {
            return View(new LoginModel { ReturnUrl = returnUrl });
        }

        [HttpPost]
        public async Task<IActionResult> Login(LoginModel model)
        {
            AuthenticationProperties props = null;
            if (model.RememberLogin)
            {
                props = new AuthenticationProperties
                {
                    IsPersistent = model.RememberLogin,
                    ExpiresUtc = DateTimeOffset.UtcNow.AddDays(14),
                };
            };

            var claims = new Claim[] { new Claim(ClaimTypes.Name, model.Username) };
            var identity = new ClaimsIdentity(
                claims
                , CookieAuthenticationDefaults.AuthenticationScheme
            );
            var principal = new ClaimsPrincipal(identity);
            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(principal), props).ConfigureAwait(false);

            return View(model);
        }

        #endregion
    }
}
