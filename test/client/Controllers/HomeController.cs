using client.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Diagnostics;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;

namespace client.Controllers
{
    public class HomeController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }

        [Authorize]
        public async Task<IActionResult> Privacy()
        {
            return View();
        }

        [Authorize]
        [HttpGet("/testapi")]
        public async Task<IActionResult> TestApi()
        {
            var token = await HttpContext.GetTokenAsync("access_token").ConfigureAwait(false);
            var client = new HttpClient();
            var request = new HttpRequestMessage(HttpMethod.Get, new Uri("https://di.test.com/users"));
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            var resp = await client.SendAsync(request).ConfigureAwait(false);
            var rs = await resp.Content.ReadAsStringAsync().ConfigureAwait(false);

            return Content(rs);
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
