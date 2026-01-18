using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class TestController : ControllerBase
    {
        [HttpGet("basic")]
        public IActionResult Get()
        {
            return Ok("Auth API is running.");
        }

        [HttpGet("protected")]
        [Authorize]
        public IActionResult GetProtected()
        {
            return Ok("protected resource");
        }

        [Authorize(Roles = "admin")]
        [HttpGet("admin")]
        public IActionResult GetAdmin()
        {
            return Ok("admin resource");
        }
    }
}
