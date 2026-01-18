using AuthApi.DTOs;
using AuthApi.Entities;
using AuthApi.Infra;
using AuthApi.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace AuthApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<User> _userManager;
        private readonly AppDbContext _dbContext;
        private readonly ITokenService _tokenService;
        public AuthController(ITokenService tokenService, UserManager<User> userManager, AppDbContext dbContext)
        {
            _dbContext = dbContext;
            _userManager = userManager;
            _tokenService = tokenService;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] Register registerRequest)
        {
            var user = new User
            {
                UserName = registerRequest.Username,
                Email = registerRequest.Email
            };

            var possibleExistingUser = await _userManager.FindByEmailAsync(registerRequest.Email).ConfigureAwait(false);
            if (possibleExistingUser is not null)
                return BadRequest("User with this email already exists.");

            var result = await _userManager.CreateAsync(user, registerRequest.Password).ConfigureAwait(false);
            if (!result.Succeeded)
                return BadRequest(string.Format("User creation failed due to the following errors : {0}", result.Errors.Select(x => x.Description)));

            return Ok(new { Message = "User registered successfullt" });
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] Login loginRequest)
        {
            var user = await _userManager.FindByEmailAsync(loginRequest.Email).ConfigureAwait(false);
            if (user == null || !await _userManager.CheckPasswordAsync(user, loginRequest.Password).ConfigureAwait(false))
            {
                return Unauthorized("Invalid email or password.");
            }
            var roles = await _userManager.GetRolesAsync(user).ConfigureAwait(false);
            var accessToken = _tokenService.GenerateAccessToken(user, roles.ToList());
            var refreshToken = _tokenService.GenerateRefreshToken(GetIpAddress());
            user.RefreshTokens.Add(refreshToken); 
            await _userManager.UpdateAsync(user).ConfigureAwait(false);
            return Ok(new TokenDtoRes(accessToken, refreshToken.Token));
        }

        [HttpPost("revoke")]
        public async Task<IActionResult> RevokeToken([FromBody] TokenDtoReq request)
        {
           var token = request.RefreshToken;
           var user = await _userManager.Users.Include(x => x.RefreshTokens).SingleOrDefaultAsync(u => u.RefreshTokens.Any(t => t.Token == token)).ConfigureAwait(false);
           if (user == null)
                return NotFound("User not found.");

           var existingToken = user.RefreshTokens.SingleOrDefault(t => t.Token == token);
            if (existingToken == null || !existingToken.IsActive)
                return BadRequest("Token is already revoked");
            existingToken.Revoked = DateTime.UtcNow;
            existingToken.RevokedByIp = GetIpAddress();
            await _userManager.UpdateAsync(user).ConfigureAwait(false);
            return Ok("Token revoked");
        }

        private string GetIpAddress()
        {
            if (Request.Headers.TryGetValue("X-Forwarded-For", out Microsoft.Extensions.Primitives.StringValues value))
                return value.ToString();
            return HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown";
        }
    }
}
