using AuthApi.DTOs;
using AuthApi.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace AuthApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class RoleController : ControllerBase
    {
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly UserManager<User> _userManager;
        public RoleController(UserManager<User> userManager, RoleManager<IdentityRole> roleManager)
        {
            _userManager = userManager;
            _roleManager = roleManager;
        }

        [HttpPost("create")]
        public async Task<IActionResult> CreateRole([FromBody] string roleName)
        {
            if (await _roleManager.RoleExistsAsync(roleName).ConfigureAwait(false))
            {
                return BadRequest(roleName + " already exists.");
            }

            var role = await _roleManager.CreateAsync(new IdentityRole(roleName)).ConfigureAwait(false);
            if (!role.Succeeded)
                return BadRequest(string.Format("Error creating role {0}", role.Errors));
            return Ok(string.Format("Role {0} created successfully", roleName));
        }

        [HttpPost("assign")]
        public async Task<IActionResult> AssignRole([FromBody] AssingRole requestModel)
        {
            var user = await _userManager.FindByEmailAsync(requestModel.Email).ConfigureAwait(false);
            if (user == null)
                return NotFound(string.Format("User {0} not found.", requestModel.Email));

            if (!await _roleManager.RoleExistsAsync(requestModel.Role).ConfigureAwait(false))
            {
                return NotFound(string.Format("Role {0} does not exist.", requestModel.Role));
            }
            var result = await _userManager.AddToRoleAsync(user, requestModel.Role).ConfigureAwait(false);
            if (!result.Succeeded)
            {
                return BadRequest(string.Format("Error assigning role {0} to user {1}: {2}", requestModel.Role, requestModel.Email, result.Errors));
            }
            return Ok(string.Format("Role {0} assigned to user {1} successfully.", requestModel.Role, requestModel.Email));
        }
    }
}
