

using Microsoft.AspNetCore.Identity;

namespace AuthApi.Entities
{
    public class User : IdentityUser
    {
        public List<RefreshToken> RefreshTokens { get; set; } = new List<RefreshToken>();
    }
}
