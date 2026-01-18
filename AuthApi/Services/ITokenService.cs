using AuthApi.Entities;

namespace AuthApi.Services
{
    public interface ITokenService
    {
        string GenerateAccessToken(User user, List<string> roles);
        RefreshToken GenerateRefreshToken(string ipAddress);
    }
}
