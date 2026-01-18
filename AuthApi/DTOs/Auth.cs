namespace AuthApi.DTOs
{
    public readonly record struct Register(string Username, string Email, string Password);
    public readonly record struct Login(string Email, string Password);
    public readonly record struct TokenDtoReq(string AccessToken, string RefreshToken);
    public readonly record struct TokenDtoRes(string AccessToken, string RefreshToken);
    public readonly record struct AssingRole(string Email, string Role);
}
