using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using System.Linq;
using System;
using Microsoft.Extensions.Configuration;

[Route("api/auth")]
[ApiController]
public class AuthController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly IConfiguration _config;
    private readonly EmailService _emailService;

    public AuthController(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, IConfiguration config, EmailService emailService)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _config = config;
        _emailService = emailService;
    }

    // User registration
    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterModel model)
    {
        // check if the email is registered
        var existingUser = await _userManager.FindByEmailAsync(model.Email);
        if (existingUser != null)
        {
            return BadRequest(new { message = "Email is already registered." });
        }

        var user = new ApplicationUser { UserName = model.Username, Email = model.Email };
        var result = await _userManager.CreateAsync(user, model.Password);
        if (result.Succeeded)
        {
            return Ok(new { message = "User registered successfully" });
        }
        return BadRequest(result.Errors.Select(e => e.Description));
    }


    // User Loggin
    [HttpPost("login")]
    [AllowAnonymous]
    public async Task<IActionResult> Login([FromBody] LoginModel model)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var user = await _userManager.FindByNameAsync(model.Username);
        if (user != null && await _userManager.CheckPasswordAsync(user, model.Password))
        {
            var tokenString = GenerateJWTToken(user);
            return Ok(new { Token = tokenString });
        }
        return Unauthorized(new { message = "Wrong user name or password" });
    }

    //User Logout
    [Authorize]
    [HttpPost("logout")]
    public async Task<IActionResult> Logout()
    {
        await _signInManager.SignOutAsync();
        return Ok(new { message = "User logged out successfully" });
    }

    // Create JWT Token
    private string GenerateJWTToken(ApplicationUser user)
    {
        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
        };

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        var token = new JwtSecurityToken(
            _config["Jwt:Issuer"],
            _config["Jwt:Audience"],
            claims,
            expires: DateTime.UtcNow.AddHours(1),
            signingCredentials: creds);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    //Recover Username
    [HttpPost("recover-username")]
    public async Task<IActionResult> RecoverUsername([FromBody] ForgotPasswordModel model)
    {
        var user = await _userManager.FindByEmailAsync(model.Email);
        if (user == null)
            return BadRequest(new { message = "User not found" });

        var message = $"Your username is: {user.UserName}";
        await _emailService.SendEmailAsync(model.Email, "Username Recovery", message);

        return Ok(new { message = "Username sent to email" });
    }

    // Sent verifacation code for password reset
    [HttpPost("forgot-password")]
    public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordModel model)
    {
        var user = await _userManager.FindByEmailAsync(model.Email);
        if (user == null)
            return BadRequest(new { message = "User not found" });

        //create 6 diget code
        var code = new Random().Next(100000, 999999).ToString();
        await _userManager.SetAuthenticationTokenAsync(user, "Default", "PasswordReset", code);

        // sent email
        var message = $"Your password reset verification code is: {code}";
        await _emailService.SendEmailAsync(model.Email, "Password Reset Code", message);

        return Ok(new { message = "Verification code sent to email" });
    }

    //Verify code and reset password
    [HttpPost("reset-password")]
    public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordModel model)
    {
        var user = await _userManager.FindByEmailAsync(model.Email);
        if (user == null)
            return BadRequest(new { message = "User not found" });

        var token = await _userManager.GetAuthenticationTokenAsync(user, "Default", "PasswordReset");
        if (token != model.Code)
            return BadRequest(new { message = "Invalid verification code" });

        var result = await _userManager.ResetPasswordAsync(user, await _userManager.GeneratePasswordResetTokenAsync(user), model.NewPassword);
        if (result.Succeeded)
            return Ok(new { message = "Password reset successfully" });

        return BadRequest(new { errors = result.Errors.Select(e => e.Description) });
    }
}

// Models
public class RegisterModel
{
    public string Username { get; set; }
    public string Email { get; set; }
    public string Password { get; set; }
}

public class LoginModel
{
    public string Username { get; set; }
    public string Password { get; set; }
}

public class ForgotPasswordModel
{
    public string Email { get; set; }
}

public class ResetPasswordModel
{
    public string Email { get; set; }
    public string Code { get; set; }
    public string NewPassword { get; set; }
}

