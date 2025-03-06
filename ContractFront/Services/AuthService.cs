using Blazored.LocalStorage;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Threading.Tasks;

public class AuthService
{
    private readonly HttpClient _httpClient;
    private readonly ILocalStorageService _localStorage;

    public AuthService(HttpClient httpClient, ILocalStorageService localStorage)
    {
        _httpClient = httpClient;
        _localStorage = localStorage;
    }

    public async Task<bool> Login(string username, string password)
    {
        var response = await _httpClient.PostAsJsonAsync("api/auth/login", new { username, password });

        var json = await response.Content.ReadAsStringAsync();
        Console.WriteLine($"Login Response: {json}");

        if (!response.IsSuccessStatusCode)
        {
            Console.WriteLine($"Login failed: {response.StatusCode}");
            return false;
        }

        try
        {
            var result = JsonSerializer.Deserialize<AuthResponse>(json, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            if (result != null && !string.IsNullOrEmpty(result.Token))
            {
                // 保存 token 与用户名
                await _localStorage.SetItemAsync("authToken", result.Token);
                await _localStorage.SetItemAsync("username", username);
                _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", result.Token);
                return true;
            }
        }
        catch (JsonException ex)
        {
            Console.WriteLine($"JSON Error: {ex.Message}");
        }

        return false;
    }

    public async Task<bool> Register(string username, string email, string password)
    {
        var response = await _httpClient.PostAsJsonAsync("api/auth/register", new { username, email, password });

        if (!response.IsSuccessStatusCode)
        {
            Console.WriteLine($"Register failed: {await response.Content.ReadAsStringAsync()}");
        }

        return response.IsSuccessStatusCode;
    }

    public async Task Logout()
    {
        await _localStorage.RemoveItemAsync("authToken");
        await _localStorage.RemoveItemAsync("username");
        _httpClient.DefaultRequestHeaders.Authorization = null;
    }

    public async Task<string> GetToken()
    {
        return await _localStorage.GetItemAsync<string>("authToken");
    }

    public async Task<string> GetUsername()
    {
        return await _localStorage.GetItemAsync<string>("username");
    }

    public async Task Initialize()
    {
        var token = await GetToken();
        if (!string.IsNullOrEmpty(token))
        {
            _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        }
    }
}

public class AuthResponse
{
    public string Token { get; set; }
}
