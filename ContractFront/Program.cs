using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using System.Net.Http;
using Blazored.LocalStorage;
using ContractFront;

var builder = WebAssemblyHostBuilder.CreateDefault(args);
builder.RootComponents.Add<App>("#app");

builder.Services.AddScoped(sp => new HttpClient { BaseAddress = new Uri("https://localhost:7229/") });
builder.Services.AddScoped<AuthService>();
builder.Services.AddBlazoredLocalStorage();

await builder.Build().RunAsync();
