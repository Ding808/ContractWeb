using MailKit.Net.Smtp;
using MimeKit;
using Microsoft.Extensions.Configuration;
using System;
using System.Threading.Tasks;

public class EmailService
{
    private readonly IConfiguration _config;

    public EmailService(IConfiguration config)
    {
        _config = config;
    }

    public async Task<bool> SendEmailAsync(string email, string subject, string message)
    {
        try
        {
            var emailSettings = _config.GetSection("EmailSettings");
            var smtpServer = emailSettings["SmtpServer"];
            var port = int.Parse(emailSettings["Port"]);
            var senderEmail = emailSettings["SenderEmail"];
            var senderPassword = emailSettings["SenderPassword"];

            Console.WriteLine($"Connecting to SMTP server: {smtpServer}:{port}");
            Console.WriteLine($"Sender Email: {senderEmail}");

            var emailMessage = new MimeMessage();
            emailMessage.From.Add(new MailboxAddress("Support", senderEmail));
            emailMessage.To.Add(new MailboxAddress("", email));
            emailMessage.Subject = subject;
            emailMessage.Body = new TextPart("plain") { Text = message };

            using (var client = new SmtpClient())
            {
                await client.ConnectAsync(smtpServer, port, MailKit.Security.SecureSocketOptions.StartTls);
                Console.WriteLine("SMTP Server connected successfully.");

                await client.AuthenticateAsync(senderEmail, senderPassword);
                Console.WriteLine("Authenticated successfully.");

                await client.SendAsync(emailMessage);
                await client.DisconnectAsync(true);
                Console.WriteLine($"Email successfully sent to {email}");
            }

            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Email sending failed: {ex.Message}");
            return false;
        }
    }
}
