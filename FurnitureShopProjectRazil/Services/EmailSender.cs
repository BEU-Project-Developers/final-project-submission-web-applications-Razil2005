// CaterManagementSystem.Services/EmailSender.cs
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Logging; // ILogger üçün
using MimeKit;
using MimeKit.Text; // TextFormat.Html üçün
using MailKit.Net.Smtp;
using MailKit.Security;
using System;
using System.Threading.Tasks;
using FurnitureShopProjectRazil.Services;
using FurnitureShopProjectRazil.Interfaces;

namespace FurnitureShopProjectRazil.Services
{
    public class EmailSender : IEmailSender
    {
        private readonly MailSettings _mailSettings;
        private readonly ILogger<EmailSender> _logger; // ILogger istifadə edirik

        public EmailSender(IOptions<MailSettings> mailSettings, ILogger<EmailSender> logger) // Logger-i DI ilə alırıq
        {
            _mailSettings = mailSettings.Value;
            _logger = logger; // Logger-i təyin edirik
        }

        public async Task SendEmailAsync(string toEmail, string subject, string htmlMessage)
        {
            if (string.IsNullOrEmpty(_mailSettings.SmtpServer) ||
                _mailSettings.SmtpPort <= 0 ||
                string.IsNullOrEmpty(_mailSettings.SmtpUsername) ||
                string.IsNullOrEmpty(_mailSettings.SmtpPassword) ||
                string.IsNullOrEmpty(_mailSettings.FromAddress))
            {
                _logger.LogError("Mail settings are not configured properly. SmtpServer: {SmtpServer}, Port: {SmtpPort}, Username: {SmtpUsername}, FromAddress: {FromAddress}. Email not sent to {ToEmail}",
                    _mailSettings.SmtpServer, _mailSettings.SmtpPort, _mailSettings.SmtpUsername, _mailSettings.FromAddress, toEmail);
                throw new InvalidOperationException("Email settings are not properly configured in appsettings.json.");
            }

            try
            {
                var email = new MimeMessage();
                email.From.Add(new MailboxAddress(_mailSettings.FromName ?? "CaterManagementSystem", _mailSettings.FromAddress));
                email.To.Add(MailboxAddress.Parse(toEmail));
                email.Subject = subject;
                // Əvvəlki kodunuzda TextPart istifadə olunub, CaterManagementSystem-də BodyBuilder.
                // Hər ikisi də işləyir. TextPart daha sadədir.
                email.Body = new TextPart(TextFormat.Html) { Text = htmlMessage };
                // Və ya BodyBuilder ilə (əvvəlki CaterManagementSystem kodunuzdakı kimi):
                // var builder = new BodyBuilder { HtmlBody = htmlMessage };
                // email.Body = builder.ToMessageBody();

                using var smtp = new SmtpClient();
                smtp.Timeout = 30000; // 30 saniyəlik timeout

                SecureSocketOptions secureSocketOptions;
                // appsettings.json-dakı UseSsl və SmtpPort dəyərlərinə görə
                if (_mailSettings.SmtpPort == 587) // Gmail/Outlook üçün ümumi StartTls portu
                {
                    secureSocketOptions = SecureSocketOptions.StartTls;
                }
                else if (_mailSettings.SmtpPort == 465) // Ümumi SslOnConnect portu
                {
                    secureSocketOptions = SecureSocketOptions.SslOnConnect;
                }
                else if (_mailSettings.UseSsl) // Əgər UseSsl explicitly true isə
                {
                    secureSocketOptions = SecureSocketOptions.SslOnConnect;
                }
                else // Digər hallar və ya server özü qərar versin
                {
                    // StartTlsWhenAvailable daha təhlükəsiz bir default ola bilər
                    secureSocketOptions = SecureSocketOptions.StartTlsWhenAvailable;
                }

                _logger.LogInformation("Connecting to SMTP: {SmtpServer}:{SmtpPort} with options {SecureSocketOptions}",
                    _mailSettings.SmtpServer, _mailSettings.SmtpPort, secureSocketOptions);

                await smtp.ConnectAsync(_mailSettings.SmtpServer, _mailSettings.SmtpPort, secureSocketOptions);
                _logger.LogInformation("Connected. Authenticating with {SmtpUsername}...", _mailSettings.SmtpUsername);

                await smtp.AuthenticateAsync(_mailSettings.SmtpUsername, _mailSettings.SmtpPassword);
                _logger.LogInformation("Authenticated. Sending email to {ToEmail}...", toEmail);

                await smtp.SendAsync(email);
                _logger.LogInformation("Email sent successfully to {ToEmail}.", toEmail);

                await smtp.DisconnectAsync(true);
                _logger.LogInformation("Disconnected from SMTP server.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error sending email to {ToEmail}. Subject: {Subject}. Exception: {ExceptionDetails}",
                    toEmail, subject, ex.ToString()); // ex.ToString() daha çox detal verir
                throw; // Xətanı yuxarıya ötürürük ki, AccountController-da tutulsun
            }
        }
    }
}