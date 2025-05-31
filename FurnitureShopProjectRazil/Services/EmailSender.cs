using Microsoft.Extensions.Options; // IOptions üçün
using MimeKit;
using MimeKit.Text;
using MailKit.Net.Smtp;
using MailKit.Security; // SecureSocketOptions üçün
using System.Threading.Tasks;
using System;
using FurnitureShopProjectRazil.Interfaces; // Exception üçün

namespace SchoolSystem.Services
{
    public class EmailSender : IEmailSender
    {
        private readonly EmailSettings _emailSettings;

        public EmailSender(IOptions<EmailSettings> emailSettings)
        {
            _emailSettings = emailSettings.Value;
        }

        public async Task SendEmailAsync(string toEmail, string subject, string htmlMessage)
        {
            if (string.IsNullOrEmpty(_emailSettings.SmtpServer) ||
                string.IsNullOrEmpty(_emailSettings.SmtpUsername) ||
                string.IsNullOrEmpty(_emailSettings.SmtpPassword) ||
                string.IsNullOrEmpty(_emailSettings.FromAddress))
            {
                // Loglama: Email ayarları düzgün konfiqurasiya edilməyib
                Console.WriteLine("Email ayarları tam deyil. E-poçt göndərilə bilmədi.");
                // throw new InvalidOperationException("Email settings are not configured properly.");
                return; // Və ya xəta fırlat
            }

            try
            {
                var email = new MimeMessage();
                email.From.Add(new MailboxAddress(_emailSettings.FromName ?? "SchoolSystem", _emailSettings.FromAddress));
                email.To.Add(MailboxAddress.Parse(toEmail));
                email.Subject = subject;
                email.Body = new TextPart(TextFormat.Html) { Text = htmlMessage };

                using var smtp = new SmtpClient();

                // Serverin tələb etdiyi təhlükəsizlik seçiminə görə dəyişə bilər
                // Gmail üçün: Port 587, SecureSocketOptions.StartTls
                // Outlook üçün: Port 587, SecureSocketOptions.StartTls
                // Bəzi hostinqlər: Port 465, SecureSocketOptions.SslOnConnect
                SecureSocketOptions secureSocketOptions;
                if (_emailSettings.UseSsl) // Əgər port 465 kimi bir şeydirsə
                {
                    secureSocketOptions = SecureSocketOptions.SslOnConnect;
                }
                else // Əgər port 587 kimi bir şeydirsə (StartTls)
                {
                    secureSocketOptions = SecureSocketOptions.StartTlsWhenAvailable; // Və ya birbaşa StartTls
                }

                await smtp.ConnectAsync(_emailSettings.SmtpServer, _emailSettings.SmtpPort, secureSocketOptions);
                await smtp.AuthenticateAsync(_emailSettings.SmtpUsername, _emailSettings.SmtpPassword);
                await smtp.SendAsync(email);
                await smtp.DisconnectAsync(true);
            }
            catch (Exception ex)
            {
                // Xətanı loglayın
                Console.WriteLine($"E-poçt göndərmə xətası ({toEmail}): {ex.ToString()}");
                // throw; // E-poçt göndərmənin kritik olduğu hallarda xətanı yuxarıya fırlatmaq olar
            }
        }
    }
}