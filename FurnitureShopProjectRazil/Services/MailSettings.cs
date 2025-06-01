namespace FurnitureShopProjectRazil.Services
{
    public class MailSettings
    {
        public string? SmtpServer { get; set; }
        public int SmtpPort { get; set; }
        public string? SmtpUsername { get; set; } // E-poçt göndərmək üçün istifadəçi adı (adətən e-poçt ünvanı)
        public string? SmtpPassword { get; set; } // E-poçt üçün App Password
        public string? FromName { get; set; }     // Göndərən adı
        public string? FromAddress { get; set; }  // "From" sahəsində görünəcək e-poçt ünvanı
        public bool UseSsl { get; set; }          // SSL/TLS istifadə edilib-edilməyəcəyi
    }
}
