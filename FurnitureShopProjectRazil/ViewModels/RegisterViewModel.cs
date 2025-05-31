using System.ComponentModel.DataAnnotations;

namespace FurnitureShopProjectRazil.ViewModels
{
    public class RegisterViewModel
    {
        [Required(ErrorMessage = "İstifadəçi adı tələb olunur.")]
        [StringLength(50, MinimumLength = 3, ErrorMessage = "İstifadəçi adı 3 ilə 50 simvol arasında olmalıdır.")]
        [RegularExpression(@"^[a-zA-Z0-9_.-]*$", ErrorMessage = "İstifadəçi adında yalnız hərflər, rəqəmlər, alt xətt, nöqtə və tire ola bilər.")]
        [Display(Name = "İstifadəçi adı")]
        public string Username { get; set; } = string.Empty;

        [Required(ErrorMessage = "Tam ad tələb olunur.")]
        [StringLength(100, ErrorMessage = "Tam ad maksimum 100 simvol ola bilər.")]
        [Display(Name = "Adınız və Soyadınız")]
        public string Fullname { get; set; } = string.Empty;

        [Required(ErrorMessage = "E-poçt ünvanı tələb olunur.")]
        [EmailAddress(ErrorMessage = "Düzgün e-poçt formatı daxil edin.")]
        [StringLength(100, ErrorMessage = "E-poçt maksimum 100 simvol ola bilər.")]
        [Display(Name = "E-poçt ünvanınız")]
        public string Email { get; set; } = string.Empty;

        [Required(ErrorMessage = "Parol tələb olunur.")]
        [DataType(DataType.Password)]
        [StringLength(100, MinimumLength = 6, ErrorMessage = "Parol ən az 6 simvol olmalıdır.")]
        // Parolun mürəkkəbliyi üçün RegularExpression əlavə edə bilərsiniz, məsələn:
        // [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{6,}$", ErrorMessage = "Parol ən az bir böyük hərf, bir kiçik hərf, bir rəqəm və bir xüsusi simvol ehtiva etməlidir.")]
        [Display(Name = "Parolunuz")]
        public string Password { get; set; } = string.Empty;

        [DataType(DataType.Password)]
        [Compare(nameof(Password), ErrorMessage = "Parol və təkrar parol eyni deyil.")]
        [Display(Name = "Parolu təsdiqləyin")]
        public string ConfirmPassword { get; set; } = string.Empty;
    }
}