using System.ComponentModel.DataAnnotations;

namespace FurnitureShopProjectRazil.ViewModels
{
    public class ResetPasswordViewModel
    {
        // Bu sahələr URL-dən gələn parametrlərdən (userId, token)
        // və ya EnterResetCodeViewModel-dən (Email, Code) doldurulacaq
        // və formda hidden olaraq saxlanılacaq.
        [Required]
        public string? UserId { get; set; } // Linkdən gələn userId


        [Required]
        public string? Token { get; set; } // Linkdən gələn URL-kodlanmış token VƏ YA EnterResetCode-dan gələn 6 rəqəmli kod

        // public string? Email { get; set; } // Əgər EnterResetCode-dan gəlirsə və ya View-da göstərmək üçün lazım olarsa

        // Bu sahələr istifadəçi tərəfindən doldurulacaq
        [Required(ErrorMessage = "Yeni parol tələb olunur.")]
        [DataType(DataType.Password)]
        [StringLength(100, MinimumLength = 6, ErrorMessage = "Parol ən az 6 simvol olmalıdır.")]
        [Display(Name = "Yeni Parol")]
        public string Password { get; set; } = string.Empty;

        [DataType(DataType.Password)]
        [Compare(nameof(Password), ErrorMessage = "Yeni parol və təkrar parol eyni deyil.")]
        [Display(Name = "Yeni Parolu Təsdiqləyin")]
        public string ConfirmPassword { get; set; } = string.Empty;
    }
}