using System.ComponentModel.DataAnnotations;

namespace FurnitureShopProjectRazil.ViewModels
{
    public class EnterResetCodeViewModel
    {
        [Required(ErrorMessage = "E-poçt ünvanı tələb olunur.")]
        [EmailAddress]
        public string Email { get; set; } = string.Empty; // Formda hidden olaraq ötürüləcək

        [Required(ErrorMessage = "Təsdiq kodu tələb olunur.")]
        [StringLength(6, MinimumLength = 6, ErrorMessage = "Kod 6 rəqəmli olmalıdır.")]
        [RegularExpression(@"^\d{6}$", ErrorMessage = "Kod yalnız 6 rəqəmdən ibarət olmalıdır.")]
        [Display(Name = "Təsdiq Kodu")]
        public string Code { get; set; } = string.Empty;
    }
}