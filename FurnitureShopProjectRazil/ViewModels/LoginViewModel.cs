using System.ComponentModel.DataAnnotations;

namespace FurnitureShopProjectRazil.ViewModels
{
    public class LoginViewModel
    {
        [Required(ErrorMessage = "İstifadəçi adı və ya e-poçt tələb olunur.")]
        [Display(Name = "İstifadəçi adı və ya E-poçt")]
        [StringLength(100)]
        public string UsernameOrEmail { get; set; } = string.Empty;

        [Required(ErrorMessage = "Parol tələb olunur.")]
        [DataType(DataType.Password)]
        [Display(Name = "Parolunuz")]
        public string Password { get; set; } = string.Empty;

        [Display(Name = "Məni xatırla")]
        public bool RememberMe { get; set; }
    }
}